package admin

import (
	"cmp"
	"context"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"unicode"

	"github.com/softwarity/meerkat/internal/idp"
	"github.com/softwarity/meerkat/internal/store"
	"github.com/softwarity/meerkat/internal/vault"
)

// Moving a stored secret into the vault (VAULT-05).
//
// The console can offer this on a field it knows nothing about, because the
// move happens ENTIRELY server-side: the browser sends a name, not a value. It
// is the only way to handle a secret that arrived through the bootstrap file or
// an older save — the console never received that literal, so it could not put
// it in the vault itself even if it wanted to.
//
// One endpoint rather than one per screen, so the form field component can do
// this on its own instead of every screen wiring its own call.

// secretHolder is one place in the configuration that may hold a secret.
type secretHolder struct {
	// scope is the plane this holder's references resolve in. A secret moved
	// out of it has to land there, or the reference would never resolve.
	scope string
	// load returns the holder's display name and the STORED value of each of
	// its declared secret fields.
	load func(ctx context.Context, id string) (label string, secrets map[string]string, err error)
	// stash writes value into one field and persists the holder.
	stash func(ctx context.Context, id, field, value string) error
}

// secretHolders is the registry. Adding an object that holds a secret means
// adding it here; everything else (the field's three states, the offer to move
// it, the audit entry) follows.
func (a *API) secretHolders() map[string]secretHolder {
	return map[string]secretHolder{
		"authprovider": {
			scope: vault.ScopeInfra,
			load: func(ctx context.Context, id string) (string, map[string]string, error) {
				p, err := a.st.GetAuthProvider(ctx, id)
				if err != nil {
					return "", nil, err
				}
				secrets := map[string]string{}
				for _, field := range idp.SecretFields(p.Kind) {
					s, _ := p.Config[field].(string)
					secrets[field] = s
				}
				return p.Name, secrets, nil
			},
			stash: func(ctx context.Context, id, field, value string) error {
				p, err := a.st.GetAuthProvider(ctx, id)
				if err != nil {
					return err
				}
				if p.Config == nil {
					p.Config = map[string]any{}
				}
				p.Config[field] = value
				return a.st.SaveAuthProvider(ctx, p)
			},
		},
		"mailrelay": {
			scope: vault.ScopeInfra,
			load: func(ctx context.Context, _ string) (string, map[string]string, error) {
				cfg := a.st.RawSMTP(ctx)
				// Both modes hold a secret, and either can arrive as a literal
				// through the bootstrap file.
				return "mail relay", map[string]string{
					"password":           cfg.Password,
					"oauth2ClientSecret": cfg.OAuth2.ClientSecret,
				}, nil
			},
			stash: func(ctx context.Context, _, field, value string) error {
				cfg := a.st.RawSMTP(ctx)
				switch field {
				case "password":
					cfg.Password = value
				case "oauth2ClientSecret":
					cfg.OAuth2.ClientSecret = value
				default:
					return fmt.Errorf("the mail relay holds no secret named %q", field)
				}
				return a.st.SetSetting(ctx, store.SettingSMTP, cfg)
			},
		},
	}
}

// stashRequest is what the console sends: where the secret is, and what to call
// the entry. Never the value — it does not have it.
type stashRequest struct {
	Holder      string `json:"holder"`
	ID          string `json:"id"`
	Field       string `json:"field"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// SuggestEntryName derives the name a secret lands under when the caller does
// not pick one: the object it belongs to, then the field. Deterministic on
// purpose, so the same field always suggests the same entry and re-running a
// bootstrap does not scatter near-duplicates.
func SuggestEntryName(id, field string) string {
	name := strings.TrimSpace(id) + "-" + kebab(field)
	name = strings.Trim(strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' || r == '.' {
			return unicode.ToLower(r)
		}
		return '-'
	}, name), "-")
	if name == "" || !unicode.IsLetter(rune(name[0])) {
		name = "secret-" + name
	}
	return name
}

// kebab turns clientSecret into client-secret.
func kebab(s string) string {
	var b strings.Builder
	for i, r := range s {
		if unicode.IsUpper(r) && i > 0 {
			b.WriteByte('-')
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}

// stashSecret moves the literal the server already holds into a new vault
// entry and points the field at it. The value never enters this request or its
// response.
func (a *API) stashSecret(w http.ResponseWriter, r *http.Request, actor store.User) {
	var req stashRequest
	if err := decodeStrict(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request: "+err.Error())
		return
	}
	holders := a.secretHolders()
	h, ok := holders[req.Holder]
	if !ok {
		writeErr(w, http.StatusUnprocessableEntity,
			"unknown secret holder "+req.Holder+" (allowed: "+strings.Join(sortedKeys(holders), ", ")+")")
		return
	}
	ctx := r.Context()
	if !slices.Contains(a.vaultScopes(ctx, actor), h.scope) {
		writeErr(w, http.StatusForbidden, "you do not administer the "+h.scope+" scope")
		return
	}
	label, secrets, err := h.load(ctx, req.ID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "unknown "+req.Holder+" "+req.ID)
		return
	}
	literal, declared := secrets[req.Field]
	if !declared {
		writeErr(w, http.StatusUnprocessableEntity,
			req.Field+" is not a secret field of "+req.Holder+
				" (allowed: "+strings.Join(sortedKeys(secrets), ", ")+")")
		return
	}
	switch {
	case literal == "":
		writeErr(w, http.StatusUnprocessableEntity, "nothing to move: "+req.Field+" holds no value")
		return
	case vault.IsRef(literal):
		writeErr(w, http.StatusUnprocessableEntity,
			req.Field+" is already in the vault, as "+vault.RefName(literal))
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		// A holder with no id of its own (there is one mail relay) would derive
		// a bare field name — "password" alone, squatting a name the whole
		// infra scope shares. Fall back to what it is.
		name = SuggestEntryName(cmp.Or(strings.TrimSpace(req.ID), req.Holder), req.Field)
	}
	if !vault.NameOK.MatchString(name) {
		writeErr(w, http.StatusUnprocessableEntity,
			"a vault name starts with a letter and holds letters, digits, . _ or - (got "+name+")")
		return
	}
	// Never overwrite: the entry that is already there may be what something
	// else resolves, and losing it would break that silently.
	if _, err := a.st.GetVaultEntry(ctx, h.scope, name); err == nil {
		writeErr(w, http.StatusConflict,
			"the "+h.scope+" scope already holds an entry named "+name+
				": pick another name, or point the field at that entry instead")
		return
	}
	entry := vault.Entry{
		Name: name, Kind: vault.KindSecret, Scope: h.scope,
		Value: literal, Description: strings.TrimSpace(req.Description),
	}
	if entry.Description == "" {
		entry.Description = label + " · " + req.Field
	}
	if err := a.st.SaveVaultEntry(ctx, entry); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err := h.stash(ctx, req.ID, req.Field, vault.Ref(name)); err != nil {
		// The entry now holds a secret nothing points at: drop it, or a second
		// attempt would collide with the leftover of the first.
		_, _ = a.st.DeleteVaultEntry(ctx, h.scope, name)
		a.internal(w, fmt.Errorf("the entry was created but %s could not be updated: %w", req.Holder, err))
		return
	}
	// A new entry changes what an already-written $name resolves to, same as
	// saving one from the vault screen does.
	if err := a.router.Reload(ctx); err != nil {
		a.internal(w, fmt.Errorf("moved, but reload failed: %w", err))
		return
	}
	a.auditEvent(ctx, actor, "vault.stash", "vault", name, name, "",
		"from "+label+" · "+req.Field)
	writeJSON(w, http.StatusOK, map[string]string{
		"name": name, "scope": h.scope, "kind": vault.KindSecret, "ref": vault.Ref(name),
	})
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
