package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/softwarity/meerkat/internal/store"
	"github.com/softwarity/meerkat/internal/vault"
)

// registerVault mounts the vault surface (VAULT-01/02). Like the audit trail,
// it is TRANSVERSE: several kinds of administrator keep values here, so the
// guard only asks for a session and each handler scopes the caller to the
// planes their capabilities cover (RBAC-05).
func (a *API) registerVault(mux *http.ServeMux) {
	mux.Handle("GET /api/vault", a.authed(a.listVault))
	mux.Handle("PUT /api/vault/{scope}/{name}", a.authed(a.putVaultEntry))
	mux.Handle("DELETE /api/vault/{scope}/{name}", a.authed(a.deleteVaultEntry))
	// Moving a stored secret in (see secrets.go): the value never leaves the
	// server, so this cannot be done through PUT /api/vault.
	mux.Handle("POST /api/vault/stash", a.authed(a.stashSecret))
	// The vault as an encrypted file (see vaultfile.go).
	a.registerVaultFile(mux)
}

// vaultScopes lists the planes a caller may WRITE: root covers the global ones,
// an infra admin the routing plane, an app admin the application one, and a
// tenant admin their own organisations.
func (a *API) vaultScopes(ctx context.Context, u store.User) []string {
	var scopes []string
	if u.Root || u.InfraAdmin {
		scopes = append(scopes, vault.ScopeInfra)
	}
	if u.Root || u.AppAdmin {
		scopes = append(scopes, vault.ScopeApp)
	}
	if administered, err := a.st.ListTenantsAdministeredBy(ctx, u.ID); err == nil {
		for _, t := range administered {
			scopes = append(scopes, vault.TenantScope(t.ID))
		}
	}
	return scopes
}

// vaultVisibleScopes adds what the caller may READ without editing: a tenant
// admin sees the application entries their tenant inherits, so they can tell
// what a $name will resolve to (and shadow it on purpose).
func (a *API) vaultVisibleScopes(ctx context.Context, u store.User) []string {
	scopes := a.vaultScopes(ctx, u)
	if !slices.Contains(scopes, vault.ScopeApp) {
		for _, sc := range scopes {
			if vault.IsTenantScope(sc) {
				scopes = append(scopes, vault.ScopeApp)
				break
			}
		}
	}
	return scopes
}

// vaultEntryView is one entry as the console sees it. A secret's value is
// NEVER sent: hasValue says it holds one, usedBy says where it is referenced.
type vaultEntryView struct {
	Name        string   `json:"name"`
	Kind        string   `json:"kind"`
	Scope       string   `json:"scope"`
	Value       string   `json:"value,omitempty"`
	HasValue    bool     `json:"hasValue"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	CreatedAt   int64    `json:"createdAt"`
	UpdatedAt   int64    `json:"updatedAt"`
	// ReadOnly marks an inherited entry: a tenant admin sees the application
	// values their scope falls back to, but may only shadow them.
	ReadOnly bool `json:"readOnly,omitempty"`
	// UsedBy names the objects referencing this entry ("route: api"), so an
	// admin can tell a live entry from a leftover before deleting it.
	UsedBy []string `json:"usedBy,omitempty"`
}

func (a *API) listVault(w http.ResponseWriter, r *http.Request, actor store.User) {
	writable := a.vaultScopes(r.Context(), actor)
	if len(writable) == 0 {
		writeErr(w, http.StatusForbidden, "you administer no plane holding vault entries")
		return
	}
	entries, err := a.st.ListVaultEntries(r.Context(), a.vaultVisibleScopes(r.Context(), actor))
	if err != nil {
		a.internal(w, err)
		return
	}
	usage, err := a.vaultUsage(r.Context())
	if err != nil {
		a.internal(w, err)
		return
	}
	out := make([]vaultEntryView, 0, len(entries))
	for _, e := range entries {
		out = append(out, vaultEntryView{
			Name: e.Name, Kind: e.Kind, Scope: e.Scope, Value: e.Value,
			// A stored secret always holds a value (creating one without is
			// refused), and that value never travels.
			HasValue:    e.Kind == vault.KindSecret || e.Value != "",
			Description: e.Description, Tags: e.Tags,
			CreatedAt: e.CreatedAt, UpdatedAt: e.UpdatedAt,
			ReadOnly: !slices.Contains(writable, e.Scope),
			UsedBy:   usage[e.Name],
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) putVaultEntry(w http.ResponseWriter, r *http.Request, actor store.User) {
	var e vault.Entry
	if err := decodeStrict(r, &e); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed vault entry: "+err.Error())
		return
	}
	e.Name = r.PathValue("name")
	e.Scope = r.PathValue("scope")
	if e.Kind == "" {
		e.Kind = vault.KindValue
	}
	if !vault.ValidScope(e.Scope) {
		writeErr(w, http.StatusUnprocessableEntity, "unknown scope "+e.Scope)
		return
	}
	if !slices.Contains(a.vaultScopes(r.Context(), actor), e.Scope) {
		writeErr(w, http.StatusForbidden, "you do not administer the "+e.Scope+" scope")
		return
	}
	_, err := a.st.GetVaultEntry(r.Context(), e.Scope, e.Name)
	existed := err == nil
	if err := a.st.SaveVaultEntry(r.Context(), e); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	// A vault change moves what the routes resolve to: apply it now, exactly
	// like saving a route does.
	if err := a.router.Reload(r.Context()); err != nil {
		a.internal(w, fmt.Errorf("saved, but reload failed: %w", err))
		return
	}
	action := "vault.create"
	if existed {
		action = "vault.update"
	}
	// The VALUE never reaches the audit trail - only that it changed.
	a.auditEvent(r.Context(), actor, action, "vault", e.Name, e.Name, "", e.Kind+" - "+e.Scope)
	writeJSON(w, http.StatusOK, vaultEntryView{Name: e.Name, Kind: e.Kind, Scope: e.Scope, HasValue: true})
}

func (a *API) deleteVaultEntry(w http.ResponseWriter, r *http.Request, actor store.User) {
	name, scope := r.PathValue("name"), r.PathValue("scope")
	if _, err := a.st.GetVaultEntry(r.Context(), scope, name); err != nil {
		writeErr(w, http.StatusNotFound, "vault entry not found")
		return
	}
	if !slices.Contains(a.vaultScopes(r.Context(), actor), scope) {
		writeErr(w, http.StatusForbidden, "you do not administer the "+scope+" scope")
		return
	}
	// Refuse to delete something the configuration still points at: the routes
	// would silently keep an unresolved $name.
	usage, err := a.vaultUsage(r.Context())
	if err != nil {
		a.internal(w, err)
		return
	}
	if used := usage[name]; len(used) > 0 {
		writeErr(w, http.StatusConflict, "still referenced by "+strings.Join(used, ", "))
		return
	}
	if _, err := a.st.DeleteVaultEntry(r.Context(), scope, name); err != nil {
		a.internal(w, err)
		return
	}
	a.auditEvent(r.Context(), actor, "vault.delete", "vault", name, name, "", "")
	w.WriteHeader(http.StatusNoContent)
}

// vaultUsage maps an entry name to the objects referencing it. Each holder is
// scanned as JSON, so a reference counts wherever it sits (an upstream, a
// filter argument, a client secret) without enumerating fields.
//
// Completeness is the point: this is what refuses the deletion of a live entry,
// and a holder missing from here is a holder whose secret can be deleted from
// under it, leaving an authority to fail at the next sign-in with an
// unresolved $name.
func (a *API) vaultUsage(ctx context.Context) (map[string][]string, error) {
	usage := map[string][]string{}
	add := func(label string, holder any) error {
		raw, err := json.Marshal(holder)
		if err != nil {
			return err
		}
		for _, name := range vault.Refs(string(raw)) {
			usage[name] = append(usage[name], label)
		}
		return nil
	}
	routes, err := a.st.ListRoutes(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range routes {
		if err := add("route: "+r.Name, r); err != nil {
			return nil, err
		}
	}
	providers, err := a.st.ListAuthProviders(ctx)
	if err != nil {
		return nil, err
	}
	for _, p := range providers {
		if err := add("authority: "+p.Name, p.Config); err != nil {
			return nil, err
		}
	}
	if err := add("mail relay", a.st.RawSMTP(ctx)); err != nil {
		return nil, err
	}
	return usage, nil
}
