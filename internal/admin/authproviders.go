package admin

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"strings"

	"github.com/softwarity/meerkat/internal/idp"
	"github.com/softwarity/meerkat/internal/store"
	"github.com/softwarity/meerkat/internal/vault"
)

// External authorities (AUTH-19), INFRA plane. A directory or an identity
// provider is a third-party service reached by URL, with credentials and
// certificates, exactly like a route's upstream or the mail relay. What it
// grants once someone is in — tenants, roles — stays the application's.
func (a *API) registerAuthProviders(mux *http.ServeMux) {
	mux.Handle("GET /api/auth-providers", a.infraAdmin(a.listAuthProviders))
	mux.Handle("PUT /api/auth-providers/{id}", a.infraAdmin(a.putAuthProvider))
	mux.Handle("DELETE /api/auth-providers/{id}", a.infraAdmin(a.deleteAuthProvider))
	mux.Handle("POST /api/auth-providers/{id}/check", a.infraAdmin(a.checkAuthProvider))
}

// providerView is the transport, and it obeys the rule the whole configuration
// obeys: A REFERENCE IS PUBLIC, A LITERAL NEVER IS. A ${name} comes back as
// itself — it names an entry, not a value, and the console needs it to show
// which one. A literal secret is stripped out entirely and only named in
// SecretsSet, so it never travels through a response, a browser, a cache or an
// export, whoever is entitled to read it.
type providerView struct {
	store.AuthProvider
	// Linked counts the accounts reachable through this authority: deleting
	// it strands them, and the console says so before asking.
	Linked int `json:"linked"`
	// CallbackURL is what has to be registered on the authority's side. It is
	// the single most common reason a first setup fails, so it is handed over
	// rather than described.
	CallbackURL string `json:"callbackUrl,omitempty"`
	// SecretsSet names the secret fields that hold a stored LITERAL: the value
	// is not in this payload, but the console has to know one exists, or an
	// empty-looking field reads as "not configured" and invites a reset.
	SecretsSet []string `json:"secretsSet,omitempty"`
}

// publicProvider returns the authority as the console may see it, plus the
// fields whose literal was withheld.
func publicProvider(p store.AuthProvider) (store.AuthProvider, []string) {
	fields := idp.SecretFields(p.Kind)
	if len(fields) == 0 || len(p.Config) == 0 {
		return p, nil
	}
	// Copy: the config comes from the store's own decode, and stripping it in
	// place would blank it for whatever else holds that map.
	cfg := make(map[string]any, len(p.Config))
	maps.Copy(cfg, p.Config)
	var held []string
	for _, field := range fields {
		s, ok := cfg[field].(string)
		if !ok || s == "" || vault.IsRef(s) {
			continue
		}
		delete(cfg, field)
		held = append(held, field)
	}
	p.Config = cfg
	return p, held
}

// view builds the transport for one authority, callback URL included.
func (a *API) providerView(r *http.Request, p store.AuthProvider) providerView {
	public, held := publicProvider(p)
	v := providerView{AuthProvider: public, SecretsSet: held}
	if p.Kind == store.ProviderOIDC || p.Kind == store.ProviderSAML || p.Kind == store.ProviderGitHub {
		v.CallbackURL = a.callbackURL(r, p.ID)
	}
	return v
}

// lastWayIn refuses to take away the last authority while the local password
// is restricted (AUTH-24). Two screens, two admins, one hole: the password can
// be closed on the application side and the authority disabled on the infra
// side, and neither knows about the other. This is the check on the second
// side. excludeID is the authority about to be disabled or deleted.
func (a *API) lastWayIn(ctx context.Context, excludeID string) error {
	if a.st.GetPasswordLoginPolicy(ctx).Mode == store.PasswordLoginEveryone {
		return nil
	}
	all, err := a.st.ListAuthProviders(ctx)
	if err != nil {
		return err
	}
	for _, p := range all {
		if p.Enabled && p.ID != excludeID {
			return nil
		}
	}
	return errors.New("password sign-in is restricted (Application, Security): " +
		"this is the last authority, and taking it away would leave no way into the data plane")
}

// carrySecretsForward fills back the secrets the console could not send. It
// never received the literal, so a blank field means "leave it alone", not
// "erase it" — without this, opening an authority and renaming it would wipe
// its client secret.
func carrySecretsForward(incoming *store.AuthProvider, stored store.AuthProvider) {
	for _, field := range idp.SecretFields(incoming.Kind) {
		if s, ok := incoming.Config[field].(string); ok && s != "" {
			continue // the admin typed a new one, or picked a reference
		}
		kept, ok := stored.Config[field]
		if !ok {
			continue
		}
		if incoming.Config == nil {
			incoming.Config = map[string]any{}
		}
		incoming.Config[field] = kept
	}
}

func (a *API) listAuthProviders(w http.ResponseWriter, r *http.Request, _ store.User) {
	all, err := a.st.ListAuthProviders(r.Context())
	if err != nil {
		a.internal(w, err)
		return
	}
	out := make([]providerView, 0, len(all))
	for _, p := range all {
		out = append(out, a.providerView(r, p))
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) putAuthProvider(w http.ResponseWriter, r *http.Request, actor store.User) {
	var p store.AuthProvider
	if err := decodeStrict(r, &p); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed provider: "+err.Error())
		return
	}
	p.ID = r.PathValue("id")
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		writeErr(w, http.StatusUnprocessableEntity, "a provider needs a name: it is what the login page shows")
		return
	}
	if !store.ValidProviderKind(p.Kind) {
		writeErr(w, http.StatusUnprocessableEntity, "unknown provider kind "+p.Kind+
			" (allowed: "+store.ProviderOIDC+", "+store.ProviderLDAP+", "+store.ProviderSAML+")")
		return
	}
	if !store.ValidPolicy(p.MFARequired) || !store.ValidPolicy(p.Passkeys) {
		writeErr(w, http.StatusUnprocessableEntity,
			"a policy must be empty (inherit), "+store.PolicyYes+" or "+store.PolicyNo)
		return
	}
	// Bring the stored secrets back BEFORE validating: the console never
	// received them, so a driver built on the payload alone would be refused
	// for a missing client secret that is in fact perfectly well set.
	before, _ := a.st.GetAuthProvider(r.Context(), p.ID)
	carrySecretsForward(&p, before)

	// Build the driver before storing: a configuration that cannot even be
	// compiled must be refused at save time, not discovered by the first
	// person trying to sign in.
	if _, err := idp.New(p); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	// The other half of the AUTH-24 guard: restricting the password checks that
	// an authority exists, and this checks that the last one does not go away
	// underneath it. Either way round, the data plane keeps a way in.
	if !p.Enabled && before.Enabled {
		if err := a.lastWayIn(r.Context(), p.ID); err != nil {
			writeErr(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
	}
	if err := a.st.SaveAuthProvider(r.Context(), p); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	saved, err := a.st.GetAuthProvider(r.Context(), p.ID)
	if err != nil {
		a.internal(w, err)
		return
	}
	// The audit trail sees the PUBLIC form for the same reason the console
	// does: a literal secret has no business being written down, and the diff
	// still records a field going from unset to set through SecretsSet.
	view := a.providerView(r, saved)
	beforeView, beforeHeld := publicProvider(before)
	a.auditUpdate(r.Context(), actor, "authprovider.update", "authprovider", saved.ID, saved.Name, "",
		providerView{AuthProvider: beforeView, SecretsSet: beforeHeld}, view)
	writeJSON(w, http.StatusOK, view)
}

func (a *API) deleteAuthProvider(w http.ResponseWriter, r *http.Request, actor store.User) {
	id := r.PathValue("id")
	before, err := a.st.GetAuthProvider(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "unknown provider "+id)
		return
	}
	if before.Enabled {
		if err := a.lastWayIn(r.Context(), id); err != nil {
			writeErr(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
	}
	ok, err := a.st.DeleteAuthProvider(r.Context(), id)
	if err != nil {
		a.internal(w, err)
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "unknown provider "+id)
		return
	}
	a.auditEvent(r.Context(), actor, "authprovider.delete", "authprovider", id, before.Name, "", "")
	w.WriteHeader(http.StatusNoContent)
}

// checkAuthProvider tries the configuration WITHOUT signing anyone in: an OIDC
// authority is asked for its discovery document, a directory for a bind with
// the service account. It answers what actually failed, because "invalid
// client secret" and "the issuer does not resolve" call for different fixes.
func (a *API) checkAuthProvider(w http.ResponseWriter, r *http.Request, _ store.User) {
	id := r.PathValue("id")
	p, missing, err := a.st.ResolvedAuthProvider(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "unknown provider "+id)
		return
	}
	if len(missing) > 0 {
		writeErr(w, http.StatusUnprocessableEntity,
			"unknown vault entries: "+strings.Join(missing, ", "))
		return
	}
	driver, err := idp.New(p)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err := idp.Check(r.Context(), driver); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "kind": p.Kind, "name": p.Name})
}

// callbackURL is the address to register on the authority's side. The admin
// plane and the data plane are different origins, and the sign-in happens on
// the DATA plane, so it is derived from there.
func (a *API) callbackURL(r *http.Request, providerID string) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := a.DataAddr
	if host == "" || strings.HasPrefix(host, ":") {
		// No explicit data address: same hostname, its own port.
		name := r.Host
		if i := strings.LastIndexByte(name, ':'); i >= 0 {
			name = name[:i]
		}
		host = name + host
	}
	return scheme + "://" + host + "/login/" + providerID + "/callback"
}
