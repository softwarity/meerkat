package admin

import (
	"maps"
	"net/http"
	"strings"

	"github.com/softwarity/meerkat/internal/features"
	"github.com/softwarity/meerkat/internal/idp"
	"github.com/softwarity/meerkat/internal/store"
	"github.com/softwarity/meerkat/internal/vault"
)

// The authorities (AUTH-19), INFRA plane. A directory or an identity provider
// is a third-party service reached by URL, with credentials and certificates,
// exactly like a route's upstream or the mail relay. What it grants once
// someone is in - tenants, roles - stays the application's.
//
// The accounts held HERE are in that same list (AUTH-24, kind "local"): one
// screen answers "by which door does one come in", and closing the local
// password is disabling that entry, like any other. It is seeded, unique and
// never deleted - and it never governs the ADMIN plane, which always keeps its
// password sign-in so a broken authority stays repairable. Disabling every
// authority is allowed: it means nobody signs in to the DATA plane, which is a
// legitimate state for a gateway serving public routes only.
func (a *API) registerAuthProviders(mux *http.ServeMux) {
	mux.Handle("GET /api/auth-providers", a.infraAdmin(a.listAuthProviders))
	mux.Handle("GET /api/auth-providers/callback-base", a.infraAdmin(a.getCallbackBase))
	mux.Handle("PUT /api/auth-providers/{id}", a.infraAdmin(a.putAuthProvider))
	mux.Handle("DELETE /api/auth-providers/{id}", a.infraAdmin(a.deleteAuthProvider))
	mux.Handle("POST /api/auth-providers/{id}/check", a.infraAdmin(a.checkAuthProvider))
}

// providerView is the transport, and it obeys the rule the whole configuration
// obeys: A REFERENCE IS PUBLIC, A LITERAL NEVER IS. A ${name} comes back as
// itself - it names an entry, not a value, and the console needs it to show
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

// carrySecretsForward fills back the secrets the console could not send. It
// never received the literal, so a blank field means "leave it alone", not
// "erase it" - without this, opening an authority and renaming it would wipe
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

// getCallbackBase answers what the editor needs to show the values an admin
// has to paste into the vendor's form: the data plane's own address (GitHub
// asks for a homepage URL) and the base a callback is built from, so the full
// URL can be composed while the identifier is still being decided.
func (a *API) getCallbackBase(w http.ResponseWriter, r *http.Request, _ store.User) {
	origin := a.dataOrigin(r)
	writeJSON(w, http.StatusOK, map[string]string{"origin": origin, "base": origin + "/login/"})
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
	// Decoded as the VIEW, saved as the model: the console sends back the
	// object it was given, and an endpoint that refuses a field it emitted
	// itself (linked, callbackUrl, secretsSet) breaks the plainest gesture
	// there is - flipping the switch on a row. They are read-only, so they are
	// accepted and dropped here.
	var in providerView
	if err := decodeStrict(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed provider: "+err.Error())
		return
	}
	p := in.AuthProvider
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
	// A directory or a SAML federation is what the licence covers. OIDC and
	// GitHub stay community on purpose: without a free path to a modern
	// identity provider this would be a toll rather than an edition, and what
	// is bought here is plugging an existing estate in DIRECTLY.
	//
	// Only the WRITE is gated. A provider already declared keeps authenticating
	// whatever the licence says - cutting sign-in over a contract would make
	// this undeployable in front of a production.
	if err := requiredFeatureFor(p.Kind); err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	// The local accounts are ONE seeded entry (AUTH-24): its name and its
	// switch are editable, its identity is not. A second one would be a second
	// answer to the same question.
	if (p.Kind == store.ProviderLocal) != (p.ID == store.LocalProviderID) {
		writeErr(w, http.StatusUnprocessableEntity,
			"the local accounts are the built-in authority "+store.LocalProviderID+
				": it cannot be created, renamed to another kind, or duplicated")
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
	// person trying to sign in. The local accounts have no driver - there is
	// no third party to reach - so there is nothing to compile.
	if p.Kind != store.ProviderLocal {
		if _, err := idp.New(p); err != nil {
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
	// The local accounts are part of the product, not a configuration one
	// added: they are turned off, never removed.
	if before.Kind == store.ProviderLocal {
		writeErr(w, http.StatusUnprocessableEntity,
			"the local accounts cannot be deleted: disable them to close password sign-in on the data plane")
		return
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
	return a.callbackBase(r) + providerID + "/callback"
}

// callbackBase is that same address minus the identifier, and it exists for
// the moment the identifier does not: while CREATING an authority, the admin
// is filling in the vendor's form in another tab and needs the callback then,
// not after a first save. Only the server can build it - the console is served
// by the admin port and has no idea what the data plane listens on - so it
// hands over the base and the console completes it.
func (a *API) callbackBase(r *http.Request) string {
	return a.dataOrigin(r) + "/login/"
}

// dataOrigin is where a sign-in actually happens, scheme and host. The admin
// plane and the data plane are different origins, and every address a vendor
// has to be given (GitHub asks for a homepage AND a callback) is rooted here,
// never in the console's own address.
func (a *API) dataOrigin(r *http.Request) string {
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
	return scheme + "://" + host
}

// requiredFeatureFor maps an authority kind to the feature that may declare it.
func requiredFeatureFor(kind string) error {
	switch kind {
	case store.ProviderLDAP:
		return features.Require(features.Directories)
	case store.ProviderSAML:
		return features.Require(features.SAML)
	}
	return nil
}
