package admin

import (
	"net/http"
	"strings"

	"github.com/softwarity/meerkat/internal/idp"
	"github.com/softwarity/meerkat/internal/store"
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

// providerView is the transport. Secrets inside Config are NOT redacted here
// on purpose: an admin who may configure the authority may read what they
// configured, and the recommended shape is a $name vault reference anyway,
// which is what actually keeps the secret out of this payload.
type providerView struct {
	store.AuthProvider
	// Linked counts the accounts reachable through this authority: deleting
	// it strands them, and the console says so before asking.
	Linked int `json:"linked"`
	// CallbackURL is what has to be registered on the authority's side. It is
	// the single most common reason a first setup fails, so it is handed over
	// rather than described.
	CallbackURL string `json:"callbackUrl,omitempty"`
}

func (a *API) listAuthProviders(w http.ResponseWriter, r *http.Request, _ store.User) {
	all, err := a.st.ListAuthProviders(r.Context())
	if err != nil {
		a.internal(w, err)
		return
	}
	out := make([]providerView, 0, len(all))
	for _, p := range all {
		v := providerView{AuthProvider: p}
		if p.Kind == store.ProviderOIDC || p.Kind == store.ProviderSAML {
			v.CallbackURL = a.callbackURL(r, p.ID)
		}
		out = append(out, v)
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
	// Build the driver before storing: a configuration that cannot even be
	// compiled must be refused at save time, not discovered by the first
	// person trying to sign in.
	if _, err := idp.New(p); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	before, _ := a.st.GetAuthProvider(r.Context(), p.ID)
	if err := a.st.SaveAuthProvider(r.Context(), p); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	saved, err := a.st.GetAuthProvider(r.Context(), p.ID)
	if err != nil {
		a.internal(w, err)
		return
	}
	a.auditUpdate(r.Context(), actor, "authprovider.update", "authprovider", saved.ID, saved.Name, "", before, saved)
	writeJSON(w, http.StatusOK, providerView{AuthProvider: saved, CallbackURL: a.callbackURL(r, saved.ID)})
}

func (a *API) deleteAuthProvider(w http.ResponseWriter, r *http.Request, actor store.User) {
	id := r.PathValue("id")
	before, err := a.st.GetAuthProvider(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "unknown provider "+id)
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
