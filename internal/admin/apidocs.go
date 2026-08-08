package admin

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/softwarity/meerkat/internal/admin/apidocs"
	"github.com/softwarity/meerkat/internal/store"
	"github.com/softwarity/meerkat/internal/version"
)

// registerAPIDocs mounts the CONSOLE swagger-ui (DOCS-01): assets vendored in
// the binary (offline-first - nothing comes from a CDN) and Meerkat's OWN
// admin API, served and tried on this very origin. It stays here, on the
// control plane: the data plane never exposes Meerkat's contract. The routes'
// specs are a DEVELOPER matter and live there instead
// (gateway.RegisterDevDocs), where the dev capability is the whole gate.
func (a *API) registerAPIDocs(mux *http.ServeMux) {
	mux.Handle("GET /apidocs", http.RedirectHandler("/apidocs/", http.StatusMovedPermanently))
	mux.HandleFunc("GET /apidocs/{$}", a.apidocsPage)
	mux.HandleFunc("GET /apidocs/assets/{file}", apidocsAsset)
	mux.Handle("GET /apidocs/specs.json", a.authed(a.apidocsSpecs))
	mux.Handle("GET /apidocs/specs/meerkat-admin.json", a.authed(a.apidocsAdminSpec))
	mux.Handle("POST /api/apidocs/token", a.authed(a.mintTestToken))
}

// apidocsPage serves the shell. A browser without a live session is sent to
// the login page (and comes back after) instead of staring at a JSON 401.
func (a *API) apidocsPage(w http.ResponseWriter, r *http.Request) {
	if sess, err := a.sm.Resolve(r.Context(), r); err != nil || sess.Pending != "" {
		http.Redirect(w, r, "/login?next="+url.QueryEscape("/apidocs/"), http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(apidocs.Page)
}

// apidocsAsset serves the vendored swagger-ui files and the Sentinel skin.
// They carry no data, so they are not session-gated; an hour of cache keeps
// the iframe snappy without pinning an old bundle after an upgrade.
func apidocsAsset(w http.ResponseWriter, r *http.Request) {
	var body []byte
	var contentType string
	switch r.PathValue("file") {
	case "swagger-ui-bundle.js":
		body, contentType = apidocs.BundleJS, "application/javascript; charset=utf-8"
	case "swagger-ui.css":
		body, contentType = apidocs.CSS, "text/css; charset=utf-8"
	case "skin.css":
		body, contentType = apidocs.Skin, "text/css; charset=utf-8"
	default:
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(body)
}

// specRef is one entry of the spec picker.
type specRef struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// apidocsSpecs: the console documents the CONTROL plane - Meerkat's own API,
// nothing else. The routes' specs live on the data plane, for developers.
func (a *API) apidocsSpecs(w http.ResponseWriter, _ *http.Request, _ store.User) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, []specRef{{Name: "Meerkat Admin API", URL: "specs/meerkat-admin.json"}})
}

// apidocsAdminSpec serves the embedded admin spec, stamped with the build
// version so the page shows what this binary actually answers. Its servers
// are this origin: Try it out hits /api directly, no tunnel involved.
func (a *API) apidocsAdminSpec(w http.ResponseWriter, _ *http.Request, _ store.User) {
	spec := bytes.Replace(apidocs.AdminSpec,
		[]byte(`"version": "dev"`), []byte(`"version": "`+version.Version+`"`), 1)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(spec)
}

// testTokenRequest is the API screen's mint form: an identity to impersonate
// and a bounded lifetime.
type testTokenRequest struct {
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
	Minutes  int      `json:"minutes"`
}

// mintTestToken issues an ephemeral test token (gateway/simulate.go): sent as
// `Authorization: Bearer mksim_...` to the data plane (swagger, curl, Postman),
// it carries the whole authorization - the same capabilities that may
// simulate by header may mint.
func (a *API) mintTestToken(w http.ResponseWriter, r *http.Request, actor store.User) {
	mayMint := actor.Root || actor.InfraAdmin || actor.Dev || actor.Tester
	if !mayMint {
		writeErr(w, http.StatusForbidden, "minting test tokens requires the root, infra-admin, dev or tester capability")
		return
	}
	var body testTokenRequest
	if err := decodeStrict(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request: "+err.Error())
		return
	}
	body.Username = strings.TrimSpace(body.Username)
	if body.Username == "" {
		writeErr(w, http.StatusUnprocessableEntity, "a username is required (the identity the token impersonates)")
		return
	}
	if body.Minutes < 1 || body.Minutes > 60 {
		body.Minutes = 15
	}
	token, exp := a.router.MintSimulationToken(body.Username, body.Roles, time.Duration(body.Minutes)*time.Minute)
	a.auditEvent(r.Context(), actor, "token.simulate", "token", "", body.Username, "",
		fmt.Sprintf("test token as %q roles %v for %dm", body.Username, body.Roles, body.Minutes))
	writeJSON(w, http.StatusCreated, map[string]any{"token": token, "expiresAt": exp.Unix()})
}
