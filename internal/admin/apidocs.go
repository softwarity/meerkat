package admin

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/softwarity/meerkat/internal/admin/apidocs"
	"github.com/softwarity/meerkat/internal/gateway"
	"github.com/softwarity/meerkat/internal/openapi"
	"github.com/softwarity/meerkat/internal/store"
	"github.com/softwarity/meerkat/internal/version"
)

// registerAPIDocs mounts the swagger-ui page (DOCS-01): the assets vendored in
// the binary (offline-first — nothing comes from a CDN), the list of available
// specifications, Meerkat's own admin spec, and a server-side proxy for the
// specs the routes declare (same origin, so the browser needs no CORS). The
// whole surface ships OFF and plays dead (404) until an infra admin flips
// SettingAPIDocsExposed on the Others screen.
func (a *API) registerAPIDocs(mux *http.ServeMux) {
	mux.Handle("GET /api/settings/api-docs", a.infraAdmin(a.getAPIDocsSetting))
	mux.Handle("PUT /api/settings/api-docs", a.infraAdmin(a.putAPIDocsSetting))
	mux.Handle("GET /apidocs", a.ifDocsExposed(http.RedirectHandler("/apidocs/", http.StatusMovedPermanently)))
	mux.Handle("GET /apidocs/{$}", a.ifDocsExposed(http.HandlerFunc(a.apidocsPage)))
	mux.Handle("GET /apidocs/assets/{file}", a.ifDocsExposed(http.HandlerFunc(apidocsAsset)))
	mux.Handle("GET /apidocs/specs.json", a.ifDocsExposed(a.authed(a.apidocsSpecs)))
	mux.Handle("GET /apidocs/specs/meerkat-admin.json", a.ifDocsExposed(a.authed(a.apidocsAdminSpec)))
	mux.Handle("GET /apidocs/specs/route/{id}", a.ifDocsExposed(a.gw(a.apidocsRouteSpec)))
	mux.Handle("/apidocs/try/", a.ifDocsExposed(a.gw(a.apidocsTry))) // every method: Try it out
	mux.Handle("POST /api/apidocs/token", a.ifDocsExposed(a.authed(a.mintTestToken)))
}

// testTokenRequest is the API screen's mint form: an identity to impersonate
// and a bounded lifetime.
type testTokenRequest struct {
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
	Minutes  int      `json:"minutes"`
}

// mintTestToken issues an ephemeral test token (gateway/simulate.go): pasted
// into swagger's Authorize, it carries the whole authorization — the same
// capabilities that may simulate by header may mint.
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

// apiDocsSetting is the Others screen's payload.
type apiDocsSetting struct {
	Exposed bool `json:"exposed"`
}

// apidocsExposedOn reads the switch (absent = off).
func (a *API) apidocsExposedOn(ctx context.Context) bool {
	var exposed bool
	_ = a.st.GetSetting(ctx, store.SettingAPIDocsExposed, &exposed)
	return exposed
}

// ifDocsExposed hides the docs surface entirely while the switch is off — a
// 404 indistinguishable from "no such path", not a 403 advertising a feature.
func (a *API) ifDocsExposed(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.apidocsExposedOn(r.Context()) {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *API) getAPIDocsSetting(w http.ResponseWriter, r *http.Request, _ store.User) {
	writeJSON(w, http.StatusOK, apiDocsSetting{Exposed: a.apidocsExposedOn(r.Context())})
}

func (a *API) putAPIDocsSetting(w http.ResponseWriter, r *http.Request, actor store.User) {
	var body apiDocsSetting
	if err := decodeStrict(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed setting: "+err.Error())
		return
	}
	before := apiDocsSetting{Exposed: a.apidocsExposedOn(r.Context())}
	if err := a.st.SetSetting(r.Context(), store.SettingAPIDocsExposed, body.Exposed); err != nil {
		a.internal(w, err)
		return
	}
	a.auditUpdate(r.Context(), actor, "apidocs.expose", "settings", "", "", "", before, body)
	writeJSON(w, http.StatusOK, body)
}

// apidocsTry hands a Try-it-out call to the data plane IN PROCESS: the page
// and its calls stay on the admin origin (nothing cross-origin, cookies just
// travel), and the router matches exactly as if the request had hit the data
// port. The admin session authorizes identity simulation, a data session
// authenticates gated routes, and the proxy transport strips every gateway
// cookie and simulation header before the upstream, as for any call.
func (a *API) apidocsTry(w http.ResponseWriter, r *http.Request) {
	fwd := r.Clone(r.Context())
	fwd.URL.Path = strings.TrimPrefix(r.URL.Path, "/apidocs/try")
	if fwd.URL.Path == "" {
		fwd.URL.Path = "/"
	}
	fwd.URL.RawPath = ""
	fwd.RequestURI = ""
	a.router.ServeHTTP(w, fwd)
}

// apidocsPage serves the shell. A browser without a live session is sent to
// the login page (and comes back here) instead of staring at a JSON 401.
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

// apidocsSpecs lists what the picker offers: Meerkat's own admin API for every
// signed-in console user, plus the spec of each route that declares one for
// actors on the routing plane (the same scope that may read those routes).
func (a *API) apidocsSpecs(w http.ResponseWriter, r *http.Request, actor store.User) {
	specs := []specRef{{Name: "Meerkat Admin API", URL: "specs/meerkat-admin.json"}}
	if actor.Root || actor.InfraAdmin {
		routes, err := a.st.ListRoutes(r.Context())
		if err != nil {
			a.internal(w, err)
			return
		}
		for _, route := range routes {
			if route.API == nil || strings.TrimSpace(route.API.OpenapiURL) == "" {
				continue
			}
			specs = append(specs, specRef{Name: route.Name, URL: "specs/route/" + route.ID})
		}
	}
	// Deleted routes must leave the picker on the next load.
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, specs)
}

// apidocsAdminSpec serves the embedded admin spec, stamped with the build
// version so the page shows what this binary actually answers.
func (a *API) apidocsAdminSpec(w http.ResponseWriter, _ *http.Request, _ store.User) {
	spec := bytes.Replace(apidocs.AdminSpec,
		[]byte(`"version": "dev"`), []byte(`"version": "`+version.Version+`"`), 1)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(spec)
}

// apidocsRouteSpec obtains a route's declared OpenAPI spec and hands it to
// the page. A RELATIVE openapiUrl travels THROUGH THE ROUTE itself — an
// in-process data-plane request, so vault expansion, filters, access rules
// and the real upstream all apply exactly as for any client; an ABSOLUTE url
// is fetched directly (it explicitly points elsewhere). The spec's own server
// information (httpbin ships its literal host, for instance) is then
// REWRITTEN to the route's public base, so the display and Try it out both
// cross the gateway. A YAML spec passes through untouched.
func (a *API) apidocsRouteSpec(w http.ResponseWriter, r *http.Request) {
	route, err := a.st.GetRoute(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "route not found")
		return
	}
	if route.API == nil || strings.TrimSpace(route.API.OpenapiURL) == "" {
		writeErr(w, http.StatusUnprocessableEntity, "this route declares no OpenAPI spec url")
		return
	}
	specURL := strings.TrimSpace(route.API.OpenapiURL)
	var body []byte
	var contentType string
	if strings.HasPrefix(specURL, "http://") || strings.HasPrefix(specURL, "https://") {
		body, contentType, err = a.fetchSpecDirect(r.Context(), specURL)
	} else {
		body, contentType, err = a.fetchSpecThroughRoute(r, route, specURL)
	}
	if err != nil {
		writeErr(w, http.StatusBadGateway, "spec fetch failed: "+err.Error())
		return
	}
	// Point the spec's servers at the same-origin forwarder: the page, its
	// cookies and every Try it out stay on this admin port; the tunnel hands
	// the call to the data plane in process. The route's own match prefix is
	// part of the public path.
	if rewritten, err := openapi.Rewrite(body, "/apidocs/try"+routeMatchPrefix(route)); err == nil {
		body, contentType = rewritten, "application/json; charset=utf-8"
		// Identity simulation (gateway/simulate.go): let Authorize input a
		// user and roles for Try it out, on every route spec.
		if enriched, err := openapi.InjectSimulation(body); err == nil {
			body = enriched
		}
	}
	if contentType == "" {
		contentType = "application/json; charset=utf-8"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(body)
}

// fetchSpecDirect GETs an absolute spec url server-side.
func (a *API) fetchSpecDirect(ctx context.Context, specURL string) ([]byte, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, specURL, nil)
	if err != nil {
		return nil, "", err
	}
	res, err := specClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("upstream answered %s", res.Status)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	return body, res.Header.Get("Content-Type"), err
}

// fetchSpecThroughRoute resolves a relative spec url THROUGH the data plane:
// an in-process request on the route's public path (its prefix + the relative
// url), carrying the caller's cookies — so the route's own access rules apply
// to its spec exactly as they would to any client, and endpoint security can
// delegate just that path if desired.
func (a *API) fetchSpecThroughRoute(r *http.Request, route store.Route, rel string) ([]byte, string, error) {
	path := routeMatchPrefix(route) + "/" + strings.TrimLeft(rel, "/")
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	// The caller was verified root/infra-admin by this endpoint's guard:
	// reading the contract bypasses the route's access, calls never do.
	ctx = gateway.WithSpecRead(ctx)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://gateway.internal"+path, nil)
	if err != nil {
		return nil, "", err
	}
	if host := routeLiteralHost(route); host != "" {
		req.Host = host // host predicates must keep matching
	} else if h, _, splitErr := net.SplitHostPort(r.Host); splitErr == nil {
		req.Host = h
	} else {
		req.Host = r.Host
	}
	if c := r.Header.Get("Cookie"); c != "" {
		req.Header.Set("Cookie", c)
	}
	rec := &specRecorder{header: http.Header{}, status: http.StatusOK}
	a.router.ServeHTTP(rec, req)
	if rec.status != http.StatusOK {
		return nil, "", fmt.Errorf("the route answered %d for %s", rec.status, path)
	}
	return rec.buf.Bytes(), rec.header.Get("Content-Type"), nil
}

// specRecorder captures the data plane's in-process answer, bounded.
type specRecorder struct {
	header http.Header
	status int
	buf    bytes.Buffer
}

func (r *specRecorder) Header() http.Header { return r.header }
func (r *specRecorder) WriteHeader(s int)   { r.status = s }
func (r *specRecorder) Write(p []byte) (int, error) {
	if r.buf.Len()+len(p) > 8<<20 {
		p = p[:max(0, 8<<20-r.buf.Len())]
	}
	return r.buf.Write(p)
}

// routeLiteralHost returns the first wildcard-free host the route matches on,
// or "".
func routeLiteralHost(route store.Route) string {
	for _, p := range route.Predicates {
		if p.Type != "host" {
			continue
		}
		for _, h := range specStrings(p.Args["hosts"]) {
			if h != "" && !strings.Contains(h, "*") {
				return h
			}
		}
	}
	return ""
}

// routeMatchPrefix is the static prefix a client's path must carry to enter
// the route ("/demo/**" → "/demo") — where its relative spec lives publicly.
func routeMatchPrefix(route store.Route) string {
	for _, p := range route.Predicates {
		if p.Type != "path" {
			continue
		}
		if patterns := specStrings(p.Args["patterns"]); len(patterns) > 0 {
			return staticPrefix(patterns[0])
		}
		break
	}
	return ""
}

// staticPrefix keeps the pattern's leading literal segments: "/demo/v1/**" →
// "/demo/v1", "/{tenant}/api/**" → "".
func staticPrefix(pattern string) string {
	var kept []string
	for _, seg := range strings.Split(strings.Trim(pattern, "/"), "/") {
		if seg == "" || strings.ContainsAny(seg, "*{") {
			break
		}
		kept = append(kept, seg)
	}
	if len(kept) == 0 {
		return ""
	}
	return "/" + strings.Join(kept, "/")
}

// specStrings coerces a decoded JSON list into its string items.
func specStrings(v any) []string {
	items, _ := v.([]any)
	out := make([]string, 0, len(items))
	for _, it := range items {
		if s, ok := it.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
