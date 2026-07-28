package admin

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/softwarity/meerkat/internal/admin/apidocs"
	"github.com/softwarity/meerkat/internal/store"
	"github.com/softwarity/meerkat/internal/version"
)

// registerAPIDocs mounts the swagger-ui page (DOCS-01): the assets vendored in
// the binary (offline-first — nothing comes from a CDN), the list of available
// specifications, Meerkat's own admin spec, and a server-side proxy for the
// specs the routes declare (same origin, so the browser needs no CORS).
func (a *API) registerAPIDocs(mux *http.ServeMux) {
	mux.Handle("GET /apidocs", http.RedirectHandler("/apidocs/", http.StatusMovedPermanently))
	mux.HandleFunc("GET /apidocs/{$}", a.apidocsPage)
	mux.HandleFunc("GET /apidocs/assets/{file}", apidocsAsset)
	mux.Handle("GET /apidocs/specs.json", a.authed(a.apidocsSpecs))
	mux.Handle("GET /apidocs/specs/meerkat-admin.json", a.authed(a.apidocsAdminSpec))
	mux.Handle("GET /apidocs/specs/route/{id}", a.gw(a.apidocsRouteSpec))
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

// apidocsRouteSpec fetches a route's declared OpenAPI spec server-side and
// hands it to the page: same origin for the browser, and the upstream stays
// reachable even when only the gateway can see it. The spec's own server
// information (httpbin ships its literal host, for instance) is REWRITTEN to
// the route's public base, so the display and Try it out both cross the
// gateway — and its endpoint security — instead of calling the upstream
// directly. A YAML spec passes through untouched (only gateway targeting is
// lost).
func (a *API) apidocsRouteSpec(w http.ResponseWriter, r *http.Request) {
	route, err := a.st.GetRoute(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "route not found")
		return
	}
	specURL, err := resolveSpecURL(route)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, specURL, nil)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	res, err := specClient.Do(req)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "spec fetch failed: "+err.Error())
		return
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		writeErr(w, http.StatusBadGateway, "spec fetch failed: upstream answered "+res.Status)
		return
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		writeErr(w, http.StatusBadGateway, "spec fetch failed: "+err.Error())
		return
	}
	contentType := res.Header.Get("Content-Type")
	if rewritten, err := openapi.Rewrite(body, a.routeExposedBase(r, route)); err == nil {
		body, contentType = rewritten, "application/json; charset=utf-8"
	}
	if contentType == "" {
		contentType = "application/json; charset=utf-8"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(body)
}

// routeExposedBase derives the public URL the route answers on. Host: a
// literal host predicate when the route pins one, otherwise this admin
// request's hostname on the data plane's port (DataAddr) — the two planes ride
// the same machine. Path: the static prefix of the route's path pattern, kept
// only when a strip-prefix filter removes exactly that prefix (otherwise the
// upstream sees the full path and the spec's paths already carry it). A
// rewrite-path filter makes the mapping non-derivable: origin only.
func (a *API) routeExposedBase(r *http.Request, route store.Route) string {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	host := routeLiteralHost(route)
	if host == "" {
		hostname := r.Host
		if h, _, err := net.SplitHostPort(r.Host); err == nil {
			hostname = h
		}
		host = hostname
		if _, port, err := net.SplitHostPort(a.DataAddr); err == nil && port != "" {
			host = net.JoinHostPort(hostname, port)
		}
	}
	return scheme + "://" + host + routePathPrefix(route)
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

// routePathPrefix returns the static prefix of the route's first path pattern
// ("/demo/**" → "/demo") when a strip-prefix filter removes exactly those
// segments; otherwise "" (see routeExposedBase).
func routePathPrefix(route store.Route) string {
	var prefix string
	for _, p := range route.Predicates {
		if p.Type != "path" {
			continue
		}
		if patterns := specStrings(p.Args["patterns"]); len(patterns) > 0 {
			prefix = staticPrefix(patterns[0])
		}
		break
	}
	if prefix == "" {
		return ""
	}
	stripped := 0
	for _, f := range route.Filters {
		switch f.Type {
		case "rewrite-path":
			return ""
		case "strip-prefix":
			if n, ok := f.Args["parts"].(float64); ok {
				stripped = int(n)
			} else {
				stripped = 1 // the filter's default
			}
		}
	}
	if stripped != strings.Count(prefix, "/") {
		return ""
	}
	return prefix
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
