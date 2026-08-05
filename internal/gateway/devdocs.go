package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/softwarity/meerkat/internal/admin/apidocs"
	"github.com/softwarity/meerkat/internal/openapi"
	"github.com/softwarity/meerkat/internal/store"
)

// Developer API docs (DOCS-01, data plane): /meerkat/apidocs serves the
// embedded swagger-ui over the specs the ROUTES declare - every one of them,
// enabled or not: a developer legitimately sees what exists and what is being
// built. Gated by a data session with the `dev` capability (the same family
// as /profile/dev-cert), and by nothing else. The
// profile bar simulates identities (all roles by default) through the
// standard simulation headers - applySimulation authorizes devs on this
// plane.

// devSpecClient fetches ABSOLUTE spec urls server-side; relative ones travel
// through the route in process.
var devSpecClient = &http.Client{Timeout: 20 * time.Second}

// RegisterDevDocs mounts the developer docs on the data-plane mux, ahead of
// the route fallback.
func (rt *Router) RegisterDevDocs(mux *http.ServeMux) {
	mux.Handle("GET /meerkat/apidocs", http.RedirectHandler("/meerkat/apidocs/", http.StatusMovedPermanently))
	mux.HandleFunc("GET /meerkat/apidocs/{$}", rt.devDocsPage)
	mux.HandleFunc("GET /meerkat/apidocs/assets/{file}", rt.devDocsAsset)
	mux.HandleFunc("GET /meerkat/apidocs/catalog.json", rt.devDocsCatalog)
	mux.HandleFunc("GET /meerkat/apidocs/spec/{id}", rt.devDocsSpec)
}

// devDocsUser resolves the caller and requires the dev capability. The bool
// tells gated JSON endpoints apart from the page redirect flow.
func (rt *Router) devDocsUser(r *http.Request) (store.User, bool) {
	u, _, ok := rt.devDocsSession(r)
	return u, ok
}

// devDocsSession resolves the caller (dev capability) AND their current tenant
// - the profile bar lists that tenant's groups, no other.
func (rt *Router) devDocsSession(r *http.Request) (store.User, string, bool) {
	sess, err := rt.sm.Resolve(r.Context(), r)
	if err != nil || sess.Pending != "" {
		return store.User{}, "", false
	}
	u, err := rt.st.GetUserByID(r.Context(), sess.UserID)
	if err != nil || !u.Enabled || !u.Dev {
		return store.User{}, "", false
	}
	return u, sess.TenantID, true
}

func (rt *Router) devDocsPage(w http.ResponseWriter, r *http.Request) {
	if sess, err := rt.sm.Resolve(r.Context(), r); err != nil || sess.Pending != "" {
		http.Redirect(w, r, "/login?next="+url.QueryEscape("/meerkat/apidocs/"), http.StatusSeeOther)
		return
	}
	if _, ok := rt.devDocsUser(r); !ok {
		http.Error(w, "the developer capability is required for the API docs", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(bytes.Replace(apidocs.DevPage, []byte("</head>"),
		[]byte(rt.devDocsTheme(r.Context())+"</head>"), 1))
}

// devDocsThemeBridge remaps the swagger skin's Sentinel tokens onto the active
// theme's tokens. Declared after skin.css AND after the page's own styles, so
// it wins the cascade. The active mode buttons swap to on-primary ink: the
// theme's primary may be a light color where the skin's white would vanish.
const devDocsThemeBridge = `
    :root {
      --mk-field: var(--mk-surface);
      --mk-bar: var(--mk-surface-container);
      --mk-panel: var(--mk-surface-container);
      --mk-panel-2: var(--mk-surface-container-high);
      --mk-ink: var(--mk-on-surface);
      --mk-muted: var(--mk-on-surface-variant);
      --mk-line: var(--mk-outline);
      --mk-teal: var(--mk-primary);
      --mk-cyan: var(--mk-primary);
      --mk-code-bg: var(--mk-surface-container);
    }
    .mk-btn.on, .mk-btn.on b, .mk-btn.on .sum { color: var(--mk-on-primary); }
  `

// devDocsTheme renders the ACTIVE theme as a <style> block for the developer
// page: this is the data plane, it follows the chosen look like every flow
// page. Only injected here; the console's /apidocs keeps the stock skin.
func (rt *Router) devDocsTheme(ctx context.Context) string {
	t, err := rt.st.GetActiveTheme(ctx)
	if err != nil {
		t = store.DefaultTheme()
	}
	return "<style>\n    " + t.CSS() + devDocsThemeBridge + "</style>\n"
}

func (rt *Router) devDocsAsset(w http.ResponseWriter, r *http.Request) {
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

// devDocsCatalog feeds the page in one request: who the developer is, the
// whole role catalogue, the CURRENT TENANT's groups resolved to effective role
// names (hierarchy applied server-side), the users one may impersonate, and
// the routes exposing a spec.
func (rt *Router) devDocsCatalog(w http.ResponseWriter, r *http.Request) {
	u, tenantID, ok := rt.devDocsSession(r)
	if !ok {
		http.Error(w, "developer capability required", http.StatusForbidden)
		return
	}
	// Everything the profile bar needs, scoped to the session's CURRENT tenant
	// (a dev works in one org context) and resolved server-side (the role
	// hierarchy applied - the page never re-implements RBAC): the group MODE
	// (SINGLE = pick one, MULTIPLE = cumulate), the tenant's groups with their
	// roles, and every user with THEIR groups (so "test as X" uses X's rights,
	// and in SINGLE mode one picks which group).
	type groupRef struct {
		Name  string   `json:"name"`
		Roles []string `json:"roles"`
	}
	type userRef struct {
		Name   string     `json:"name"`
		Groups []groupRef `json:"groups"`
	}
	type specEntry struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Disabled bool   `json:"disabled,omitempty"`
	}
	out := struct {
		Username  string      `json:"username"`
		GroupMode string      `json:"groupMode"`
		Roles     []string    `json:"roles"`
		Groups    []groupRef  `json:"groups"`
		Users     []userRef   `json:"users"`
		Specs     []specEntry `json:"specs"`
	}{Username: u.Username, Roles: []string{}, Groups: []groupRef{}, Users: []userRef{}, Specs: []specEntry{}}

	if roles, err := rt.st.ListRoles(r.Context()); err == nil {
		for _, role := range roles {
			out.Roles = append(out.Roles, role.Name)
		}
	}
	// resolveGroup names a group and resolves its effective roles once.
	resolveGroup := func(g store.Group) groupRef {
		names, _ := rt.st.EffectiveRoleNames(r.Context(), []string{g.ID})
		if names == nil {
			names = []string{}
		}
		return groupRef{Name: g.Name, Roles: names}
	}
	if tenantID != "" {
		out.GroupMode = rt.st.EffectiveGroupMode(r.Context(), tenantID)
		if groups, err := rt.st.ListGroups(r.Context(), tenantID); err == nil {
			for _, g := range groups {
				out.Groups = append(out.Groups, resolveGroup(g))
			}
		}
	}
	// Users to impersonate, each with their groups in this tenant (so their
	// rights are known, and SINGLE mode offers the group submenu).
	if users, err := rt.st.ListUsers(r.Context()); err == nil {
		for _, usr := range users {
			ref := userRef{Name: usr.Username, Groups: []groupRef{}}
			if tenantID != "" {
				if mg, err := rt.st.MemberGroups(r.Context(), tenantID, usr.ID); err == nil {
					for _, g := range mg {
						ref.Groups = append(ref.Groups, resolveGroup(g))
					}
				}
			}
			out.Users = append(out.Users, ref)
		}
	}
	if routes, err := rt.st.ListRoutes(r.Context()); err == nil {
		for _, route := range routes {
			if route.API == nil || strings.TrimSpace(route.API.OpenapiURL) == "" {
				continue
			}
			out.Specs = append(out.Specs, specEntry{ID: route.ID, Name: route.Name, Disabled: !route.Enabled})
		}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(out)
}

// devDocsSpec serves one route's spec, servers rewritten RELATIVE to this
// very origin (the routes live here): Try it out is plain same-origin.
func (rt *Router) devDocsSpec(w http.ResponseWriter, r *http.Request) {
	if _, ok := rt.devDocsUser(r); !ok {
		http.Error(w, "developer capability required", http.StatusForbidden)
		return
	}
	route, err := rt.st.GetRoute(r.Context(), r.PathValue("id"))
	if err != nil || route.API == nil || strings.TrimSpace(route.API.OpenapiURL) == "" {
		http.NotFound(w, r)
		return
	}
	specURL := strings.TrimSpace(route.API.OpenapiURL)
	var body []byte
	if strings.HasPrefix(specURL, "http://") || strings.HasPrefix(specURL, "https://") {
		body, err = rt.fetchDevSpecDirect(r.Context(), specURL)
	} else {
		body, err = rt.fetchDevSpecThroughRoute(r, route, specURL)
	}
	if err != nil {
		http.Error(w, "spec fetch failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	if rewritten, err := openapi.Rewrite(body, routeMatchPrefix(route)); err == nil {
		body = rewritten
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(body)
}

func (rt *Router) fetchDevSpecDirect(ctx context.Context, specURL string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, specURL, nil)
	if err != nil {
		return nil, err
	}
	res, err := devSpecClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream answered %s", res.Status)
	}
	return io.ReadAll(io.LimitReader(res.Body, 8<<20))
}

// fetchDevSpecThroughRoute resolves a relative spec url through the route, in
// process: vault expansion, filters and the real upstream apply. The read is
// marked WithSpecRead - the dev was verified, the route's access gates CALLS,
// not reading the contract.
func (rt *Router) fetchDevSpecThroughRoute(r *http.Request, route store.Route, rel string) ([]byte, error) {
	path := routeMatchPrefix(route) + "/" + strings.TrimLeft(rel, "/")
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(WithSpecRead(ctx), http.MethodGet, "http://gateway.internal"+path, nil)
	if err != nil {
		return nil, err
	}
	if host := routeLiteralHost(route); host != "" {
		req.Host = host
	} else if h, _, splitErr := net.SplitHostPort(r.Host); splitErr == nil {
		req.Host = h
	} else {
		req.Host = r.Host
	}
	rec := &devSpecRecorder{header: http.Header{}, status: http.StatusOK}
	rt.ServeHTTP(rec, req)
	if rec.status != http.StatusOK {
		return nil, fmt.Errorf("the route answered %d for %s", rec.status, path)
	}
	return rec.buf.Bytes(), nil
}

// devSpecRecorder captures the in-process answer, bounded.
type devSpecRecorder struct {
	header http.Header
	status int
	buf    bytes.Buffer
}

func (r *devSpecRecorder) Header() http.Header { return r.header }
func (r *devSpecRecorder) WriteHeader(s int)   { r.status = s }
func (r *devSpecRecorder) Write(p []byte) (int, error) {
	if r.buf.Len()+len(p) > 8<<20 {
		p = p[:max(0, 8<<20-r.buf.Len())]
	}
	return r.buf.Write(p)
}

// routeMatchPrefix is the static prefix a client's path must carry to enter
// the route ("/demo/**" -> "/demo") - where its relative spec lives publicly.
func routeMatchPrefix(route store.Route) string {
	for _, p := range route.Predicates {
		if p.Type != "path" {
			continue
		}
		if patterns := devSpecStrings(p.Args["patterns"]); len(patterns) > 0 {
			return devStaticPrefix(patterns[0])
		}
		break
	}
	return ""
}

// routeLiteralHost returns the first wildcard-free host the route matches on,
// or "".
func routeLiteralHost(route store.Route) string {
	for _, p := range route.Predicates {
		if p.Type != "host" {
			continue
		}
		for _, h := range devSpecStrings(p.Args["hosts"]) {
			if h != "" && !strings.Contains(h, "*") {
				return h
			}
		}
	}
	return ""
}

// devStaticPrefix keeps the pattern's leading literal segments:
// "/demo/v1/**" -> "/demo/v1", "/{tenant}/api/**" -> "".
func devStaticPrefix(pattern string) string {
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

// devSpecStrings coerces a decoded JSON list into its string items.
func devSpecStrings(v any) []string {
	items, _ := v.([]any)
	out := make([]string, 0, len(items))
	for _, it := range items {
		if s, ok := it.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
