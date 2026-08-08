// Package gateway is Meerkat's data path: route matching and reverse
// proxying. Routes come from the store as declarative predicate/filter specs
// (internal/routing), compiled into an immutable snapshot swapped atomically
// on reload - the hot path takes a read lock and nothing else.
package gateway

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	filtering "github.com/softwarity/meerkat/internal/filters"
	"github.com/softwarity/meerkat/internal/routing"
	"github.com/softwarity/meerkat/internal/session"
	"github.com/softwarity/meerkat/internal/signing"
	"github.com/softwarity/meerkat/internal/store"
	"github.com/softwarity/meerkat/internal/vault"
)

// Router matches incoming requests against the compiled routes, first match
// wins in route order.
type Router struct {
	st *store.Store
	sm *session.Manager

	// lottery draws the per-request value consumed by weight predicates
	// (canary). Overridable in tests for determinism.
	lottery func() float64

	// AdminAddr is the control plane's listen address (main's -admin-addr):
	// the data plane answers CORS for exactly that sibling origin (the admin
	// console's swagger Try it out) and no other. Empty disables it.
	AdminAddr string
	// AdminSessions resolves admin-plane sessions, ONLY to authorize identity
	// simulation (simulate.go). Nil disables simulation entirely.
	AdminSessions *session.Manager
	// simTokenKey signs the ephemeral test tokens (simulate.go); per boot.
	simTokenKey []byte

	mu       sync.RWMutex
	routes   []compiledRoute
	needDraw bool // at least one route uses weight predicates

	// uiSims holds the running UI tests (uisim.go): a developer session
	// browsing ONE route as a simulated identity. Per process, TTL-bounded.
	uiSimMu sync.RWMutex
	uiSims  map[uiSimKey]uiSimEntry
	// signing holds the gateway's identity signing keys (signed-jwt). Loaded
	// at Reload; nil until a route uses signed-jwt or the admin generates them.
	signing *signing.Set
}

type compiledRoute struct {
	id      string
	name    string
	preds   routing.CompiledPredicates
	handler http.Handler
}

// New builds a Router over the store. sm may be nil when no route requires
// authentication (tests). Call Reload to load the routes.
func New(st *store.Store, sm *session.Manager) *Router {
	key := make([]byte, 32)
	if _, err := cryptorand.Read(key); err != nil {
		panic(err) // the OS entropy source is gone; nothing sensible remains
	}
	return &Router{st: st, sm: sm, lottery: rand.Float64, simTokenKey: key}
}

// Reload compiles the enabled routes from the store and swaps them in
// atomically. Safe to call while serving. A route that fails to compile
// aborts the reload with a precise error - the previous snapshot keeps
// serving.
func (rt *Router) Reload(ctx context.Context) error {
	stored, err := rt.st.ListRoutes(ctx)
	if err != nil {
		return err
	}
	// The application locale pool feeds every route (each may exclude some).
	// It may be EMPTY (no declared app locale) - then routes forward no locale
	// and the user button shows no language submenu.
	var appLangs []string
	_ = rt.st.GetSetting(ctx, store.SettingLanguages, &appLangs)
	// Vault values feed the $name expansion below. A vault that cannot be read
	// is not a reason to stop serving: routes without references still work,
	// and the ones with references will report their unresolved names.
	values, err := rt.st.VaultValues(ctx, vault.ScopeInfra)
	if err != nil {
		slog.Warn("vault unavailable, route references will not resolve", "err", err)
		values = map[string]string{}
	}
	compiled := make([]compiledRoute, 0, len(stored))
	var allPreds []*routing.CompiledPredicates
	needDraw := false
	for _, raw := range stored {
		if !raw.Enabled {
			continue
		}
		r, missing, err := ExpandRoute(raw, values)
		if err != nil {
			return fmt.Errorf("gateway: route %q: %w", raw.Name, err)
		}
		if len(missing) > 0 {
			// Left OUT rather than compiled. A route whose references do not
			// resolve cannot serve anything - its upstream is "https://" with no
			// host - and failing the whole reload over it would take every other
			// route down with it. That is the normal state of a gateway just
			// seeded from a file (CFG-03): the configuration is in place, the
			// vault is not filled yet, and it has to start anyway.
			slog.Warn("route left out: it references vault entries that hold nothing",
				"route", raw.Name, "names", missing)
			continue
		}
		cr, err := rt.compile(r, appLangs)
		if err != nil {
			return fmt.Errorf("gateway: route %q: %w", r.Name, err)
		}
		compiled = append(compiled, cr)
		allPreds = append(allPreds, &compiled[len(compiled)-1].preds)
		needDraw = needDraw || cr.preds.HasWeight()
	}
	if err := routing.ResolveWeights(allPreds); err != nil {
		return fmt.Errorf("gateway: %w", err)
	}
	// Identity signing keys (signed-jwt): generate them the first time a route
	// actually needs them; otherwise just load what already exists (so the JWKS
	// keeps serving), leaving fresh installs that never sign untouched.
	needSigning := false
	for _, r := range stored {
		if r.Enabled && r.Identity != nil && r.Identity.Mechanism == "signed-jwt" {
			needSigning = true
			break
		}
	}
	var sset *signing.Set
	if needSigning {
		if sset, err = rt.st.EnsureSigningSet(ctx); err != nil {
			return fmt.Errorf("gateway: identity signing keys: %w", err)
		}
	} else if loaded, ok, e := rt.st.GetSigningSet(ctx); e == nil && ok {
		sset = loaded
	}
	rt.mu.Lock()
	rt.routes = compiled
	rt.needDraw = needDraw
	rt.signing = sset
	rt.mu.Unlock()
	slog.Info("routes reloaded", "count", len(compiled))
	return nil
}

// adminOrigin reports whether origin is this gateway's own admin console: the
// same hostname the data-plane request came in on, at the control plane's
// port. A route pinned to another hostname by a host predicate falls outside
// this rule - its Try it out would need the application's own CORS.
func (rt *Router) adminOrigin(r *http.Request, origin string) bool {
	if rt.AdminAddr == "" {
		return false
	}
	_, adminPort, err := net.SplitHostPort(rt.AdminAddr)
	if err != nil || adminPort == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme == "" {
		return false
	}
	originPort := u.Port()
	if originPort == "" {
		if u.Scheme == "https" {
			originPort = "443"
		} else {
			originPort = "80"
		}
	}
	hostname := r.Host
	if h, _, err := net.SplitHostPort(r.Host); err == nil {
		hostname = h
	}
	return originPort == adminPort && strings.EqualFold(u.Hostname(), hostname)
}

// stripGatewayCookies removes Meerkat's own session cookies from an outgoing
// upstream request, keeping every other cookie the application may rely on.
func stripGatewayCookies(r *http.Request) {
	cookies := r.Cookies()
	r.Header.Del("Cookie")
	for _, c := range cookies {
		if c.Name == session.CookieName || c.Name == session.AdminCookieName {
			continue
		}
		r.AddCookie(c)
	}
}

// currentSigning returns the active signing set (nil when none). Read under the
// lock so a Reload swap is race-free.
func (rt *Router) currentSigning() *signing.Set {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.signing
}

// serveJWKS publishes the public halves of the signing keys. Empty (but valid)
// when no key exists yet, so a backend can always fetch and cache it.
func (rt *Router) serveJWKS(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	set := rt.currentSigning()
	if set == nil {
		_, _ = w.Write([]byte(`{"keys":[]}`))
		return
	}
	body, err := set.JWKS()
	if err != nil {
		http.Error(w, "jwks unavailable", http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(body)
}

// ExpandRoute resolves the $name references a route carries (VAULT-01) against
// values, returning the route the engine will actually run plus the names that
// did not resolve. The expansion is IN MEMORY only: the stored route keeps its
// references, so a secret never lands in the database or in an export.
//
// It walks the route's decoded JSON, so a reference works in any string field
// (upstream, filter arguments, header names...) without listing them one by one.
func ExpandRoute(r store.Route, values map[string]string) (store.Route, []string, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return r, nil, fmt.Errorf("gateway: route %q: %w", r.Name, err)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return r, nil, fmt.Errorf("gateway: route %q: %w", r.Name, err)
	}
	expanded, missing := vault.ExpandAny(doc, func(name string) (string, bool) {
		v, ok := values[name]
		return v, ok
	})
	out, err := json.Marshal(expanded)
	if err != nil {
		return r, missing, fmt.Errorf("gateway: route %q: %w", r.Name, err)
	}
	var resolved store.Route
	if err := json.Unmarshal(out, &resolved); err != nil {
		return r, missing, fmt.Errorf("gateway: route %q: %w", r.Name, err)
	}
	missing = restoreLiteralArgs(r, &resolved, missing)
	return resolved, missing, nil
}

// restoreLiteralArgs puts back the filter arguments that must not be expanded,
// and drops the "missing" names they invented on the way through.
//
// A Go template writes $i and $r for its own loop variables; the expansion read
// them as vault references and the route was refused for "unknown vault
// entries: i, r". The two syntaxes share the dollar and only one of them owns
// it here - the template's, since its body is taken verbatim.
func restoreLiteralArgs(original store.Route, resolved *store.Route, missing []string) []string {
	invented := map[string]bool{}
	for i, spec := range original.Filters {
		if i >= len(resolved.Filters) {
			break
		}
		for _, name := range routing.LiteralArgs(spec.Type) {
			raw, ok := spec.Args[name].(string)
			if !ok {
				continue
			}
			for _, ref := range vault.Refs(raw) {
				invented[ref] = true
			}
			resolved.Filters[i].Args[name] = raw
		}
	}
	if len(invented) == 0 {
		return missing
	}
	kept := missing[:0]
	for _, name := range missing {
		if !invented[name] {
			kept = append(kept, name)
		}
	}
	return kept
}

// JWKSPath is the well-known location where the gateway publishes the public
// halves of its identity signing keys, for upstreams verifying signed-jwt.
const JWKSPath = "/.well-known/jwks.json"

// ServeHTTP dispatches to the first route whose predicates all match; nothing
// matched is a plain 404. The TRAP (ROUTE-10) is not a special case: it is an
// ordinary catch-all route ("/**") the admin orders last.
func (rt *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// The JWKS is a gateway-internal endpoint: it wins over any route (a
	// catch-all trap must never swallow it).
	if req.Method == http.MethodGet && req.URL.Path == JWKSPath {
		rt.serveJWKS(w)
		return
	}
	// The admin console's swagger page (Try it out) calls the routes straight
	// on this plane, from the control plane's origin: answer CORS for THAT one
	// sibling origin - and no other, the applications behind the gateway keep
	// their own policies.
	if origin := req.Header.Get("Origin"); origin != "" && rt.adminOrigin(req, origin) {
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", origin)
		h.Set("Access-Control-Allow-Credentials", "true")
		h.Add("Vary", "Origin")
		if req.Method == http.MethodOptions && req.Header.Get("Access-Control-Request-Method") != "" {
			h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS")
			if reqHeaders := req.Header.Get("Access-Control-Request-Headers"); reqHeaders != "" {
				h.Set("Access-Control-Allow-Headers", reqHeaders)
			}
			h.Set("Access-Control-Max-Age", "600")
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	// Identity simulation (Try it out): validated headers replace the session
	// for this request; unauthorized simulation is an explicit 403, not a
	// silent fallback to the caller's real identity.
	req, simErr := rt.applySimulation(req)
	if simErr != nil {
		http.Error(w, simErr.Error(), http.StatusForbidden)
		return
	}
	rt.mu.RLock()
	routes, needDraw := rt.routes, rt.needDraw
	rt.mu.RUnlock()
	if needDraw {
		req = req.WithContext(routing.WithLottery(req.Context(), rt.lottery()))
	}
	for i := range routes {
		if routes[i].preds.Match(req) {
			// A running UI test (uisim.go) poses its identity on every
			// request the dev session sends through the tested route.
			req = rt.applyUISim(req, routes[i].id)
			routes[i].handler.ServeHTTP(w, req)
			return
		}
	}
	http.NotFound(w, req)
}

func (rt *Router) compile(r store.Route, appLangs []string) (compiledRoute, error) {
	preds, err := routing.CompilePredicates(r.Predicates)
	if err != nil {
		return compiledRoute{}, err
	}
	filters, err := routing.CompileFilters(r.Filters)
	if err != nil {
		return compiledRoute{}, err
	}

	// The language offer is the APPLICATION's; the route only adds transport
	// mechanisms. Accept-Language is ALWAYS forwarded with the resolved
	// locale promoted to the front - every proxied route, no opt-out.
	var localeCfg store.LocalesConfig
	if r.Locales != nil {
		localeCfg = *r.Locales
	}
	// The route may EXCLUDE application locales its UI does not support:
	// they leave the button's menu and the forwarding resolution.
	localeCodes := make([]string, 0, len(appLangs))
	for _, code := range appLangs {
		if !slices.ContainsFunc(localeCfg.Disabled, func(d string) bool { return strings.EqualFold(d, code) }) {
			localeCodes = append(localeCodes, code)
		}
	}
	if len(localeCodes) > 0 {
		filters.Request = append(filters.Request, localeForwardFilter(localeCodes, localeCfg))
	}

	// A UI route with the user button enabled injects the <meerkat-user-button>
	// web component into its HTML pages - same rewriting as inject-head.
	if frag := userButtonFragment(r, localeCodes); frag != "" {
		filters.Response = append(filters.Response, filtering.InjectAfterHead(frag))
	}
	// Page injections (UIF): the session's effective roles and the user's
	// identity are stamped SERVER-SIDE onto the served HTML - roles as a class
	// or attribute on the target tag (default body) or a meta, user fields
	// likewise. No client JS, no callback home (/meerkat/page.js stays served
	// for by-hand use). The gate is a cheap session check so anonymous requests
	// never buffer the response.
	if r.IsUI && r.UI != nil &&
		((r.UI.Roles != nil && r.UI.Roles.Enabled) || (r.UI.UserInfo != nil && r.UI.UserInfo.Enabled)) {
		route := r
		filters.Response = append(filters.Response,
			filtering.RewriteHTMLFunc(
				func(res *http.Response) bool { return rt.hasIdentity(res.Request) },
				func(res *http.Response, body []byte) []byte { return rt.pageStamp(route, res, body) },
			))
	}
	// Identity forwarding (both route types): the signed-in user rides
	// upstream headers; inbound values are purged first (spoofing guard).
	if r.Identity != nil && r.Identity.Mechanism != "" {
		filters.Request = append(filters.Request, rt.identityForwardFilter(*r.Identity, r.Name))
	}
	// A UI route's custom CSS rides a <style> tag ("</style" is refused at
	// validation, so the block cannot break out).
	if r.IsUI && r.UI != nil && r.UI.CustomCSS != "" {
		filters.Response = append(filters.Response,
			filtering.InjectAfterHead("<style>\n"+r.UI.CustomCSS+"\n</style>"))
	}
	// Same deal for the custom JS, on a <script> tag ("</script" refused).
	if r.IsUI && r.UI != nil && r.UI.CustomJS != "" {
		filters.Response = append(filters.Response,
			filtering.InjectAfterHead("<script>\n"+r.UI.CustomJS+"\n</script>"))
	}

	var handler http.Handler
	if filters.Terminal != nil {
		handler = filters.Terminal
		// Outgoing filters apply to what the route answers itself, exactly as
		// they do to a proxied response: a CORS or Cache-Control header on an
		// identity endpoint is the same need either way.
		if len(filters.Response) > 0 {
			handler = filterOwnResponse(handler, filters.Response)
		}
		// A terminal that answers FROM the caller gets one resolved and carried
		// in. Only that kind pays the read: redirect and maintenance answer the
		// same thing to everyone.
		if filters.TerminalNeedsIdentity {
			handler = rt.withIdentity(handler)
		}
	} else {
		handler, err = buildProxy(r, filters)
		if err != nil {
			return compiledRoute{}, err
		}
	}
	// Per-endpoint security (RBAC-07): when an API route poses operation
	// policies, wrap the handler with the endpoint guard INSIDE the route-level
	// auth, so a route-wide gate (if any) is applied first and the per-operation
	// rule refines it. The guard maps the inbound path back to the OpenAPI
	// coordinate by undoing the route's strip-prefix.
	// Route security (RBAC-06/07): the route's base Access gates the whole route.
	// When the API route also poses per-operation policies, the endpoint guard
	// refines that base per operation (mapping the inbound path back to the
	// OpenAPI coordinate by undoing the strip-prefix); operations with no
	// override fall back to the route's base Access.
	hasOverrides := r.API != nil && r.API.Security != nil && len(r.API.Security.Endpoints) > 0
	if hasOverrides {
		if rt.sm == nil {
			return compiledRoute{}, fmt.Errorf("route poses endpoint security but no session manager is configured")
		}
		guard, err := rt.endpointGuard(*r.API.Security, r.Access, r.IsUI, r.Filters, handler)
		if err != nil {
			return compiledRoute{}, err
		}
		handler = guard
	} else if !r.Access.Empty() {
		if rt.sm == nil {
			return compiledRoute{}, fmt.Errorf("route poses security but no session manager is configured")
		}
		handler = rt.accessGate(r.Access, r.IsUI, handler)
	}
	return compiledRoute{id: r.ID, name: r.Name, preds: preds, handler: handler}, nil
}

// Validate checks that a route would compile - same checks as Reload, minus
// the session-manager wiring. The admin API uses it to refuse invalid routes
// with the engine's precise error before anything is persisted.
func Validate(r store.Route) error {
	if _, err := routing.CompilePredicates(r.Predicates); err != nil {
		return err
	}
	cf, err := routing.CompileFilters(r.Filters)
	if err != nil {
		return err
	}
	if cf.Terminal == nil {
		target, err := url.Parse(r.Upstream)
		if err != nil {
			return fmt.Errorf("bad upstream %q: %w", r.Upstream, err)
		}
		if target.Scheme == "" || target.Host == "" {
			return fmt.Errorf("bad upstream %q: scheme and host required", r.Upstream)
		}
		if target.Scheme != "http" && target.Scheme != "https" {
			return fmt.Errorf("bad upstream %q: scheme %q is not supported: only http and https", r.Upstream, target.Scheme)
		}
	}
	return validateRouteType(r)
}

// validateRouteType guards the route options: forwarding configs for every
// route, plus the UI extras when the UI toggle is on (ROUTE-02).
func validateRouteType(r store.Route) error {
	for _, role := range r.Access.Roles {
		if !schemeTokenOK.MatchString(role) {
			return fmt.Errorf("route access role %q is not allowed: letters, digits, - and _ only", role)
		}
	}
	// Endpoint-level security (RBAC-07): paths must compile, methods and access
	// modes be known. Validate also upper-cases the methods in place.
	if r.API != nil {
		if err := r.API.Security.Validate(); err != nil {
			return err
		}
	}
	// Identity forwarding is valid for BOTH types (an API service wants the
	// caller too).
	if id := r.Identity; id != nil && id.Mechanism != "" {
		switch id.Mechanism {
		case "headers", "jwt":
		case "signed-jwt":
			if id.Algorithm != "" && !signing.Valid(id.Algorithm) {
				return fmt.Errorf("identity signature algorithm %q is not allowed: allowed algorithms are %s",
					id.Algorithm, strings.Join(signing.Algorithms, ", "))
			}
		default:
			return fmt.Errorf("identity mechanism %q is not allowed: allowed mechanisms are headers, jwt, signed-jwt", id.Mechanism)
		}
		seen := make(map[string]bool, len(id.Attributes))
		for _, a := range id.Attributes {
			if !slices.Contains(store.IdentityFields, a.Field) {
				return fmt.Errorf("identity attribute %q is not allowed: allowed attributes are %s",
					a.Field, strings.Join(store.IdentityFields, ", "))
			}
			if seen[a.Field] {
				return fmt.Errorf("identity attribute %q is set twice", a.Field)
			}
			seen[a.Field] = true
			if a.As != "" {
				if id.Mechanism == "headers" && !headerNameOK.MatchString(a.As) {
					return fmt.Errorf("identity header %q for %s is not allowed: letters, digits and - only", a.As, a.Field)
				}
				if (id.Mechanism == "jwt" || id.Mechanism == "signed-jwt") && !claimNameOK.MatchString(a.As) {
					return fmt.Errorf("identity claim %q for %s is not allowed: letters, digits, and _ - . only", a.As, a.Field)
				}
			}
		}
		if id.TTL != "" {
			if _, err := store.ParseISODuration(id.TTL); err != nil {
				return fmt.Errorf("identity token ttl %q is not a valid ISO-8601 duration: %w", id.TTL, err)
			}
		}
	}
	// Locale MECHANISMS are valid for both types; only the path one demands a
	// UI route (an API takes the locale as a header or query parameter).
	// Accept-Language always goes, it is not an option here.
	if lc := r.Locales; lc != nil {
		for _, m := range lc.Mechanisms {
			switch m {
			case "custom", "query", "path":
			default:
				return fmt.Errorf("locales mechanism %q is not allowed: allowed mechanisms are custom, query, path (Accept-Language always goes)", m)
			}
		}
		if slices.Contains(lc.Mechanisms, "path") && !r.IsUI {
			return fmt.Errorf("locales mechanism \"path\" is only allowed on UI routes: an API takes the locale as a header or query parameter")
		}
		if slices.Contains(lc.Mechanisms, "custom") && !headerNameOK.MatchString(lc.Header) {
			return fmt.Errorf("locales custom header %q is not allowed: letters, digits and - only", lc.Header)
		}
		if lc.Param != "" && !headerNameOK.MatchString(lc.Param) {
			return fmt.Errorf("locales query parameter %q is not allowed: letters, digits and - only", lc.Param)
		}
		for _, d := range lc.Disabled {
			if !headerNameOK.MatchString(d) {
				return fmt.Errorf("disabled locale %q is not allowed: letters, digits and - only", d)
			}
		}
	}
	if r.UI == nil {
		return nil
	}
	if s := r.UI.Scheme; s != nil {
		switch s.Mechanism {
		case "", "attribute", "class":
		default:
			return fmt.Errorf("scheme mechanism %q is not allowed: allowed mechanisms are \"\" (color-scheme only), attribute, class", s.Mechanism)
		}
		if s.Mechanism == "attribute" && !schemeTokenOK.MatchString(s.Attribute) {
			return fmt.Errorf("scheme attribute %q is not allowed: letters, digits, - and _ only", s.Attribute)
		}
		for _, v := range []string{s.Light, s.Dark} {
			if v != "" && !schemeTokenOK.MatchString(v) {
				return fmt.Errorf("scheme value %q is not allowed: letters, digits, - and _ only", v)
			}
		}
	}
	btn := r.UI.UserButton
	if btn.Position != "" && !slices.Contains(store.UserButtonPositions, btn.Position) {
		return fmt.Errorf("user button position %q is not allowed: allowed positions are %s",
			btn.Position, strings.Join(store.UserButtonPositions, ", "))
	}
	if btn.Height != 0 && (btn.Height < 16 || btn.Height > 96) {
		return fmt.Errorf("user button height %d is out of range: allowed heights are 16-96 px", btn.Height)
	}
	if btn.PadX < 0 || btn.PadX > 500 || btn.PadY < 0 || btn.PadY > 500 {
		return fmt.Errorf("user button padding is out of range: allowed paddings are 0-500 px")
	}
	switch btn.Shape {
	case "", "round", "square":
	default:
		return fmt.Errorf("user button shape %q is not allowed: allowed shapes are round, square", btn.Shape)
	}
	switch btn.Name {
	case "", "before", "after":
	default:
		return fmt.Errorf("user button name %q is not allowed: allowed values are \"\" (hidden), before, after", btn.Name)
	}
	if ro := r.UI.Roles; ro != nil {
		switch ro.Mechanism {
		case "", "class", "attribute", "meta":
		default:
			return fmt.Errorf("roles mechanism %q is not allowed: allowed mechanisms are class, attribute, meta", ro.Mechanism)
		}
		if ro.Tag != "" && !tagNameOK.MatchString(ro.Tag) {
			return fmt.Errorf("roles tag %q is not allowed: a tag name starts with a letter, then letters, digits and -", ro.Tag)
		}
		if ro.Attribute != "" && !schemeTokenOK.MatchString(ro.Attribute) {
			return fmt.Errorf("roles attribute %q is not allowed: letters, digits, - and _ only", ro.Attribute)
		}
	}
	if ui := r.UI.UserInfo; ui != nil {
		switch ui.Mechanism {
		case "", "attribute", "meta":
		default:
			return fmt.Errorf("user-info mechanism %q is not allowed: allowed mechanisms are attribute, meta", ui.Mechanism)
		}
		if ui.Tag != "" && !tagNameOK.MatchString(ui.Tag) {
			return fmt.Errorf("user-info tag %q is not allowed: a tag name starts with a letter, then letters, digits and -", ui.Tag)
		}
		for field, name := range ui.Fields {
			if !slices.Contains(store.PageUserFields, field) {
				return fmt.Errorf("user-info field %q is not allowed: allowed fields are %s",
					field, strings.Join(store.PageUserFields, ", "))
			}
			if name != "" && !schemeTokenOK.MatchString(name) {
				return fmt.Errorf("user-info name %q for %s is not allowed: letters, digits, - and _ only", name, field)
			}
		}
	}
	// The custom CSS travels verbatim inside a <style> tag: a closing tag
	// would break out of it, and 64 KiB is plenty for page tweaks.
	if css := r.UI.CustomCSS; css != "" {
		if strings.Contains(strings.ToLower(css), "</style") {
			return fmt.Errorf("custom css must not contain \"</style\"")
		}
		if len(css) > 64<<10 {
			return fmt.Errorf("custom css is too large (%d bytes): the limit is 64 KiB", len(css))
		}
	}
	// The custom JS travels verbatim inside a <script> tag: same escape rule.
	if js := r.UI.CustomJS; js != "" {
		if strings.Contains(strings.ToLower(js), "</script") {
			return fmt.Errorf("custom js must not contain \"</script\"")
		}
		if len(js) > 64<<10 {
			return fmt.Errorf("custom js is too large (%d bytes): the limit is 64 KiB", len(js))
		}
	}
	return nil
}

// schemeTokenOK bounds the attribute/class/value tokens that travel into the
// injected HTML - validated here, so the fragment never carries free text.
var schemeTokenOK = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// headerNameOK bounds the upstream header names a route may configure.
var headerNameOK = regexp.MustCompile(`^[A-Za-z0-9-]+$`)

// claimNameOK bounds the JWT claim names a route may map an attribute onto.
var claimNameOK = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// tagNameOK bounds the page tag a stamp may target (custom elements included).
var tagNameOK = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*$`)

// identityData is the per-request resolution of the caller: what the page
// stamp writes into the HTML and what identity forwarding sends upstream.
// Every token is validated (validateRouteType) or HTML-escaped, so no free
// text ever reaches the page.
type identityData struct {
	UserID   string
	Username string
	Fullname string
	Email    string
	Timezone string
	TenantID string
	Tenant   string
	Roles    []string
}

// sessionIdentity resolves the caller for per-request injections and
// forwarding; ok is false without a completed session. A simulated identity
// (simulate.go) replaces the session wholesale.
func (rt *Router) sessionIdentity(req *http.Request) (identityData, bool) {
	if d, ok := simulatedIdentity(req.Context()); ok {
		return d, true
	}
	sess, err := rt.sm.Resolve(req.Context(), req)
	if err != nil || sess.Pending != "" {
		return identityData{}, false
	}
	u, err := rt.st.GetUserByID(req.Context(), sess.UserID)
	if err != nil || !u.Enabled {
		return identityData{}, false
	}
	d := identityData{UserID: u.ID, Username: u.Username, Fullname: u.Fullname,
		Email: u.Email, Timezone: u.Timezone}
	if sess.TenantID != "" {
		d.TenantID = sess.TenantID
		if t, err := rt.st.GetTenant(req.Context(), sess.TenantID); err == nil {
			d.Tenant = t.Name
		}
		// SessionRoleNames applies the group mode (RBAC-03): cumulative =
		// every group, exclusive = the session's chosen group only.
		if names, err := rt.st.SessionRoleNames(req.Context(), u.ID, sess.TenantID, sess.GroupID); err == nil {
			for _, n := range names {
				if schemeTokenOK.MatchString(n) {
					d.Roles = append(d.Roles, n)
				}
			}
		}
	}
	return d, true
}

// hasIdentity is the cheap gate for the page stamp: a completed session exists.
// Resolve is cached, so anonymous requests are turned away before the response
// body is ever buffered.
func (rt *Router) hasIdentity(req *http.Request) bool {
	if _, ok := simulatedIdentity(req.Context()); ok {
		return true
	}
	sess, err := rt.sm.Resolve(req.Context(), req)
	return err == nil && sess.Pending == ""
}

// pageStamp applies a UI route's roles/user-info to the served HTML entirely
// SERVER-SIDE: roles as a class or attribute on the target tag (default body)
// or a meta; each selected user field as an attribute or a meta. The body is
// returned unchanged when there is no completed session. Everything embedded
// is validated config or HTML-escaped identity, so nothing can break out.
func (rt *Router) pageStamp(r store.Route, res *http.Response, body []byte) []byte {
	ui := r.UI
	d, ok := rt.sessionIdentity(res.Request)
	if !ok {
		return body
	}
	var metas []byte
	if ui.Roles != nil && ui.Roles.Enabled {
		tag := orDefault(ui.Roles.Tag, "body")
		joined := strings.Join(d.Roles, " ")
		switch orDefault(ui.Roles.Mechanism, "class") {
		case "class":
			body = stampClass(body, tag, d.Roles)
		case "attribute":
			body = stampAttr(body, tag, orDefault(ui.Roles.Attribute, "data-roles"), joined)
		case "meta":
			metas = append(metas, metaTag(orDefault(ui.Roles.Attribute, "meerkat-roles"), joined)...)
		}
	}
	if ui.UserInfo != nil && ui.UserInfo.Enabled {
		tag := orDefault(ui.UserInfo.Tag, "body")
		asMeta := orDefault(ui.UserInfo.Mechanism, "attribute") == "meta"
		for field, name := range ui.UserInfo.Fields {
			value := userFieldValue(d, field)
			if value == "" {
				continue
			}
			attr := orDefault(name, field)
			if asMeta {
				metas = append(metas, metaTag(attr, value)...)
			} else {
				body = stampAttr(body, tag, attr, value)
			}
		}
	}
	if len(metas) > 0 {
		body = insertAfterHead(body, metas)
	}
	return body
}

// userFieldValue maps a PageUserFields key to its resolved value.
func userFieldValue(d identityData, field string) string {
	switch field {
	case "username":
		return d.Username
	case "userid":
		return d.UserID
	case "fullname":
		return d.Fullname
	case "email":
		return d.Email
	case "tenant":
		return d.Tenant
	case "tenantid":
		return d.TenantID
	case "timezone":
		return d.Timezone
	}
	return ""
}

// openTagRe matches the FIRST opening <tag ...> in the document (case-insensitive,
// attributes may span lines). Group 1 = "<tag", group 2 = the attributes (with
// their leading space) or empty; the closing ">" follows. A trailing word
// boundary keeps <body> from matching <bodyfoo>.
func openTagRe(tag string) *regexp.Regexp {
	return regexp.MustCompile(`(?i)(<` + regexp.QuoteMeta(tag) + `)((?:\s[^>]*)?)>`)
}

// stampClass merges roles into the target tag's class attribute (server-side
// equivalent of classList.add): appends to an existing class="...", or adds one.
func stampClass(body []byte, tag string, roles []string) []byte {
	if len(roles) == 0 {
		return body
	}
	m := openTagRe(tag).FindSubmatchIndex(body)
	if m == nil {
		return body
	}
	attrs := string(body[m[4]:m[5]])
	return spliceOpenTag(body, m, addClassTokens(attrs, roles))
}

// stampAttr sets name="value" on the target tag's opening tag (replacing an
// existing one, or appending). value is attribute-escaped.
func stampAttr(body []byte, tag, name, value string) []byte {
	m := openTagRe(tag).FindSubmatchIndex(body)
	if m == nil {
		return body
	}
	attrs := string(body[m[4]:m[5]])
	return spliceOpenTag(body, m, setAttrToken(attrs, name, value))
}

// spliceOpenTag rebuilds the matched opening tag with newAttrs in place of the
// original attribute list. m is openTagRe's submatch index set.
func spliceOpenTag(body []byte, m []int, newAttrs string) []byte {
	out := make([]byte, 0, len(body)+len(newAttrs))
	out = append(out, body[:m[3]]...) // up to and including "<tag"
	out = append(out, newAttrs...)
	out = append(out, '>')
	out = append(out, body[m[1]:]...) // after the original ">"
	return out
}

var classAttrRe = regexp.MustCompile(`(?i)(\sclass\s*=\s*")([^"]*)(")`)

// addClassTokens appends roles to a double-quoted class="..." inside attrs
// (skipping tokens already present), or adds a class attribute when none.
func addClassTokens(attrs string, roles []string) string {
	if classAttrRe.MatchString(attrs) {
		return classAttrRe.ReplaceAllStringFunc(attrs, func(s string) string {
			g := classAttrRe.FindStringSubmatch(s)
			existing := strings.Fields(g[2])
			for _, role := range roles {
				if !slices.Contains(existing, role) {
					existing = append(existing, role)
				}
			}
			return g[1] + strings.Join(existing, " ") + g[3]
		})
	}
	return attrs + ` class="` + html.EscapeString(strings.Join(roles, " ")) + `"`
}

// setAttrToken replaces a double-quoted name="..." inside attrs, or appends one.
func setAttrToken(attrs, name, value string) string {
	esc := html.EscapeString(value)
	re := regexp.MustCompile(`(?i)(\s` + regexp.QuoteMeta(name) + `\s*=\s*")[^"]*(")`)
	if re.MatchString(attrs) {
		return re.ReplaceAllStringFunc(attrs, func(s string) string {
			g := re.FindStringSubmatch(s)
			return g[1] + esc + g[2]
		})
	}
	return attrs + " " + name + `="` + esc + `"`
}

// metaTag builds a <meta name="..." content="..."> (both attribute-escaped).
func metaTag(name, content string) []byte {
	return []byte(`<meta name="` + html.EscapeString(name) + `" content="` + html.EscapeString(content) + `">`)
}

var headOpenRe = regexp.MustCompile(`(?i)<head[^>]*>`)

// insertAfterHead inserts frag right after the opening <head>, or at the very
// start when there is no <head>.
func insertAfterHead(body, frag []byte) []byte {
	loc := headOpenRe.FindIndex(body)
	out := make([]byte, 0, len(body)+len(frag))
	if loc == nil {
		out = append(out, frag...)
		return append(out, body...)
	}
	out = append(out, body[:loc[1]]...)
	out = append(out, frag...)
	return append(out, body[loc[1]:]...)
}

// localeForwardFilter carries the resolved locale to the upstream:
// Accept-Language ALWAYS goes, rewritten with the choice first; the route's
// extra mechanisms ride on top - a custom header, a query parameter (an
// API's natural shape), a path segment (UI only, Angular-style /fr/ builds).
func localeForwardFilter(codes []string, lc store.LocalesConfig) routing.RequestFilter {
	return func(pr *httputil.ProxyRequest) {
		loc := resolveLocale(pr.In, codes)
		pr.Out.Header.Set("Accept-Language", promoteLocale(pr.In.Header.Get("Accept-Language"), loc))
		for _, m := range lc.Mechanisms {
			switch m {
			case "path":
				pr.Out.URL.Path = "/" + loc + pr.Out.URL.Path
				pr.Out.URL.RawPath = ""
			case "query":
				q := pr.Out.URL.Query()
				q.Set(orDefault(lc.Param, "lg"), loc)
				pr.Out.URL.RawQuery = q.Encode()
			case "custom":
				pr.Out.Header.Set(lc.Header, loc)
			}
		}
	}
}

// promoteLocale rewrites an Accept-Language value with the resolved locale
// FIRST (implicit weight 1), keeping the caller's other preferences behind
// (their own q-values intact); a duplicate of the choice is dropped.
func promoteLocale(orig, loc string) string {
	out := []string{loc}
	for _, part := range strings.Split(orig, ",") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		tag, _, _ := strings.Cut(p, ";")
		if strings.EqualFold(strings.TrimSpace(tag), loc) {
			continue
		}
		out = append(out, p)
	}
	return strings.Join(out, ", ")
}

// resolveLocale picks the request's locale among the route's codes: the
// MEERKAT_LANG cookie first, then the best Accept-Language match (exact,
// then same base language), then the first code.
func resolveLocale(r *http.Request, codes []string) string {
	pick := func(tag string) string {
		for _, code := range codes {
			if strings.EqualFold(code, tag) {
				return code
			}
		}
		base, _, _ := strings.Cut(tag, "-")
		for _, code := range codes {
			cb, _, _ := strings.Cut(code, "-")
			if strings.EqualFold(cb, base) {
				return code
			}
		}
		return ""
	}
	if c, err := r.Cookie("MEERKAT_LANG"); err == nil && c.Value != "" {
		if code := pick(c.Value); code != "" {
			return code
		}
	}
	for _, part := range strings.Split(r.Header.Get("Accept-Language"), ",") {
		tag, _, _ := strings.Cut(strings.TrimSpace(part), ";")
		if tag == "" || tag == "*" {
			continue
		}
		if code := pick(tag); code != "" {
			return code
		}
	}
	return codes[0]
}

// accessGate wraps next with a unified access rule (RBAC-06/07): an empty rule
// passes through, everything else requires a valid session (401/redirect via
// requireSession) and a caller satisfying the rule.
//
// Whatever the level, the upstream still applies its own rules afterwards -
// Meerkat gates IN ADDITION to the service, never instead of it.
//
// isUI decides what a REFUSAL looks like, and that is most of the point of the
// tenant levels: on an application, being refused for lack of an organisation
// is not an error, it is a step missing. A person whose account is confirmed
// but not yet granted anything is sent to the waiting room that explains it; a
// member of several organisations who is active in the wrong one is sent to
// choose. An API answers 403 and names what is missing - there is nobody to
// read a page.
func (rt *Router) accessGate(a store.Access, isUI bool, next http.Handler) http.Handler {
	if a.Empty() {
		return next
	}
	return requireSession(rt.sm, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// An internal spec read (admin API docs) was authorized on the control
		// plane; the route's own rules gate CALLS, not reading its contract.
		if isSpecRead(req.Context()) {
			next.ServeHTTP(w, req)
			return
		}
		d, ok := rt.sessionIdentity(req)
		caller := rt.caller(req, d, ok)
		if ok && a.Grants(caller) {
			next.ServeHTTP(w, req)
			return
		}
		// A refused SIMULATED identity during a UI test must not lock the
		// developer out (a bare 403 has no developer bar): explain and offer
		// the exit instead.
		if m, simOn := simulationMeta(req.Context()); simOn && m.Via == "ui-test" {
			uiSimRefusalPage(w, req)
			return
		}
		if isUI && ok {
			if offer := a.Switchable(caller); len(offer) > 0 {
				http.Redirect(w, req, "/select-tenant?next="+url.QueryEscape(req.URL.RequestURI()), http.StatusSeeOther)
				return
			}
			// No organisation at all and none to switch to: the waiting room
			// says who to ask, which a 403 does not.
			if len(caller.Memberships) == 0 && needsTenant(a) {
				http.Redirect(w, req, "/account-pending", http.StatusSeeOther)
				return
			}
		}
		http.Error(w, refusalReason(a, caller), http.StatusForbidden)
	}))
}

// needsTenant reports whether the rule asks for an organisation at all.
func needsTenant(a store.Access) bool {
	return a.Level == store.AccessTenant || a.Level == store.AccessTenants || len(a.Roles) > 0
}

// refusalReason names what is missing rather than saying "forbidden": the
// caller can act on "you have no organisation selected", not on a bare 403.
func refusalReason(a store.Access, c store.Caller) string {
	switch {
	case needsTenant(a) && c.TenantID == "" && len(c.Memberships) == 0:
		return "forbidden: your account belongs to no organisation yet"
	case needsTenant(a) && c.TenantID == "":
		return "forbidden: no organisation is active on this session - choose one first"
	case a.Level == store.AccessTenants && !slices.Contains(a.Tenants, c.TenantID):
		return "forbidden: this endpoint is reserved to another organisation"
	case len(a.Roles) > 0:
		return "forbidden: this endpoint requires one of the roles " + strings.Join(a.Roles, ", ")
	}
	return "forbidden: you may not call this endpoint"
}

// caller assembles what a rule is evaluated against. Memberships are read only
// when the rule could care (a switch offer), never on the hot path of a public
// or plain-authenticated route.
func (rt *Router) caller(req *http.Request, d identityData, ok bool) store.Caller {
	if !ok {
		return store.Caller{}
	}
	c := store.Caller{Authenticated: true, Username: d.Username, TenantID: d.TenantID, Roles: d.Roles}
	if ms, err := rt.st.ListUserTenants(req.Context(), d.UserID); err == nil {
		for _, m := range ms {
			if m.Enabled {
				c.Memberships = append(c.Memberships, m.TenantID)
			}
		}
	}
	return c
}

// endpointGuard enforces per-operation security (RBAC-07) inside an API route.
// Every override path is precompiled once at reload; per request the guard
// undoes the route's strip-prefix to recover the OpenAPI coordinate, then
// applies the first matching override, or the route-wide default when none
// matches. Operations with neither fall through to the route's own auth.
func (rt *Router) endpointGuard(sec store.EndpointSecurity, routeAccess store.Access, isUI bool, filters []routing.Spec, next http.Handler) (http.Handler, error) {
	type compiledEP struct {
		method string
		path   routing.CompiledPath
		gate   http.Handler
	}
	eps := make([]compiledEP, 0, len(sec.Endpoints))
	for i, e := range sec.Endpoints {
		cp, err := routing.CompilePath(e.Path)
		if err != nil {
			return nil, fmt.Errorf("endpoint %d (%s %s): %w", i, e.Method, e.Path, err)
		}
		eps = append(eps, compiledEP{method: strings.ToUpper(e.Method), path: cp, gate: rt.accessGate(e.Access, isUI, next)})
	}
	strip := stripPrefixCount(filters)
	// The route's base Access is the default for any operation with no override
	// (an empty Access passes through, delegating to the upstream).
	routeGate := rt.accessGate(routeAccess, isUI, next)

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		specPath := routing.StripSegments(req.URL.Path, strip)
		for i := range eps {
			if (eps[i].method == "*" || eps[i].method == req.Method) && eps[i].path.Match(specPath) {
				eps[i].gate.ServeHTTP(w, req)
				return
			}
		}
		routeGate.ServeHTTP(w, req)
	}), nil
}

// stripPrefixCount sums the leading segments the route's strip-prefix filters
// remove, so the endpoint guard can map an inbound path back to the OpenAPI
// coordinate its operation paths live in. A strip-prefix with no explicit
// "parts" uses the schema default of 1.
func stripPrefixCount(filters []routing.Spec) int {
	n := 0
	for _, f := range filters {
		if f.Type != "strip-prefix" {
			continue
		}
		parts := 1
		if v, ok := f.Args["parts"]; ok {
			switch p := v.(type) {
			case float64:
				parts = int(p)
			case int:
				parts = p
			case int64:
				parts = int(p)
			}
		}
		n += parts
	}
	return n
}

// gatewayIssuer is the "iss" claim of identity tokens: this gateway is the
// authority the upstream trusts. A configurable issuer arrives with the signing
// identity (signed-jwt, Lot 2).
const gatewayIssuer = "meerkat"

// identityForwardFilter sends the signed-in caller upstream, per the mechanism.
// Only the SELECTED attributes travel, each optionally renamed. Inbound values
// are purged first so a client can never spoof them: the header transport drops
// every catalogue header (and each mapped target); the jwt transport drops the
// Authorization it is about to write.
func (rt *Router) identityForwardFilter(cfg store.IdentityForward, routeName string) routing.RequestFilter {
	if cfg.Mechanism == "jwt" || cfg.Mechanism == "signed-jwt" {
		signed := cfg.Mechanism == "signed-jwt"
		alg := cfg.Algorithm
		if alg == "" {
			alg = signing.ES256
		}
		return func(pr *httputil.ProxyRequest) {
			pr.Out.Header.Del("Authorization")
			d, ok := rt.sessionIdentity(pr.In)
			if !ok {
				return
			}
			claims := identityClaims(cfg, routeName, d)
			var tok string
			var err error
			if signed {
				set := rt.currentSigning()
				if set == nil {
					return
				}
				tok, err = set.SignJWT(alg, claims)
			} else {
				tok, err = mintUnsignedJWT(claims)
			}
			if err != nil {
				return
			}
			pr.Out.Header.Set("Authorization", "Bearer "+tok)
		}
	}
	return func(pr *httputil.ProxyRequest) {
		for _, f := range store.IdentityFields {
			pr.Out.Header.Del(f)
		}
		for _, a := range cfg.Attributes {
			if a.As != "" {
				pr.Out.Header.Del(a.As)
			}
		}
		d, ok := rt.sessionIdentity(pr.In)
		if !ok {
			return
		}
		for _, h := range identityHeaderPairs(cfg, d) {
			pr.Out.Header.Set(h.Name, h.Value)
		}
	}
}

// IdentityHeader is one header the "headers" mechanism emits.
type IdentityHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// identityHeaderPairs renders the headers cfg emits for the caller d, in
// attribute order: each selected fact under its mapped name, roles as a JSON
// array or a comma-separated string. Shared by the forwarding filter and the
// admin preview, so what the console shows is what the upstream receives.
func identityHeaderPairs(cfg store.IdentityForward, d identityData) []IdentityHeader {
	out := make([]IdentityHeader, 0, len(cfg.Attributes))
	for _, a := range cfg.Attributes {
		name := a.As
		if name == "" {
			name = a.Field
		}
		if a.Field == "roles" {
			if len(d.Roles) == 0 {
				continue
			}
			if a.AsJSON {
				b, err := json.Marshal(d.Roles)
				if err != nil {
					continue
				}
				out = append(out, IdentityHeader{Name: name, Value: string(b)})
			} else {
				out = append(out, IdentityHeader{Name: name, Value: strings.Join(d.Roles, ",")})
			}
			continue
		}
		if v := userFieldValue(d, a.Field); v != "" {
			out = append(out, IdentityHeader{Name: name, Value: v})
		}
	}
	return out
}

// sampleIdentity is the FICTIONAL caller the identity preview describes. It is
// fixed here on purpose: the preview mints a real (and, for signed-jwt, really
// signed) token, so letting a caller choose the claim values would let a
// infra admin forge a token for anyone the upstream trusts.
var sampleIdentity = identityData{
	UserID: "usr_123", Username: "jdoe", Fullname: "Jane Doe",
	Email: "jdoe@example.com", Timezone: "Europe/Paris",
	TenantID: "tnt_123", Tenant: "acme", Roles: []string{"role-a", "role-b"},
}

// PreviewHeaders renders the headers cfg would send for the sample caller.
func PreviewHeaders(cfg store.IdentityForward) []IdentityHeader {
	return identityHeaderPairs(cfg, sampleIdentity)
}

// PreviewClaims builds the JWT payload cfg would send for the sample caller.
func PreviewClaims(cfg store.IdentityForward, routeName string) map[string]any {
	return identityClaims(cfg, routeName, sampleIdentity)
}

// MintUnsignedJWT encodes an unsigned (alg:none) token, the "jwt" mechanism's
// wire form. Exported for the admin preview.
func MintUnsignedJWT(claims map[string]any) (string, error) {
	return mintUnsignedJWT(claims)
}

// identityClaims builds the JWT payload: the registered claims (iss/sub/aud/
// iat/exp) plus one custom claim per selected attribute, under its mapped name.
func identityClaims(cfg store.IdentityForward, routeName string, d identityData) map[string]any {
	now := time.Now()
	ttl := 2 * time.Minute
	if cfg.TTL != "" {
		if parsed, err := store.ParseISODuration(cfg.TTL); err == nil {
			ttl = parsed
		}
	}
	claims := map[string]any{
		"iss": gatewayIssuer,
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
	}
	if routeName != "" {
		claims["aud"] = routeName
	}
	if d.UserID != "" {
		claims["sub"] = d.UserID
	}
	for _, a := range cfg.Attributes {
		name := a.As
		if name == "" {
			name = a.Field
		}
		if a.Field == "roles" {
			if a.AsJSON {
				claims[name] = d.Roles
			} else {
				claims[name] = strings.Join(d.Roles, ",")
			}
			continue
		}
		if v := userFieldValue(d, a.Field); v != "" {
			claims[name] = v
		}
	}
	return claims
}

// mintUnsignedJWT encodes an unsigned (alg:none) JWT: header.payload with an
// empty signature. It carries structure, not trust - the verifiable variant is
// signed-jwt (Lot 2).
func mintUnsignedJWT(claims map[string]any) (string, error) {
	seg := func(v any) (string, error) {
		b, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		return base64.RawURLEncoding.EncodeToString(b), nil
	}
	header, err := seg(map[string]string{"alg": "none", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := seg(claims)
	if err != nil {
		return "", err
	}
	return header + "." + payload + ".", nil
}

func orDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// userButtonFragment builds the HTML injected after <head> for a UI route with
// the user button on. The custom element lands at the top of <body> (the HTML
// parser closes <head> on the first non-metadata tag) and positions itself
// fixed. Values are validated (validateRouteType) - no free text reaches HTML.
func userButtonFragment(r store.Route, localeCodes []string) string {
	if !r.IsUI || r.UI == nil || !r.UI.UserButton.Enabled {
		return ""
	}
	btn := r.UI.UserButton
	height := btn.Height
	if height == 0 {
		height = 24
	}
	position := btn.Position
	if position == "" {
		position = "top-right"
	}
	// The route id feeds the developer bar (uisim.go): the UI test is scoped
	// to THIS route. Server-generated id, HTML-safe.
	attrs := fmt.Sprintf(` height="%d" position="%s" route="%s"`, height, position, htmlEscape(r.ID))
	if btn.PadX != 0 {
		attrs += fmt.Sprintf(` pad-x="%d"`, btn.PadX)
	}
	if btn.PadY != 0 {
		attrs += fmt.Sprintf(` pad-y="%d"`, btn.PadY)
	}
	if btn.Shape == "square" {
		attrs += ` shape="square"`
	}
	if btn.Name != "" {
		attrs += fmt.Sprintf(` name="%s"`, btn.Name)
	}
	if s := r.UI.Scheme; s != nil && s.Select {
		attrs += ` scheme="select"`
		if s.Mechanism != "" {
			attrs += fmt.Sprintf(` scheme-mechanism="%s" scheme-light="%s" scheme-dark="%s"`,
				s.Mechanism, s.Light, s.Dark)
			if s.Mechanism == "attribute" {
				attrs += fmt.Sprintf(` scheme-attribute="%s"`, s.Attribute)
			}
		}
	}
	// The ROUTE's locale offer feeds the button's language submenu (codes are
	// validated BCP 47, HTML-safe; the component renders the endonyms).
	if len(localeCodes) > 0 {
		attrs += fmt.Sprintf(` languages="%s"`, strings.Join(localeCodes, ","))
	}
	return `<script defer src="/meerkat/user-button.js"></script>` +
		`<meerkat-user-button` + attrs + `></meerkat-user-button>`
}

// upstreamTransport bounds how long an upstream may take to accept a
// connection and start answering (ROUTE-07 - per-route/service overrides come
// with the Service entity). Without it, a hung upstream hangs the client
// forever; with it, the request fails fast as a 502. Body streaming is NOT
// bounded - long downloads and websockets must live.
var upstreamTransport http.RoundTripper = &http.Transport{
	Proxy:                 http.ProxyFromEnvironment,
	DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
	TLSHandshakeTimeout:   5 * time.Second,
	ResponseHeaderTimeout: 15 * time.Second,
	ForceAttemptHTTP2:     true,
	MaxIdleConnsPerHost:   8,
	// Below the common load-balancer keep-alive (AWS ELB: 60s): OUR side drops
	// an idle connection first, so a request never rides one the upstream
	// already closed.
	IdleConnTimeout: 55 * time.Second,
}

// cookieStrippingTransport removes Meerkat's own session cookies at the very
// last moment before the wire: they are gateway-internal credentials and must
// never reach an upstream (cookies are host-scoped, not port-scoped, so on a
// same-host deployment the browser sends them with every data-plane request -
// identity travels through the route's Identity mechanism instead). Stripping
// here, after every proxy hook, keeps the original request on the response so
// ModifyResponse (pageStamp) still resolves the session.
type cookieStrippingTransport struct{ base http.RoundTripper }

func (t cookieStrippingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	stripGatewayCookies(clone)
	// Same story for the simulation knobs: gateway-internal, already
	// consumed - the upstream sees the resulting identity, not the knobs.
	clone.Header.Del(SimulateUserHeader)
	clone.Header.Del(SimulateRolesHeader)
	if strings.HasPrefix(clone.Header.Get("Authorization"), "Bearer "+SimTokenPrefix) {
		clone.Header.Del("Authorization")
	}
	// A simulated call is a TEST through swagger, not a genuine user action:
	// mark the upstream request so the backend's own action log can tell them
	// apart (X-Meerkat-Test = the tool, -By = the real developer behind it).
	if meta, ok := simulationMeta(clone.Context()); ok {
		clone.Header.Set("X-Meerkat-Test", meta.Via)
		if meta.By != "" {
			clone.Header.Set("X-Meerkat-Test-By", meta.By)
		}
	}
	res, err := t.base.RoundTrip(clone)
	if res != nil {
		res.Request = req
	}
	return res, err
}

func buildProxy(r store.Route, cf routing.CompiledFilters) (http.Handler, error) {
	target, err := url.Parse(r.Upstream)
	if err != nil {
		return nil, fmt.Errorf("bad upstream %q: %w", r.Upstream, err)
	}
	if target.Scheme == "" || target.Host == "" {
		return nil, fmt.Errorf("bad upstream %q: scheme and host required", r.Upstream)
	}

	proxy := &httputil.ReverseProxy{
		Transport: cookieStrippingTransport{upstreamTransport},
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetXForwarded()
			// Request filters transform the request path/headers first, THEN
			// the upstream base path is prepended by SetURL - so strip-prefix
			// and friends reason on the request path, never on the upstream's.
			for _, f := range cf.Request {
				f(pr)
			}
			pr.SetURL(target)
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			slog.Warn("upstream error", "route", r.Name, "upstream", r.Upstream, "err", err)
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		},
	}
	proxy.ModifyResponse = func(res *http.Response) error {
		// Make upstream failures visible in OUR logs: a 5xx reaching the client
		// through the proxy comes from the application, not from the gateway
		// (the gateway's own failure is the 502 in ErrorHandler).
		if res.StatusCode >= 500 {
			slog.Warn("upstream answered 5xx", "route", r.Name, "upstream", r.Upstream, "status", res.StatusCode)
		}
		for _, f := range cf.Response {
			if err := f(res); err != nil {
				return err
			}
		}
		return nil
	}
	return proxy, nil
}

// filterOwnResponse runs the route's outgoing filters over an answer the
// gateway produced itself.
//
// It buffers, which is the honest trade: a filter takes an *http.Response, and
// a handler writes straight to the client. What a terminal answers is a page or
// a small document, so holding it in memory to let a header filter see it costs
// nothing measurable - and the alternative is telling admins that outgoing
// filters work everywhere except here.
func filterOwnResponse(next http.Handler, filters []routing.ResponseFilter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &bufferedResponse{header: http.Header{}, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		res := &http.Response{
			StatusCode: rec.status,
			Header:     rec.header.Clone(),
			Body:       io.NopCloser(bytes.NewReader(rec.body.Bytes())),
			Request:    r,
		}
		for _, f := range filters {
			if err := f(res); err != nil {
				slog.Warn("outgoing filter failed on the route's own answer", "err", err)
				http.Error(w, "the gateway could not build this answer", http.StatusInternalServerError)
				return
			}
		}
		body, err := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if err != nil {
			http.Error(w, "the gateway could not build this answer", http.StatusInternalServerError)
			return
		}
		out := w.Header()
		for k := range out {
			out.Del(k)
		}
		for k, vs := range res.Header {
			for _, v := range vs {
				out.Add(k, v)
			}
		}
		out.Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(res.StatusCode)
		_, _ = w.Write(body)
	})
}

// bufferedResponse collects a handler's answer so response filters can see it.
type bufferedResponse struct {
	header  http.Header
	status  int
	written bool
	body    bytes.Buffer
}

func (b *bufferedResponse) Header() http.Header { return b.header }

func (b *bufferedResponse) WriteHeader(status int) {
	if !b.written {
		b.status, b.written = status, true
	}
}

func (b *bufferedResponse) Write(p []byte) (int, error) {
	b.written = true
	return b.body.Write(p)
}

// withIdentity resolves the caller and hands it to a terminal that answers
// from it (the "respond" brick). No session is not an error here: the template
// asks {{if .SignedIn}} and decides what an anonymous caller is told - which is
// what lets one route serve both the signed-in shape and the public one.
func (rt *Router) withIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var id routing.Identity
		if d, ok := rt.sessionIdentity(req); ok {
			id = routing.Identity{
				Username: d.Username, UserID: d.UserID, Fullname: d.Fullname,
				Email: d.Email, Tenant: d.Tenant, TenantID: d.TenantID,
				Timezone: d.Timezone, Roles: d.Roles,
			}
		}
		next.ServeHTTP(w, req.WithContext(routing.WithIdentity(req.Context(), id)))
	})
}

// requireSession gates a route handler behind a valid session: browsers
// navigating to HTML get redirected to the gateway's login page with a
// return-to path, API-style requests get a plain 401.
func requireSession(sm *session.Manager, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// A simulated identity (simulate.go) IS the session for this request,
		// and an internal spec read was authorized on the control plane.
		if _, ok := simulatedIdentity(req.Context()); ok || isSpecRead(req.Context()) {
			next.ServeHTTP(w, req)
			return
		}
		sess, err := sm.Resolve(req.Context(), req)
		if err == nil && sess.Pending != "" {
			// AUTH-05: until every login step is satisfied, all navigation is
			// redirected to the current step.
			if wantsHTML(req) {
				http.Redirect(w, req, "/"+sess.Pending+"?next="+url.QueryEscape(req.URL.RequestURI()), http.StatusSeeOther)
			} else {
				http.Error(w, "login flow incomplete", http.StatusUnauthorized)
			}
			return
		}
		if err != nil {
			if wantsHTML(req) {
				http.Redirect(w, req, "/login?next="+url.QueryEscape(req.URL.RequestURI()), http.StatusSeeOther)
				return
			}
			w.Header().Set("WWW-Authenticate", "Session")
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, req)
	})
}

func wantsHTML(req *http.Request) bool {
	return req.Method == http.MethodGet && strings.Contains(req.Header.Get("Accept"), "text/html")
}
