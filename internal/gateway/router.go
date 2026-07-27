// Package gateway is Meerkat's data path: route matching and reverse
// proxying. Routes come from the store as declarative predicate/filter specs
// (internal/routing), compiled into an immutable snapshot swapped atomically
// on reload — the hot path takes a read lock and nothing else.
package gateway

import (
	"context"
	"fmt"
	"html"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	filtering "github.com/softwarity/meerkat/internal/filters"
	"github.com/softwarity/meerkat/internal/routing"
	"github.com/softwarity/meerkat/internal/session"
	"github.com/softwarity/meerkat/internal/store"
)

// Router matches incoming requests against the compiled routes, first match
// wins in route order.
type Router struct {
	st *store.Store
	sm *session.Manager

	// lottery draws the per-request value consumed by weight predicates
	// (canary). Overridable in tests for determinism.
	lottery func() float64

	mu       sync.RWMutex
	routes   []compiledRoute
	needDraw bool // at least one route uses weight predicates
}

type compiledRoute struct {
	name    string
	preds   routing.CompiledPredicates
	handler http.Handler
}

// New builds a Router over the store. sm may be nil when no route requires
// authentication (tests). Call Reload to load the routes.
func New(st *store.Store, sm *session.Manager) *Router {
	return &Router{st: st, sm: sm, lottery: rand.Float64}
}

// Reload compiles the enabled routes from the store and swaps them in
// atomically. Safe to call while serving. A route that fails to compile
// aborts the reload with a precise error — the previous snapshot keeps
// serving.
func (rt *Router) Reload(ctx context.Context) error {
	stored, err := rt.st.ListRoutes(ctx)
	if err != nil {
		return err
	}
	// The application locale pool feeds every route (each may exclude some).
	// It may be EMPTY (no declared app locale) — then routes forward no locale
	// and the user button shows no language submenu.
	var appLangs []string
	_ = rt.st.GetSetting(ctx, store.SettingLanguages, &appLangs)
	compiled := make([]compiledRoute, 0, len(stored))
	var allPreds []*routing.CompiledPredicates
	needDraw := false
	for _, r := range stored {
		if !r.Enabled {
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
	rt.mu.Lock()
	rt.routes = compiled
	rt.needDraw = needDraw
	rt.mu.Unlock()
	slog.Info("routes reloaded", "count", len(compiled))
	return nil
}

// ServeHTTP dispatches to the first route whose predicates all match; nothing
// matched is a plain 404. The TRAP (ROUTE-10) is not a special case: it is an
// ordinary catch-all route ("/**") the admin orders last.
func (rt *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	rt.mu.RLock()
	routes, needDraw := rt.routes, rt.needDraw
	rt.mu.RUnlock()
	if needDraw {
		req = req.WithContext(routing.WithLottery(req.Context(), rt.lottery()))
	}
	for i := range routes {
		if routes[i].preds.Match(req) {
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
	// locale promoted to the front — every proxied route, no opt-out.
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
	// web component into its HTML pages — same rewriting as inject-head.
	if frag := userButtonFragment(r, localeCodes); frag != "" {
		filters.Response = append(filters.Response, filtering.InjectAfterHead(frag))
	}
	// Page injections (UIF): the session's effective roles and the user's
	// identity are stamped SERVER-SIDE onto the served HTML — roles as a class
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
	if r.Identity != nil && r.Identity.Enabled {
		filters.Request = append(filters.Request, rt.identityForwardFilter(*r.Identity))
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
	if r.API != nil && r.API.Security != nil &&
		(len(r.API.Security.Endpoints) > 0 || r.API.Security.Route != nil) {
		if rt.sm == nil {
			return compiledRoute{}, fmt.Errorf("route poses endpoint security but no session manager is configured")
		}
		guard, err := rt.endpointGuard(*r.API.Security, r.Filters, handler)
		if err != nil {
			return compiledRoute{}, err
		}
		handler = guard
	}
	if r.RequiredRole != "" {
		// A required role IMPLIES authentication: same login redirect for
		// browsers / 401 for API calls, then the role check on top.
		if rt.sm == nil {
			return compiledRoute{}, fmt.Errorf("route requires a role but no session manager is configured")
		}
		handler = rt.requireRole(r.RequiredRole, handler)
	} else if r.Authenticated {
		if rt.sm == nil {
			return compiledRoute{}, fmt.Errorf("route requires authentication but no session manager is configured")
		}
		handler = requireSession(rt.sm, handler)
	}
	return compiledRoute{name: r.Name, preds: preds, handler: handler}, nil
}

// Validate checks that a route would compile — same checks as Reload, minus
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
	}
	return validateRouteType(r)
}

// validateRouteType guards the route options: forwarding configs for every
// route, plus the UI extras when the UI toggle is on (ROUTE-02).
func validateRouteType(r store.Route) error {
	if r.RequiredRole != "" && !schemeTokenOK.MatchString(r.RequiredRole) {
		return fmt.Errorf("required role %q is not allowed: letters, digits, - and _ only", r.RequiredRole)
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
	if id := r.Identity; id != nil {
		switch id.Mechanism {
		case "", "headers":
		default:
			return fmt.Errorf("identity mechanism %q is not allowed: only headers is available today (jwt and signed-jwt come later)", id.Mechanism)
		}
		for field, header := range id.Headers {
			if !slices.Contains(store.IdentityFields, field) {
				return fmt.Errorf("identity field %q is not allowed: allowed fields are %s",
					field, strings.Join(store.IdentityFields, ", "))
			}
			if header != "" && !headerNameOK.MatchString(header) {
				return fmt.Errorf("identity header %q for %s is not allowed: letters, digits and - only", header, field)
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
// injected HTML — validated here, so the fragment never carries free text.
var schemeTokenOK = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// headerNameOK bounds the upstream header names a route may configure.
var headerNameOK = regexp.MustCompile(`^[A-Za-z0-9-]+$`)

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
// forwarding; ok is false without a completed session.
func (rt *Router) sessionIdentity(req *http.Request) (identityData, bool) {
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

// openTagRe matches the FIRST opening <tag …> in the document (case-insensitive,
// attributes may span lines). Group 1 = "<tag", group 2 = the attributes (with
// their leading space) or empty; the closing ">" follows. A trailing word
// boundary keeps <body> from matching <bodyfoo>.
func openTagRe(tag string) *regexp.Regexp {
	return regexp.MustCompile(`(?i)(<` + regexp.QuoteMeta(tag) + `)((?:\s[^>]*)?)>`)
}

// stampClass merges roles into the target tag's class attribute (server-side
// equivalent of classList.add): appends to an existing class="…", or adds one.
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

// addClassTokens appends roles to a double-quoted class="…" inside attrs
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

// setAttrToken replaces a double-quoted name="…" inside attrs, or appends one.
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

// metaTag builds a <meta name="…" content="…"> (both attribute-escaped).
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
// extra mechanisms ride on top — a custom header, a query parameter (an
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

// requireRole gates a route behind a session HOLDING the role (implies
// authenticated): anonymous browsers land on the login page, anonymous API
// calls get 401, a signed-in user without the role gets a 403 naming it.
func (rt *Router) requireRole(role string, next http.Handler) http.Handler {
	return requireSession(rt.sm, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		d, ok := rt.sessionIdentity(req)
		if !ok || !slices.Contains(d.Roles, role) {
			http.Error(w, "forbidden: this route requires the "+role+" role", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, req)
	}))
}

// accessGate wraps next with a unified access rule (RBAC-06/07): an empty rule
// passes through (delegated to the backend); otherwise a valid session is
// required and the caller must satisfy the rule's users/roles (401/redirect
// first, via requireSession).
func (rt *Router) accessGate(a store.Access, next http.Handler) http.Handler {
	if a.Empty() {
		return next
	}
	return requireSession(rt.sm, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		d, ok := rt.sessionIdentity(req)
		if ok && a.Grants(true, d.Username, d.Roles) {
			next.ServeHTTP(w, req)
			return
		}
		http.Error(w, "forbidden: you may not call this endpoint", http.StatusForbidden)
	}))
}

// endpointGuard enforces per-operation security (RBAC-07) inside an API route.
// Every override path is precompiled once at reload; per request the guard
// undoes the route's strip-prefix to recover the OpenAPI coordinate, then
// applies the first matching override, or the route-wide default when none
// matches. Operations with neither fall through to the route's own auth.
func (rt *Router) endpointGuard(sec store.EndpointSecurity, filters []routing.Spec, next http.Handler) (http.Handler, error) {
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
		eps = append(eps, compiledEP{method: strings.ToUpper(e.Method), path: cp, gate: rt.accessGate(e.Access, next)})
	}
	strip := stripPrefixCount(filters)
	var routeGate http.Handler
	if sec.Route != nil {
		routeGate = rt.accessGate(*sec.Route, next)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		specPath := routing.StripSegments(req.URL.Path, strip)
		for i := range eps {
			if (eps[i].method == "*" || eps[i].method == req.Method) && eps[i].path.Match(specPath) {
				eps[i].gate.ServeHTTP(w, req)
				return
			}
		}
		if routeGate != nil {
			routeGate.ServeHTTP(w, req)
			return
		}
		next.ServeHTTP(w, req)
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

// identityForwardFilter sends the signed-in user upstream as headers: one
// per field (names from cfg.Headers, the field name itself as default), plus
// the standard Remote-User always carrying the username. Inbound values are
// purged first so a client can never spoof them.
func (rt *Router) identityForwardFilter(cfg store.IdentityForward) routing.RequestFilter {
	name := func(field string) string {
		if n := cfg.Headers[field]; n != "" {
			return n
		}
		return field
	}
	return func(pr *httputil.ProxyRequest) {
		pr.Out.Header.Del("Remote-User")
		for _, f := range store.IdentityFields {
			pr.Out.Header.Del(name(f))
		}
		d, ok := rt.sessionIdentity(pr.In)
		if !ok {
			return
		}
		set := func(field, value string) {
			if value != "" {
				pr.Out.Header.Set(name(field), value)
			}
		}
		set("username", d.Username)
		set("userid", d.UserID)
		set("tenant", d.Tenant)
		set("tenantid", d.TenantID)
		set("email", d.Email)
		set("timezone", d.Timezone)
		set("roles", strings.Join(d.Roles, ","))
		if d.Username != "" {
			pr.Out.Header.Set("Remote-User", d.Username)
		}
	}
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
// fixed. Values are validated (validateRouteType) — no free text reaches HTML.
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
	attrs := fmt.Sprintf(` height="%d" position="%s"`, height, position)
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
// connection and start answering (ROUTE-07 — per-route/service overrides come
// with the Service entity). Without it, a hung upstream hangs the client
// forever; with it, the request fails fast as a 502. Body streaming is NOT
// bounded — long downloads and websockets must live.
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

func buildProxy(r store.Route, cf routing.CompiledFilters) (http.Handler, error) {
	target, err := url.Parse(r.Upstream)
	if err != nil {
		return nil, fmt.Errorf("bad upstream %q: %w", r.Upstream, err)
	}
	if target.Scheme == "" || target.Host == "" {
		return nil, fmt.Errorf("bad upstream %q: scheme and host required", r.Upstream)
	}

	proxy := &httputil.ReverseProxy{
		Transport: upstreamTransport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetXForwarded()
			// Request filters transform the request path/headers first, THEN
			// the upstream base path is prepended by SetURL — so strip-prefix
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

// requireSession gates a route handler behind a valid session: browsers
// navigating to HTML get redirected to the gateway's login page with a
// return-to path, API-style requests get a plain 401.
func requireSession(sm *session.Manager, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
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
