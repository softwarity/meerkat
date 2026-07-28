package gateway

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/softwarity/meerkat/internal/routing"
	"github.com/softwarity/meerkat/internal/session"
	"github.com/softwarity/meerkat/internal/store"
)

func pathRoute(id, name string, order int, pattern, upstream string, filters ...routing.Spec) store.Route {
	return store.Route{
		ID: id, Name: name, Order: order, Enabled: true, Upstream: upstream,
		Predicates: []routing.Spec{{Type: "path", Args: map[string]any{"patterns": pattern}}},
		Filters:    filters,
	}
}

func newRouter(t *testing.T, routes ...store.Route) *Router {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	for _, r := range routes {
		if err := st.SaveRoute(context.Background(), r); err != nil {
			t.Fatalf("SaveRoute: %v", err)
		}
	}
	rt := New(st, session.NewManager(st))
	if err := rt.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	return rt
}

func get(t *testing.T, rt *Router, path string) (*http.Response, string) {
	t.Helper()
	srv := httptest.NewServer(rt)
	t.Cleanup(srv.Close)
	res, err := http.Get(srv.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	body, err := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return res, string(body)
}

func htmlUpstream(t *testing.T, wantPath string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != wantPath {
			http.NotFound(w, r)
			return
		}
		if xf := r.Header.Get("X-Forwarded-For"); xf == "" {
			t.Error("missing X-Forwarded-For on upstream request")
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<html><head></head><body>ok</body></html>`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestProxiesWithStripPrefixAndInjection(t *testing.T) {
	upstream := htmlUpstream(t, "/page")
	r := pathRoute("r1", "demo", 1, "/demo/**", upstream.URL,
		routing.Spec{Type: "strip-prefix", Args: map[string]any{"parts": 1}},
	)
	// Injection rides the UI options now (the generic inject-head filter is gone).
	r.IsUI = true
	r.UI = &store.RouteUI{CustomJS: "meerkat()"}
	rt := newRouter(t, r)
	res, body := get(t, rt, "/demo/page")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if want := "<html><head><script>\nmeerkat()\n</script></head><body>ok</body></html>"; body != want {
		t.Fatalf("got %q, want %q", body, want)
	}
}

func TestUpstreamBasePathComposesWithStrip(t *testing.T) {
	upstream := htmlUpstream(t, "/base/page")
	// Upstream carries a base path: strip works on the REQUEST path, then the
	// base path is prepended — /demo/page → /page → /base/page.
	rt := newRouter(t, pathRoute("r1", "demo", 1, "/demo/**", upstream.URL+"/base",
		routing.Spec{Type: "strip-prefix", Args: map[string]any{"parts": 1}},
	))
	if res, _ := get(t, rt, "/demo/page"); res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
}

func TestFirstMatchWinsInOrder(t *testing.T) {
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "A")
	}))
	t.Cleanup(a.Close)
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "B")
	}))
	t.Cleanup(b.Close)

	rt := newRouter(t,
		pathRoute("r2", "wide", 2, "/**", b.URL),
		pathRoute("r1", "narrow", 1, "/api/**", a.URL),
	)
	if _, body := get(t, rt, "/api/x"); body != "A" {
		t.Fatalf("/api/x routed to %q, want A", body)
	}
	if _, body := get(t, rt, "/other"); body != "B" {
		t.Fatalf("/other routed to %q, want B", body)
	}
}

func TestMultiplePredicatesAreANDed(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "hit")
	}))
	t.Cleanup(up.Close)
	r := pathRoute("r1", "and", 1, "/api/**", up.URL)
	r.Predicates = append(r.Predicates, routing.Spec{Type: "method", Args: map[string]any{"methods": "POST"}})
	rt := newRouter(t, r)

	if res, _ := get(t, rt, "/api/x"); res.StatusCode != http.StatusNotFound {
		t.Fatalf("GET matched a POST-only route: %d", res.StatusCode)
	}
	srv := httptest.NewServer(rt)
	t.Cleanup(srv.Close)
	res, err := http.Post(srv.URL+"/api/x", "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("POST should match: %d", res.StatusCode)
	}
}

func TestCanaryWeightsEndToEnd(t *testing.T) {
	stable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "stable")
	}))
	t.Cleanup(stable.Close)
	canary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "canary")
	}))
	t.Cleanup(canary.Close)

	rStable := pathRoute("r1", "stable", 1, "/app/**", stable.URL)
	rStable.Predicates = append(rStable.Predicates, routing.Spec{Type: "weight", Args: map[string]any{"group": "app", "weight": 9}})
	rCanary := pathRoute("r2", "canary", 2, "/app/**", canary.URL)
	rCanary.Predicates = append(rCanary.Predicates, routing.Spec{Type: "weight", Args: map[string]any{"group": "app", "weight": 1}})

	rt := newRouter(t, rStable, rCanary)
	draws := []float64{0.05, 0.5, 0.89, 0.91, 0.99}
	i := 0
	rt.lottery = func() float64 { v := draws[i%len(draws)]; i++; return v }

	got := make([]string, 0, len(draws))
	for range draws {
		_, body := get(t, rt, "/app/x")
		got = append(got, body)
	}
	want := []string{"stable", "stable", "stable", "canary", "canary"}
	for j := range want {
		if got[j] != want[j] {
			t.Fatalf("draw %v routed to %q, want %q (all: %v)", draws[j], got[j], want[j], got)
		}
	}
}

func TestRedirectRoute(t *testing.T) {
	r := store.Route{
		ID: "r1", Name: "moved", Order: 1, Enabled: true, Upstream: "http://unused.invalid",
		Predicates: []routing.Spec{{Type: "path", Args: map[string]any{"patterns": "/old/**"}}},
		Filters:    []routing.Spec{{Type: "redirect", Args: map[string]any{"location": "/new", "status": 301}}},
	}
	rt := newRouter(t, r)
	srv := httptest.NewServer(rt)
	t.Cleanup(srv.Close)
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	res, err := noRedirect.Get(srv.URL + "/old/x")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != 301 || res.Header.Get("Location") != "/new" {
		t.Fatalf("redirect: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
}

func TestResponseHeaderFilters(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "leaky")
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(up.Close)
	rt := newRouter(t, pathRoute("r1", "hardened", 1, "/**", up.URL,
		routing.Spec{Type: "remove-response-header", Args: map[string]any{"name": "Server"}},
		routing.Spec{Type: "set-response-header", Args: map[string]any{"name": "X-Frame-Options", "value": "DENY"}},
	))
	res, _ := get(t, rt, "/x")
	if res.Header.Get("Server") != "" || res.Header.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("response headers wrong: %+v", res.Header)
	}
}

func TestInvalidRouteAbortsReloadKeepingOldSnapshot(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(up.Close)
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	if err := st.SaveRoute(ctx, pathRoute("r1", "good", 1, "/**", up.URL)); err != nil {
		t.Fatal(err)
	}
	rt := New(st, nil)
	if err := rt.Reload(ctx); err != nil {
		t.Fatal(err)
	}

	// A broken route arrives: reload must fail loudly...
	if err := st.SaveRoute(ctx, store.Route{
		ID: "r2", Name: "broken", Order: 2, Enabled: true, Upstream: up.URL,
		Predicates: []routing.Spec{{Type: "path", Args: map[string]any{"patterns": "/a/**/b"}}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := rt.Reload(ctx); err == nil || !strings.Contains(err.Error(), `route "broken"`) {
		t.Fatalf("reload error = %v, want route name in it", err)
	}
	// ...and the previous snapshot keeps serving.
	if res, _ := get(t, rt, "/x"); res.StatusCode != http.StatusOK {
		t.Fatalf("old snapshot gone: %d", res.StatusCode)
	}
}

func TestAuthenticatedRouteGating(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "secret")
	}))
	t.Cleanup(upstream.Close)

	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	if err := st.CreateUser(ctx, store.User{ID: "u1", Username: "admin", PasswordHash: "x"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	secure := pathRoute("r1", "secure", 1, "/secure/**", upstream.URL)
	secure.Authenticated = true
	if err := st.SaveRoute(ctx, secure); err != nil {
		t.Fatalf("SaveRoute: %v", err)
	}
	sm := session.NewManager(st)
	rt := New(st, sm)
	if err := rt.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	srv := httptest.NewServer(rt)
	t.Cleanup(srv.Close)

	req, _ := http.NewRequest("GET", srv.URL+"/secure/x?a=1", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	res, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/login?next=%2Fsecure%2Fx%3Fa%3D1" {
		t.Fatalf("anonymous HTML: %d %q", res.StatusCode, res.Header.Get("Location"))
	}

	res, err = http.Get(srv.URL + "/secure/api")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous API: %d, want 401", res.StatusCode)
	}

	rec := httptest.NewRecorder()
	if _, err := sm.Issue(ctx, rec, httptest.NewRequest("POST", "/login", nil), "u1"); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	req, _ = http.NewRequest("GET", srv.URL+"/secure/x", nil)
	req.AddCookie(rec.Result().Cookies()[0])
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK || string(body) != "secret" {
		t.Fatalf("authenticated: %d %q", res.StatusCode, body)
	}
}

func TestUpstreamDownIs502(t *testing.T) {
	rt := newRouter(t, pathRoute("r1", "down", 1, "/down/**", "http://127.0.0.1:1"))
	res, body := get(t, rt, "/down")
	if res.StatusCode != http.StatusBadGateway || !strings.Contains(body, "upstream unavailable") {
		t.Fatalf("%d %q", res.StatusCode, body)
	}
}

func TestReloadPicksUpChanges(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "up")
	}))
	t.Cleanup(up.Close)

	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	rt := New(st, nil)
	if err := rt.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	srv := httptest.NewServer(rt)
	t.Cleanup(srv.Close)

	res, err := http.Get(srv.URL + "/new")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("before reload: %d, want 404", res.StatusCode)
	}
	if err := st.SaveRoute(context.Background(), pathRoute("r1", "new", 1, "/new/**", up.URL)); err != nil {
		t.Fatalf("SaveRoute: %v", err)
	}
	if err := rt.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	res, err = http.Get(srv.URL + "/new")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK || string(body) != "up" {
		t.Fatalf("after reload: %d %q", res.StatusCode, body)
	}
}

// TestCatchAllRouteTraps: the TRAP (ROUTE-10) is an ordinary route — a "/**"
// catch-all ordered LAST. Whatever the routes above did not match lands on it,
// "/" included, any method; without such a route, unmatched is a plain 404.
func TestCatchAllRouteTraps(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("trapped"))
	}))
	t.Cleanup(up.Close)

	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	if err := st.SaveRoute(ctx, pathRoute("r1", "demo", 1, "/demo/**", up.URL+"/unused")); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveRoute(ctx, pathRoute("trap", "trap", 2, "/**", up.URL)); err != nil {
		t.Fatal(err)
	}
	rt := New(st, nil)
	if err := rt.Reload(ctx); err != nil {
		t.Fatal(err)
	}

	for _, req := range []*http.Request{
		httptest.NewRequest("GET", "/", nil),
		httptest.NewRequest("POST", "/nope", nil),
	} {
		rec := httptest.NewRecorder()
		rt.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || rec.Body.String() != "trapped" {
			t.Fatalf("%s %s: %d %q, want the catch-all to trap it", req.Method, req.URL.Path, rec.Code, rec.Body.String())
		}
	}
}

// TestUpstreamHangIs502: an upstream that never answers its headers must fail
// fast as 502 thanks to the transport's ResponseHeaderTimeout (ROUTE-07).
func TestUpstreamHangIs502(t *testing.T) {
	prev := upstreamTransport
	upstreamTransport = &http.Transport{ResponseHeaderTimeout: 100 * time.Millisecond}
	t.Cleanup(func() { upstreamTransport = prev })

	release := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		<-release // hang until the test ends
	}))
	t.Cleanup(func() { close(release); up.Close() })

	rt := newRouter(t, pathRoute("r1", "hang", 1, "/**", up.URL))

	start := time.Now()
	rec := httptest.NewRecorder()
	rt.ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("hanging upstream: %d, want 502", rec.Code)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("502 took %v — the timeout did not bound the wait", elapsed)
	}
}

// resolveLocale: cookie first, then Accept-Language (exact then base), then
// the route's first code.
func TestResolveLocale(t *testing.T) {
	codes := []string{"en-US", "fr-FR", "de"}
	mk := func(cookie, accept string) *http.Request {
		req := httptest.NewRequest("GET", "/", nil)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: "MEERKAT_LANG", Value: cookie})
		}
		if accept != "" {
			req.Header.Set("Accept-Language", accept)
		}
		return req
	}
	cases := []struct{ cookie, accept, want string }{
		{"fr-FR", "", "fr-FR"},
		{"fr", "", "fr-FR"},      // base-language cookie picks the region variant
		{"es", "de;q=0.9", "de"}, // unknown cookie falls to Accept-Language
		{"", "fr-CA,en;q=0.8", "fr-FR"},
		{"", "es,pt", "en-US"}, // nothing matches: first code
		{"", "", "en-US"},
	}
	for _, c := range cases {
		if got := resolveLocale(mk(c.cookie, c.accept), codes); got != c.want {
			t.Errorf("resolveLocale(cookie=%q accept=%q) = %q, want %q", c.cookie, c.accept, got, c.want)
		}
	}
}

// Locale mechanisms: custom/query/path only (Accept-Language always goes),
// path demands a UI route, names are validated.
func TestValidateLocales(t *testing.T) {
	mk := func(isUI bool, mechs []string, header, param string) store.Route {
		return store.Route{IsUI: isUI, Upstream: "http://up",
			Locales: &store.LocalesConfig{Mechanisms: mechs, Header: header, Param: param}}
	}
	if err := Validate(mk(true, []string{"query", "path"}, "", "lg")); err != nil {
		t.Fatalf("valid locales refused: %v", err)
	}
	if err := Validate(mk(false, []string{"query"}, "", "")); err != nil {
		t.Fatalf("query mechanism on an API refused: %v", err)
	}
	if err := Validate(mk(false, []string{"path"}, "", "")); err == nil {
		t.Fatal("path mechanism accepted on a non-UI route")
	}
	if err := Validate(mk(true, []string{"header"}, "", "")); err == nil {
		t.Fatal("header is not a mechanism anymore (always sent)")
	}
	if err := Validate(mk(true, []string{"custom"}, "X Locale", "")); err == nil {
		t.Fatal("bad custom header accepted")
	}
}

// Accept-Language promotion: the resolved locale lands first, the caller's
// other preferences stay behind, duplicates are dropped.
func TestPromoteLocale(t *testing.T) {
	cases := []struct{ orig, loc, want string }{
		{"", "fr", "fr"},
		{"en-US,en;q=0.8", "fr", "fr, en-US, en;q=0.8"},
		{"fr;q=0.5,en;q=0.8", "fr", "fr, en;q=0.8"},
		{"de", "de", "de"},
	}
	for _, c := range cases {
		if got := promoteLocale(c.orig, c.loc); got != c.want {
			t.Errorf("promoteLocale(%q, %q) = %q, want %q", c.orig, c.loc, got, c.want)
		}
	}
}

// Identity forwarding validates its mechanism, attributes and mapped names.
func TestValidateIdentity(t *testing.T) {
	mk := func(mech string, attrs ...store.IdentityAttr) store.Route {
		return store.Route{Upstream: "http://up",
			Identity: &store.IdentityForward{Mechanism: mech, Attributes: attrs}}
	}
	if err := Validate(mk("headers", store.IdentityAttr{Field: "username", As: "X-User"})); err != nil {
		t.Fatalf("valid headers identity refused: %v", err)
	}
	if err := Validate(mk("jwt", store.IdentityAttr{Field: "roles", As: "role_list", AsJSON: true})); err != nil {
		t.Fatalf("valid jwt identity refused: %v", err)
	}
	if err := Validate(mk("signed-jwt", store.IdentityAttr{Field: "username"})); err != nil {
		t.Fatalf("valid signed-jwt refused: %v", err)
	}
	badAlg := mk("signed-jwt", store.IdentityAttr{Field: "username"})
	badAlg.Identity.Algorithm = "HS256"
	if err := Validate(badAlg); err == nil {
		t.Fatal("bad signature algorithm accepted")
	}
	if err := Validate(mk("carrier-pigeon")); err == nil {
		t.Fatal("unknown mechanism accepted")
	}
	if err := Validate(mk("headers", store.IdentityAttr{Field: "shoesize"})); err == nil {
		t.Fatal("unknown identity attribute accepted")
	}
	if err := Validate(mk("headers", store.IdentityAttr{Field: "email", As: "not a header"})); err == nil {
		t.Fatal("bad header name accepted")
	}
	if err := Validate(mk("jwt", store.IdentityAttr{Field: "email", As: "bad claim"})); err == nil {
		t.Fatal("bad claim name accepted")
	}
	if err := Validate(mk("headers", store.IdentityAttr{Field: "username"}, store.IdentityAttr{Field: "username"})); err == nil {
		t.Fatal("duplicate attribute accepted")
	}
	bad := mk("jwt", store.IdentityAttr{Field: "username"})
	bad.Identity.TTL = "banana"
	if err := Validate(bad); err == nil {
		t.Fatal("bad ttl accepted")
	}
}

// Identity forwarding rides EVERY request of the route, HTML navigations and
// API calls alike (a UI route's page and its /api calls share the pipe):
// headers reach the upstream, spoofed inbound values are purged, anonymous
// requests carry nothing.
func TestIdentityForwardHeadersReachUpstream(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	if err := st.CreateUser(ctx, store.User{ID: "u1", Username: "neo", Email: "neo@io",
		Timezone: "Europe/Paris", Enabled: true, PasswordHash: "x"}); err != nil {
		t.Fatal(err)
	}
	sm := session.NewManager(st)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "user="+r.Header.Get("username")+
			";remote="+r.Header.Get("Remote-User")+
			";mail="+r.Header.Get("X-Mail")+
			";tenant="+r.Header.Get("tenant"))
	}))
	t.Cleanup(upstream.Close)

	route := store.Route{ID: "r", Name: "r", Enabled: true, Upstream: upstream.URL,
		Predicates: []routing.Spec{{Type: "path", Args: map[string]any{"patterns": []any{"/**"}}}},
		Identity: &store.IdentityForward{Mechanism: "headers", Attributes: []store.IdentityAttr{
			{Field: "username"}, {Field: "email", As: "X-Mail"},
		}}}
	if err := st.SaveRoute(ctx, route); err != nil {
		t.Fatal(err)
	}
	rt := New(st, sm)
	if err := rt.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(rt)
	t.Cleanup(srv.Close)

	rec := httptest.NewRecorder()
	if _, err := sm.Issue(ctx, rec, httptest.NewRequest("POST", "/login", nil), "u1"); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cookie := rec.Result().Cookies()[0]

	call := func(withSession bool) string {
		req, _ := http.NewRequest("GET", srv.URL+"/get", nil)
		// Spoofing attempts: the gateway must purge these.
		req.Header.Set("username", "hacker")
		req.Header.Set("tenant", "EvilCorp")
		if withSession {
			req.AddCookie(cookie)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		return string(body)
	}

	// Only the selected attributes travel: username (default name) and email
	// (mapped to X-Mail). No implicit Remote-User, and the unselected tenant is
	// purged (the inbound spoof is dropped and nothing is written back).
	if got := call(true); got != "user=neo;remote=;mail=neo@io;tenant=" {
		t.Fatalf("signed-in forwarding wrong: %q", got)
	}
	if got := call(false); got != "user=;remote=;mail=;tenant=" {
		t.Fatalf("anonymous request must carry no identity: %q", got)
	}
}

// TestIdentityForwardJWT: the jwt mechanism carries the selected attributes as
// claims in an Authorization: Bearer token, purges an inbound Authorization
// spoof, and writes nothing for an anonymous caller.
func TestIdentityForwardJWT(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	if err := st.CreateUser(ctx, store.User{ID: "u1", Username: "neo", Email: "neo@io",
		Enabled: true, PasswordHash: "x"}); err != nil {
		t.Fatal(err)
	}
	sm := session.NewManager(st)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Header.Get("Authorization"))
	}))
	t.Cleanup(upstream.Close)

	route := store.Route{ID: "r", Name: "orders", Enabled: true, Upstream: upstream.URL,
		Predicates: []routing.Spec{{Type: "path", Args: map[string]any{"patterns": []any{"/**"}}}},
		Identity: &store.IdentityForward{Mechanism: "jwt", Attributes: []store.IdentityAttr{
			{Field: "username", As: "preferred_username"},
		}}}
	if err := st.SaveRoute(ctx, route); err != nil {
		t.Fatal(err)
	}
	rt := New(st, sm)
	if err := rt.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(rt)
	t.Cleanup(srv.Close)

	rec := httptest.NewRecorder()
	if _, err := sm.Issue(ctx, rec, httptest.NewRequest("POST", "/login", nil), "u1"); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cookie := rec.Result().Cookies()[0]

	req, _ := http.NewRequest("GET", srv.URL+"/get", nil)
	req.Header.Set("Authorization", "Bearer spoofed") // must be purged
	req.AddCookie(cookie)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()

	got := string(body)
	if !strings.HasPrefix(got, "Bearer ") {
		t.Fatalf("no bearer token forwarded: %q", got)
	}
	parts := strings.Split(strings.TrimPrefix(got, "Bearer "), ".")
	if len(parts) != 3 || parts[2] != "" {
		t.Fatalf("not an unsigned JWT (header.payload.): %q", got)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("payload not json: %v", err)
	}
	if claims["iss"] != "meerkat" || claims["sub"] != "u1" || claims["aud"] != "orders" {
		t.Fatalf("registered claims wrong: %+v", claims)
	}
	if claims["preferred_username"] != "neo" {
		t.Fatalf("mapped attribute claim wrong: %+v", claims)
	}
	if _, ok := claims["exp"]; !ok {
		t.Fatalf("missing exp claim: %+v", claims)
	}

	// Anonymous: no token at all, and the inbound spoof is gone.
	anon, _ := http.NewRequest("GET", srv.URL+"/get", nil)
	anon.Header.Set("Authorization", "Bearer spoofed")
	res2, err := http.DefaultClient.Do(anon)
	if err != nil {
		t.Fatal(err)
	}
	body2, _ := io.ReadAll(res2.Body)
	_ = res2.Body.Close()
	if strings.TrimSpace(string(body2)) != "" {
		t.Fatalf("anonymous request must carry no Authorization: %q", string(body2))
	}
}

// TestIdentityForwardSignedJWT proves the whole signed-jwt chain: the route
// forwards a token the gateway signed (ES256), and that token verifies against
// the very key the gateway publishes at /.well-known/jwks.json.
func TestIdentityForwardSignedJWT(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	if err := st.CreateUser(ctx, store.User{ID: "u1", Username: "neo", Enabled: true, PasswordHash: "x"}); err != nil {
		t.Fatal(err)
	}
	sm := session.NewManager(st)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Header.Get("Authorization"))
	}))
	t.Cleanup(upstream.Close)

	route := store.Route{ID: "r", Name: "orders", Enabled: true, Upstream: upstream.URL,
		Predicates: []routing.Spec{{Type: "path", Args: map[string]any{"patterns": []any{"/**"}}}},
		Identity: &store.IdentityForward{Mechanism: "signed-jwt", Algorithm: "ES256",
			Attributes: []store.IdentityAttr{{Field: "username", As: "preferred_username"}}}}
	if err := st.SaveRoute(ctx, route); err != nil {
		t.Fatal(err)
	}
	rt := New(st, sm)
	if err := rt.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(rt)
	t.Cleanup(srv.Close)

	// The JWKS is public and carries an ES256 EC key.
	pub, kid := fetchES256JWK(t, srv.URL+JWKSPath)

	rec := httptest.NewRecorder()
	if _, err := sm.Issue(ctx, rec, httptest.NewRequest("POST", "/login", nil), "u1"); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cookie := rec.Result().Cookies()[0]
	req, _ := http.NewRequest("GET", srv.URL+"/get", nil)
	req.AddCookie(cookie)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()

	token := strings.TrimPrefix(string(body), "Bearer ")
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[2] == "" {
		t.Fatalf("expected a signed JWT (three non-empty segments): %q", string(body))
	}
	var header map[string]any
	if err := json.Unmarshal(mustB64(t, parts[0]), &header); err != nil {
		t.Fatalf("header: %v", err)
	}
	if header["alg"] != "ES256" || header["kid"] != kid {
		t.Fatalf("header alg/kid wrong: %+v (jwks kid %q)", header, kid)
	}
	// The signature verifies against the JWKS-published key.
	h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	sig := mustB64(t, parts[2])
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, h[:], r, s) {
		t.Fatal("forwarded token does not verify against the published JWKS key")
	}
	var claims map[string]any
	if err := json.Unmarshal(mustB64(t, parts[1]), &claims); err != nil {
		t.Fatalf("claims: %v", err)
	}
	if claims["sub"] != "u1" || claims["aud"] != "orders" || claims["preferred_username"] != "neo" {
		t.Fatalf("claims wrong: %+v", claims)
	}
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64url %q: %v", s, err)
	}
	return b
}

// fetchES256JWK pulls the JWKS and rebuilds the ES256 EC public key.
func fetchES256JWK(t *testing.T, url string) (*ecdsa.PublicKey, string) {
	t.Helper()
	res, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET jwks: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	var doc struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.NewDecoder(res.Body).Decode(&doc); err != nil {
		t.Fatalf("jwks decode: %v", err)
	}
	for _, k := range doc.Keys {
		if k["alg"] != "ES256" {
			continue
		}
		return &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(mustB64(t, k["x"])),
			Y:     new(big.Int).SetBytes(mustB64(t, k["y"])),
		}, k["kid"]
	}
	t.Fatal("no ES256 key in JWKS")
	return nil, ""
}
