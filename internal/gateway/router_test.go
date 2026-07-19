package gateway

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
	rt := newRouter(t, pathRoute("r1", "demo", 1, "/demo/**", upstream.URL,
		routing.Spec{Type: "strip-prefix", Args: map[string]any{"parts": 1}},
		routing.Spec{Type: "inject-head", Args: map[string]any{"fragment": `<script>meerkat</script>`}},
	))
	res, body := get(t, rt, "/demo/page")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if want := `<html><head><script>meerkat</script></head><body>ok</body></html>`; body != want {
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
