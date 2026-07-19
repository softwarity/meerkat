package gateway

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/softwarity/meerkat/internal/session"
	"github.com/softwarity/meerkat/internal/store"
)

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

func TestProxiesWithStripPrefixAndInjection(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/page" {
			http.NotFound(w, r)
			return
		}
		if xf := r.Header.Get("X-Forwarded-For"); xf == "" {
			t.Error("missing X-Forwarded-For on upstream request")
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<html><head></head><body>ok</body></html>`)
	}))
	t.Cleanup(upstream.Close)

	rt := newRouter(t, store.Route{
		ID: "r1", Name: "demo", Enabled: true,
		PathPrefix: "/demo", StripPrefix: true,
		Upstream: upstream.URL, InjectHead: `<script>meerkat</script>`,
	})

	res, body := get(t, rt, "/demo/page")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if want := `<html><head><script>meerkat</script></head><body>ok</body></html>`; body != want {
		t.Fatalf("got %q, want %q", body, want)
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
		store.Route{ID: "r2", Name: "wide", Order: 2, Enabled: true, PathPrefix: "/", Upstream: b.URL},
		store.Route{ID: "r1", Name: "narrow", Order: 1, Enabled: true, PathPrefix: "/api", Upstream: a.URL},
	)

	if _, body := get(t, rt, "/api/x"); body != "A" {
		t.Fatalf("/api/x routed to %q, want A", body)
	}
	if _, body := get(t, rt, "/other"); body != "B" {
		t.Fatalf("/other routed to %q, want B", body)
	}
}

func TestDisabledRouteIsSkippedAnd404(t *testing.T) {
	rt := newRouter(t, store.Route{
		ID: "r1", Name: "off", Enabled: false, PathPrefix: "/x", Upstream: "http://127.0.0.1:1",
	})
	if res, _ := get(t, rt, "/x"); res.StatusCode != http.StatusNotFound {
		t.Fatalf("disabled route served: %d", res.StatusCode)
	}
}

func TestPrefixMatchesOnSegmentBoundary(t *testing.T) {
	cases := []struct {
		path, prefix string
		want         bool
	}{
		{"/demo", "/demo", true},
		{"/demo/", "/demo", true},
		{"/demo/x", "/demo", true},
		{"/demolition", "/demo", false},
		{"/anything", "/", true},
	}
	for _, c := range cases {
		if got := matchPrefix(c.path, c.prefix); got != c.want {
			t.Errorf("matchPrefix(%q, %q) = %v, want %v", c.path, c.prefix, got, c.want)
		}
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
	if err := st.SaveRoute(ctx, store.Route{
		ID: "r1", Name: "secure", Enabled: true, Authenticated: true,
		PathPrefix: "/secure", Upstream: upstream.URL,
	}); err != nil {
		t.Fatalf("SaveRoute: %v", err)
	}
	sm := session.NewManager(st)
	rt := New(st, sm)
	if err := rt.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	srv := httptest.NewServer(rt)
	t.Cleanup(srv.Close)

	// Anonymous browser navigation → redirect to the login page with return path.
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
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("anonymous HTML: %d, want 303", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); loc != "/login?next=%2Fsecure%2Fx%3Fa%3D1" {
		t.Fatalf("Location = %q", loc)
	}

	// Anonymous API call → plain 401.
	res, err = http.Get(srv.URL + "/secure/api")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous API: %d, want 401", res.StatusCode)
	}

	// With a valid session cookie → proxied.
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
	rt := newRouter(t, store.Route{
		ID: "r1", Name: "down", Enabled: true, PathPrefix: "/down",
		Upstream: "http://127.0.0.1:1",
	})
	res, body := get(t, rt, "/down")
	if res.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", res.StatusCode)
	}
	if !strings.Contains(body, "upstream unavailable") {
		t.Fatalf("body = %q", body)
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

	if err := st.SaveRoute(context.Background(), store.Route{
		ID: "r1", Name: "new", Enabled: true, PathPrefix: "/new", Upstream: up.URL,
	}); err != nil {
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
