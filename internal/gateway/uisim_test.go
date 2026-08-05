package gateway

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/softwarity/meerkat/internal/session"
	"github.com/softwarity/meerkat/internal/store"
)

// The UI test mode (DEV-10): dead while the switch is off, dev-only, scoped
// to the caller's session AND one route, visible in the served page (roles
// stamp) and to the upstream (X-Meerkat-Test markers), reversible, bounded.
func TestUISim(t *testing.T) {
	// The upstream records the test markers it receives.
	var lastVia, lastBy atomic.Value
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastVia.Store(r.Header.Get("X-Meerkat-Test"))
		lastBy.Store(r.Header.Get("X-Meerkat-Test-By"))
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<html><head></head><body>ok</body></html>`)
	}))
	t.Cleanup(upstream.Close)

	open := pathRoute("r-open", "open", 1, "/open/**", upstream.URL)
	open.IsUI = true
	open.UI = &store.RouteUI{Roles: &store.RolesConfig{Enabled: true}}
	gated := pathRoute("r-gated", "gated", 2, "/gated/**", upstream.URL)
	gated.Access = store.Access{Roles: []string{"admin"}}

	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	for _, r := range []store.Route{open, gated} {
		if err := st.SaveRoute(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.CreateUser(ctx, store.User{ID: "d", Username: "devon", PasswordHash: "x", Enabled: true, Dev: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUser(ctx, store.User{ID: "b", Username: "bob", PasswordHash: "x", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	// A small hierarchy: ops implies ops-read and ops-write (RBAC-01).
	for _, role := range []store.Role{
		{ID: "role-ops", Name: "ops"},
		{ID: "role-ops-read", Name: "ops-read", ParentID: "role-ops"},
		{ID: "role-ops-write", Name: "ops-write", ParentID: "role-ops"},
	} {
		if err := st.SaveRole(ctx, role); err != nil {
			t.Fatal(err)
		}
	}
	sm := session.NewManager(st)
	rt := New(st, sm)
	if err := rt.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	// Same mux shape as main: the dev-sim endpoints beside the router.
	mux := http.NewServeMux()
	rt.RegisterUISim(mux)
	mux.Handle("/", rt)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cookieFor := func(userID string) *http.Cookie {
		rec := httptest.NewRecorder()
		if _, err := sm.Issue(ctx, rec, httptest.NewRequest("POST", "/login", nil), userID); err != nil {
			t.Fatal(err)
		}
		return rec.Result().Cookies()[0]
	}
	devC, bobC := cookieFor("d"), cookieFor("b")

	call := func(method, path, body string, cookie *http.Cookie) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if cookie != nil {
			req.AddCookie(cookie)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		return res.StatusCode, string(b)
	}

	t.Run("dev-only, live routes only, roles filtered", func(t *testing.T) {
		if code, _ := call("POST", "/meerkat/dev-sim", `{"route":"r-open","user":"jane"}`, bobC); code != http.StatusUnauthorized {
			t.Fatalf("non-dev: %d, want 401", code)
		}
		if code, _ := call("POST", "/meerkat/dev-sim", `{"route":"nope","user":"jane"}`, devC); code != http.StatusUnprocessableEntity {
			t.Fatalf("unknown route: %d, want 422", code)
		}
		if code, _ := call("POST", "/meerkat/dev-sim", `{"route":"r-open","user":""}`, devC); code != http.StatusUnprocessableEntity {
			t.Fatalf("empty user: %d, want 422", code)
		}
		code, body := call("POST", "/meerkat/dev-sim", `{"route":"r-open","user":"jane","roles":["sales","bad token"]}`, devC)
		if code != http.StatusOK || !strings.Contains(body, `"active":true`) || strings.Contains(body, "bad token") {
			t.Fatalf("set: %d %s", code, body)
		}
		if _, body := call("GET", "/meerkat/dev-sim?route=r-open", "", devC); !strings.Contains(body, `"user":"jane"`) {
			t.Fatalf("state: %s", body)
		}
	})

	t.Run("the tested route serves AS the simulated identity, marked as a test", func(t *testing.T) {
		if _, body := call("GET", "/open/page", "", devC); !strings.Contains(body, `<body class="sales">`) {
			t.Fatalf("simulated roles must stamp the page: %s", body)
		}
		if lastVia.Load() != "ui-test" || lastBy.Load() != "devon" {
			t.Fatalf("upstream markers: via=%v by=%v", lastVia.Load(), lastBy.Load())
		}
		// Another session on the same route stays untouched.
		if _, body := call("GET", "/open/page", "", bobC); strings.Contains(body, "sales") {
			t.Fatalf("bob must not inherit the simulation: %s", body)
		}
		if via := lastVia.Load(); via != "" {
			t.Fatalf("bob's request must not be marked: %v", via)
		}
	})

	t.Run("a refused simulated identity gets the exit page, not a lockout", func(t *testing.T) {
		if code, body := call("GET", "/gated/page", "", devC); code != http.StatusForbidden || strings.Contains(body, "Exit UI test") {
			t.Fatalf("no sim on gated: %d %s", code, body)
		}
		if code, _ := call("POST", "/meerkat/dev-sim", `{"route":"r-gated","user":"jane","roles":["sales"]}`, devC); code != http.StatusOK {
			t.Fatalf("set gated sim: %d", code)
		}
		code, body := call("GET", "/gated/page", "", devC)
		if code != http.StatusForbidden || !strings.Contains(body, "Exit UI test mode") || !strings.Contains(body, "jane") {
			t.Fatalf("refusal page: %d %s", code, body)
		}
	})

	t.Run("a posed role implies its descendants (RBAC-01)", func(t *testing.T) {
		code, body := call("POST", "/meerkat/dev-sim", `{"route":"r-open","user":"jane","roles":["ops"]}`, devC)
		if code != http.StatusOK || !strings.Contains(body, "ops-read") || !strings.Contains(body, "ops-write") {
			t.Fatalf("set with a parent role must answer the expansion: %d %s", code, body)
		}
		if _, body := call("GET", "/open/page", "", devC); !strings.Contains(body, `<body class="ops ops-read ops-write">`) {
			t.Fatalf("descendants must stamp the page too: %s", body)
		}
	})

	t.Run("exit and expiry both end the test", func(t *testing.T) {
		if code, _ := call("DELETE", "/meerkat/dev-sim?route=r-open", "", devC); code != http.StatusOK {
			t.Fatalf("clear: %d", code)
		}
		if _, body := call("GET", "/open/page", "", devC); strings.Contains(body, "sales") {
			t.Fatalf("cleared sim still applies: %s", body)
		}
		// An expired leftover answers inactive without waiting for a sweep.
		rt.uiSimMu.Lock()
		for k, e := range rt.uiSims {
			e.expires = time.Now().Add(-time.Minute)
			rt.uiSims[k] = e
		}
		rt.uiSimMu.Unlock()
		if _, body := call("GET", "/gated/page", "", devC); strings.Contains(body, "Exit UI test mode") {
			t.Fatalf("expired sim still applies: %s", body)
		}
	})
}
