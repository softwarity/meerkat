package gateway

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/softwarity/meerkat/internal/routing"
	"github.com/softwarity/meerkat/internal/session"
	"github.com/softwarity/meerkat/internal/store"
)

// End to end: per-endpoint security (RBAC-07) enforced by the router. The route
// strips one segment, so /demo/get reaches the guard's OpenAPI coordinate /get.
// The route-wide default locks the API; specific operations open or tighten it.
func TestEndpointSecurityEnforcement(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "up:"+r.URL.Path) // echoes the post-strip path
	}))
	t.Cleanup(upstream.Close)

	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}

	// A user "neo" in tenant t1 holding the "ops" role.
	must(st.CreateUser(ctx, store.User{ID: "u1", Username: "neo", PasswordHash: "x", Enabled: true}))
	must(st.SaveTenant(ctx, store.Tenant{ID: "t1", Name: "acme", Enabled: true}))
	must(st.SaveMembership(ctx, store.Membership{
		UserID: "u1", TenantID: "t1", Type: store.MemberUser, Enabled: true,
		BusinessAccess: store.BusinessAccess{Inherited: true},
	}))
	must(st.SaveRole(ctx, store.Role{ID: "r-ops", Name: "ops"}))
	must(st.SaveGroup(ctx, store.Group{ID: "g-ops", TenantID: "t1", Name: "Ops", RoleIDs: []string{"r-ops"}}))
	must(st.SetMemberGroups(ctx, "t1", "u1", []string{"g-ops"}))

	route := pathRoute("r1", "demo", 1, "/demo/**", upstream.URL,
		routing.Spec{Type: "strip-prefix", Args: map[string]any{"parts": 1}})
	// Whole route needs a session by default (route-wide base Access).
	route.Access = store.Access{Authenticated: true}
	route.API = &store.RouteAPI{Security: &store.EndpointSecurity{
		Endpoints: []store.EndpointPolicy{
			{Method: "GET", Path: "/get", Access: store.Access{}},                              // reopened to anonymous
			{Method: "GET", Path: "/admin/{id}", Access: store.Access{Roles: []string{"ops"}}}, // ops role
			{Method: "POST", Path: "/user-only", Access: store.Access{Users: []string{"neo"}}}, // named user
		},
	}}
	must(st.SaveRoute(ctx, route))

	sm := session.NewManager(st)
	rt := New(st, sm)
	must(rt.Reload(ctx))
	srv := httptest.NewServer(rt)
	t.Cleanup(srv.Close)

	// A cookie for a fully signed-in session with an active tenant+group (roles
	// live), for user "neo".
	signedIn := func() *http.Cookie {
		rec := httptest.NewRecorder()
		if _, err := sm.IssueWith(ctx, rec, httptest.NewRequest("POST", "/login", nil),
			"u1", "t1", "g-ops", time.Hour, "", ""); err != nil {
			t.Fatalf("IssueWith: %v", err)
		}
		return rec.Result().Cookies()[0]
	}
	// A session with no active tenant carries no roles.
	noRole := func() *http.Cookie {
		rec := httptest.NewRecorder()
		if _, err := sm.Issue(ctx, rec, httptest.NewRequest("POST", "/login", nil), "u1"); err != nil {
			t.Fatalf("Issue: %v", err)
		}
		return rec.Result().Cookies()[0]
	}

	do := func(method, path string, cookie *http.Cookie) (int, string) {
		req, _ := http.NewRequest(method, srv.URL+path, nil)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		return res.StatusCode, string(body)
	}

	cases := []struct {
		name         string
		method, path string
		cookie       *http.Cookie
		wantCode     int
		wantBody     string
	}{
		{"reopened op, anon", "GET", "/demo/get", nil, 200, "up:/get"},
		{"route default locks, anon", "GET", "/demo/other", nil, http.StatusUnauthorized, ""},
		{"route default, signed in", "GET", "/demo/other", signedIn(), 200, "up:/other"},
		{"roles override, has ops", "GET", "/demo/admin/42", signedIn(), 200, "up:/admin/42"},
		{"roles override, no role", "GET", "/demo/admin/42", noRole(), http.StatusForbidden, ""},
		{"named user override", "POST", "/demo/user-only", signedIn(), 200, "up:/user-only"},
		{"named user override, anon", "POST", "/demo/user-only", nil, http.StatusUnauthorized, ""},
		{"method specific falls to route default", "GET", "/demo/user-only", nil, http.StatusUnauthorized, ""},
	}
	for _, c := range cases {
		code, body := do(c.method, c.path, c.cookie)
		if code != c.wantCode {
			t.Errorf("%s: status %d, want %d (body %q)", c.name, code, c.wantCode, body)
		}
		if c.wantBody != "" && body != c.wantBody {
			t.Errorf("%s: body %q, want %q", c.name, body, c.wantBody)
		}
	}
}

// With no route-wide default, an operation with no override falls through to
// the route's own auth (here: none), so it is served; overrides still apply.
func TestEndpointSecurityFallThrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "up:"+r.URL.Path)
	}))
	t.Cleanup(upstream.Close)

	route := pathRoute("r1", "demo", 1, "/demo/**", upstream.URL,
		routing.Spec{Type: "strip-prefix", Args: map[string]any{"parts": 1}})
	route.API = &store.RouteAPI{Security: &store.EndpointSecurity{
		Endpoints: []store.EndpointPolicy{
			{Method: "*", Path: "/locked", Access: store.Access{Authenticated: true}},
		},
	}}
	rt := newRouter(t, route)
	srv := httptest.NewServer(rt)
	t.Cleanup(srv.Close)

	// Unbound path, no route default: served.
	if res, err := http.Get(srv.URL + "/demo/free"); err != nil {
		t.Fatal(err)
	} else {
		_ = res.Body.Close()
		if res.StatusCode != 200 {
			t.Fatalf("unbound path should pass: %d", res.StatusCode)
		}
	}
	// Bound path with * method: any verb requires a session -> 401 anonymous.
	if res, err := http.Get(srv.URL + "/demo/locked"); err != nil {
		t.Fatal(err)
	} else {
		_ = res.Body.Close()
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("locked path anonymous: %d, want 401", res.StatusCode)
		}
	}
}
