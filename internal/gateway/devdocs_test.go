package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/softwarity/meerkat/internal/routing"
	"github.com/softwarity/meerkat/internal/session"
	"github.com/softwarity/meerkat/internal/store"
)

// The developer docs: dev capability + the Others switch; every route
// exposing a spec is listed (even disabled — a dev sees what is being
// built), and specs come out rewritten to this very origin.
func TestDevDocs(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"openapi":"3.0.0","info":{"title":"petstore","version":"1"},"servers":[{"url":"https://internal.example/v1"}],"paths":{}}`)
		case "/whoami":
			// Echo the swagger-test markers the gateway is expected to add.
			_, _ = fmt.Fprintf(w, "test=%s|by=%s", r.Header.Get("X-Meerkat-Test"), r.Header.Get("X-Meerkat-Test-By"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(upstream.Close)

	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	for _, u := range []store.User{
		{ID: "dev", Username: "devon", PasswordHash: "x", Enabled: true, Dev: true},
		{ID: "bob", Username: "bob", PasswordHash: "x", Enabled: true},
	} {
		if err := st.CreateUser(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	// A role catalogue and one tenant with one group, for the profile bar.
	for _, r := range []store.Role{{ID: "admin", Name: "admin"}, {ID: "viewer", Name: "viewer", ParentID: "admin"}} {
		if err := st.SaveRole(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.SaveTenant(ctx, store.Tenant{ID: "t1", Name: "acme", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveGroup(ctx, store.Group{ID: "g1", TenantID: "t1", Name: "staff", RoleIDs: []string{"admin"}}); err != nil {
		t.Fatal(err)
	}
	// bob is a member of t1 in the staff group: "test as bob" must know his roles.
	if err := st.SaveMembership(ctx, store.Membership{UserID: "bob", TenantID: "t1", Type: store.MemberUser, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetMemberGroups(ctx, "t1", "bob", []string{"g1"}); err != nil {
		t.Fatal(err)
	}
	// One enabled route with a spec (gated: reading the contract still works),
	// one DISABLED route with a spec, one route without.
	for _, r := range []store.Route{
		{ID: "pets", Name: "pets", Enabled: true, Upstream: upstream.URL,
			Access:     store.Access{Roles: []string{"auditor"}},
			Predicates: []routing.Spec{{Type: "path", Args: map[string]any{"patterns": []any{"/pets/**"}}}},
			Filters:    []routing.Spec{{Type: "strip-prefix", Args: map[string]any{"parts": float64(1)}}},
			API:        &store.RouteAPI{OpenapiURL: "/openapi.json"}},
		{ID: "wip", Name: "wip", Enabled: false, Upstream: upstream.URL,
			Predicates: []routing.Spec{{Type: "path", Args: map[string]any{"patterns": []any{"/wip/**"}}}},
			API:        &store.RouteAPI{OpenapiURL: "/openapi.json"}},
		{ID: "bare", Name: "bare", Enabled: true, Upstream: upstream.URL,
			Predicates: []routing.Spec{{Type: "path", Args: map[string]any{"patterns": []any{"/bare/**"}}}}},
	} {
		if err := st.SaveRoute(ctx, r); err != nil {
			t.Fatal(err)
		}
	}

	sm := session.NewManager(st)
	rt := New(st, sm)
	if err := rt.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	rt.RegisterDevDocs(mux)
	mux.Handle("/", rt)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// The dev session carries a CURRENT tenant (t1): the bar lists that
	// tenant's groups, no other.
	rec := httptest.NewRecorder()
	if _, err := sm.IssueWith(ctx, rec, httptest.NewRequest("POST", "/login", nil),
		"dev", "t1", "", time.Hour, "", ""); err != nil {
		t.Fatal(err)
	}
	devC := rec.Result().Cookies()[0]
	bobC := issueSession(t, sm, "bob")

	get := func(t *testing.T, path string, cookie *http.Cookie) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		res, err := noFollow.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = res.Body.Close() })
		return res
	}

	t.Run("ships OFF: the whole surface plays dead", func(t *testing.T) {
		for _, p := range []string{"/meerkat/apidocs/", "/meerkat/apidocs/catalog.json",
			"/meerkat/apidocs/spec/pets", "/meerkat/apidocs/assets/skin.css"} {
			if res := get(t, p, devC); res.StatusCode != http.StatusNotFound {
				t.Fatalf("%s while off: %d, want 404", p, res.StatusCode)
			}
		}
	})

	if err := st.SetSetting(ctx, store.SettingDevDocsExposed, true); err != nil {
		t.Fatal(err)
	}

	t.Run("gating: anonymous is sent to login, a non-dev is refused", func(t *testing.T) {
		res := get(t, "/meerkat/apidocs/", nil)
		if res.StatusCode != http.StatusSeeOther || !strings.Contains(res.Header.Get("Location"), "/login?next=") {
			t.Fatalf("anonymous: %d %q", res.StatusCode, res.Header.Get("Location"))
		}
		if res := get(t, "/meerkat/apidocs/", bobC); res.StatusCode != http.StatusForbidden {
			t.Fatalf("non-dev: %d, want 403", res.StatusCode)
		}
		if res := get(t, "/meerkat/apidocs/catalog.json", bobC); res.StatusCode != http.StatusForbidden {
			t.Fatalf("non-dev catalog: %d, want 403", res.StatusCode)
		}
	})

	t.Run("the page follows the ACTIVE theme, remapped over the skin", func(t *testing.T) {
		res := get(t, "/meerkat/apidocs/", devC)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("page: %d, want 200", res.StatusCode)
		}
		raw, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		if body := string(raw); !strings.Contains(body, "--mk-primary:") ||
			!strings.Contains(body, "--mk-teal: var(--mk-primary)") {
			t.Fatal("page misses the injected theme block and skin bridge")
		}
	})

	t.Run("the catalogue feeds the profile bar in one request", func(t *testing.T) {
		res := get(t, "/meerkat/apidocs/catalog.json", devC)
		type gref struct {
			Name  string   `json:"name"`
			Roles []string `json:"roles"`
		}
		var c struct {
			Username  string   `json:"username"`
			GroupMode string   `json:"groupMode"`
			Roles     []string `json:"roles"`
			Groups    []gref   `json:"groups"`
			Users     []struct {
				Name   string `json:"name"`
				Groups []gref `json:"groups"`
			} `json:"users"`
			Specs []struct {
				ID       string `json:"id"`
				Disabled bool   `json:"disabled"`
			} `json:"specs"`
		}
		if err := json.NewDecoder(res.Body).Decode(&c); err != nil {
			t.Fatal(err)
		}
		if c.Username != "devon" || len(c.Roles) != 2 {
			t.Fatalf("catalog identity/roles = %q %v", c.Username, c.Roles)
		}
		// Cumulative by default (t1 sets no group mode).
		if c.GroupMode != "MULTIPLE" {
			t.Fatalf("groupMode = %q, want MULTIPLE (default)", c.GroupMode)
		}
		// Only the CURRENT tenant's group, name alone, roles RESOLVED (admin
		// grants viewer through the hierarchy) — the page never re-does RBAC.
		if len(c.Groups) != 1 || c.Groups[0].Name != "staff" ||
			strings.Join(c.Groups[0].Roles, ",") != "admin,viewer" {
			t.Fatalf("catalog groups = %+v (want the current tenant's staff only)", c.Groups)
		}
		// Users carry THEIR groups in this tenant: bob is in staff, devon in none.
		byName := map[string][]gref{}
		for _, u := range c.Users {
			byName[u.Name] = u.Groups
		}
		if len(c.Users) != 2 || len(byName["devon"]) != 0 ||
			len(byName["bob"]) != 1 || byName["bob"][0].Name != "staff" ||
			strings.Join(byName["bob"][0].Roles, ",") != "admin,viewer" {
			t.Fatalf("catalog users = %+v (bob->staff, devon->none)", c.Users)
		}
		// Every route with a spec shows, the disabled one flagged.
		if len(c.Specs) != 2 || c.Specs[0].ID != "pets" || c.Specs[1].ID != "wip" || !c.Specs[1].Disabled {
			t.Fatalf("catalog specs = %+v", c.Specs)
		}
	})

	t.Run("a spec comes out same-origin, gated route or not", func(t *testing.T) {
		res := get(t, "/meerkat/apidocs/spec/pets", devC)
		var spec struct {
			Servers []struct {
				URL string `json:"url"`
			} `json:"servers"`
		}
		if err := json.NewDecoder(res.Body).Decode(&spec); err != nil {
			t.Fatal(err)
		}
		// The route prefix + the spec's own path, RELATIVE: the routes answer
		// on this very origin.
		if len(spec.Servers) != 1 || spec.Servers[0].URL != "/pets/v1" {
			t.Fatalf("servers = %+v, want /pets/v1", spec.Servers)
		}
		if res := get(t, "/meerkat/apidocs/spec/bare", devC); res.StatusCode != http.StatusNotFound {
			t.Fatalf("spec-less route: %d, want 404", res.StatusCode)
		}
	})

	t.Run("a dev DATA session simulates, and the call reaches the upstream MARKED as a swagger test", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/pets/whoami", nil)
		req.AddCookie(devC)
		req.Header.Set(SimulateUserHeader, "ghost")
		req.Header.Set(SimulateRolesHeader, "auditor")
		res, err := noFollow.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = res.Body.Close() })
		if res.StatusCode != http.StatusOK {
			t.Fatalf("dev simulation: %d, want 200", res.StatusCode)
		}
		// The backend can tell a test from real traffic: the tool, and the
		// REAL developer behind it — not the impersonated "ghost".
		if body := readBody(t, res); body != "test=dev-swagger|by=devon" {
			t.Fatalf("upstream markers = %q, want the dev-swagger test tag by devon", body)
		}
		// A plain data session may not simulate at all.
		req2, _ := http.NewRequest(http.MethodGet, srv.URL+"/pets/whoami", nil)
		req2.AddCookie(bobC)
		req2.Header.Set(SimulateUserHeader, "ghost")
		req2.Header.Set(SimulateRolesHeader, "auditor")
		res2, err := noFollow.Do(req2)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = res2.Body.Close() })
		if res2.StatusCode != http.StatusForbidden {
			t.Fatalf("plain data session simulates: %d, want 403", res2.StatusCode)
		}
	})
}

var noFollow = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}}
