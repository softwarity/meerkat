package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/softwarity/meerkat/internal/session"
	"github.com/softwarity/meerkat/internal/store"
)

// The gate end to end (RBAC-06), and above all what a REFUSAL looks like on a
// UI route. This is the bug of 2026-08-06: signing in returned "your account is
// awaiting access", and the very same session then walked through a route gated
// on "authenticated" - reaching the application with no organisation and no
// role. The rule is unchanged for "auth" (that level really does mean "I know
// who you are"); what changed is that an application can now ask for an
// organisation, and that being refused for the lack of one leads somewhere.
func TestAccessLevelsOverHTTP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("upstream"))
	}))
	t.Cleanup(upstream.Close)

	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()

	// newcomer belongs nowhere (the waiting room); jane is in acme only.
	for _, u := range []store.User{
		{ID: "u-new", Username: "newcomer", Enabled: true, PasswordHash: "x"},
		{ID: "u-jane", Username: "jane", Enabled: true, PasswordHash: "x"},
	} {
		if err := st.CreateUser(ctx, u); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
	}
	for _, id := range []string{"acme", "globex"} {
		if err := st.SaveTenant(ctx, store.Tenant{ID: id, Name: id, Enabled: true}); err != nil {
			t.Fatalf("SaveTenant: %v", err)
		}
	}
	if err := st.SaveMembership(ctx, store.Membership{UserID: "u-jane", TenantID: "acme", Type: store.MemberUser, Enabled: true}); err != nil {
		t.Fatalf("SaveMembership: %v", err)
	}

	ui := func(id, pattern, level string, tenants ...string) store.Route {
		r := pathRoute(id, id, 1, pattern, upstream.URL)
		r.IsUI = true
		r.Access = store.Access{Level: level, Tenants: tenants}
		return r
	}
	for _, r := range []store.Route{
		ui("r-auth", "/auth/**", store.AccessAuth),
		ui("r-tenant", "/tenant/**", store.AccessTenant),
		ui("r-acme", "/acme/**", store.AccessTenants, "acme"),
	} {
		if err := st.SaveRoute(ctx, r); err != nil {
			t.Fatalf("SaveRoute: %v", err)
		}
	}
	// The same rule on an API route: no page to read, so no redirection.
	api := pathRoute("r-api", "r-api", 2, "/api/**", upstream.URL)
	api.Access = store.Access{Level: store.AccessTenant}
	if err := st.SaveRoute(ctx, api); err != nil {
		t.Fatalf("SaveRoute: %v", err)
	}

	sm := session.NewManager(st)
	rt := New(st, sm)
	if err := rt.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	srv := httptest.NewServer(rt)
	t.Cleanup(srv.Close)

	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	get := func(t *testing.T, path string, c *http.Cookie) *http.Response {
		t.Helper()
		req, _ := http.NewRequest("GET", srv.URL+path, nil)
		req.Header.Set("Accept", "text/html")
		if c != nil {
			req.AddCookie(c)
		}
		res, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = res.Body.Close() })
		return res
	}

	newcomer := issueSession(t, sm, "u-new")
	jane := issueSession(t, sm, "u-jane")
	if err := sm.SetTenant(ctx, requestWith(srv.URL, jane), "acme"); err != nil {
		t.Fatalf("SetTenant: %v", err)
	}

	t.Run("auth still takes the waiting room, on purpose", func(t *testing.T) {
		if res := get(t, "/auth/x", newcomer); res.StatusCode != http.StatusOK {
			t.Fatalf("newcomer on auth = %d, want 200", res.StatusCode)
		}
	})

	t.Run("tenant sends the waiting room to the page that explains it", func(t *testing.T) {
		res := get(t, "/tenant/x", newcomer)
		if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/account-pending" {
			t.Fatalf("newcomer on tenant = %d %q, want 303 /account-pending",
				res.StatusCode, res.Header.Get("Location"))
		}
	})

	t.Run("an API answers 403 and names what is missing", func(t *testing.T) {
		res := get(t, "/api/x", newcomer)
		if res.StatusCode != http.StatusForbidden {
			t.Fatalf("newcomer on api = %d, want 403", res.StatusCode)
		}
		if body := readBody(t, res); body == "" || !strings.Contains(body, "no organisation") {
			t.Fatalf("403 body = %q, want it to name the missing organisation", body)
		}
	})

	t.Run("a member passes the levels their organisation satisfies", func(t *testing.T) {
		for _, p := range []string{"/auth/x", "/tenant/x", "/acme/x"} {
			if res := get(t, p, jane); res.StatusCode != http.StatusOK {
				t.Fatalf("jane on %s = %d, want 200", p, res.StatusCode)
			}
		}
	})

	t.Run("a route reserved to another organisation is refused, not offered", func(t *testing.T) {
		// jane is in acme only: nothing to switch to, so this is final.
		other := pathRoute("r-globex", "r-globex", 3, "/globex/**", upstream.URL)
		other.IsUI = true
		other.Access = store.Access{Level: store.AccessTenants, Tenants: []string{"globex"}}
		if err := st.SaveRoute(ctx, other); err != nil {
			t.Fatalf("SaveRoute: %v", err)
		}
		if err := rt.Reload(ctx); err != nil {
			t.Fatalf("Reload: %v", err)
		}
		if res := get(t, "/globex/x", jane); res.StatusCode != http.StatusForbidden {
			t.Fatalf("jane on globex = %d, want 403", res.StatusCode)
		}
	})

	t.Run("but a member of the accepted organisation is offered the switch", func(t *testing.T) {
		if err := st.SaveMembership(ctx, store.Membership{UserID: "u-jane", TenantID: "globex", Type: store.MemberUser, Enabled: true}); err != nil {
			t.Fatalf("SaveMembership: %v", err)
		}
		res := get(t, "/globex/x", jane)
		if res.StatusCode != http.StatusSeeOther {
			t.Fatalf("jane on globex after joining = %d, want 303", res.StatusCode)
		}
		if loc := res.Header.Get("Location"); !strings.Contains(loc, "/select-tenant") || !strings.Contains(loc, "globex") {
			t.Fatalf("Location = %q, want the tenant chooser carrying the destination", loc)
		}
	})
}

// requestWith builds the request SetTenant needs to find the session cookie.
func requestWith(base string, c *http.Cookie) *http.Request {
	req := httptest.NewRequest("GET", base, nil)
	req.AddCookie(c)
	return req
}
