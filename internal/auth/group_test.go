package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/softwarity/meerkat/internal/routing"
	"github.com/softwarity/meerkat/internal/session"
	"github.com/softwarity/meerkat/internal/store"
)

// groupSetup: one user, tenant t1 in EXCLUSIVE mode with two groups (ops,
// sales - one role each), tenant t2 with a single group, and one role-gated
// UI route per role.
func groupSetup(t *testing.T) (*http.ServeMux, *session.Manager, *store.Store) {
	t.Helper()
	mux, sm, st := mfaSetup(t)
	ctx := context.Background()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	// Both tenants run in EXCLUSIVE mode via their own column - the group mode
	// is a per-tenant setting (RBAC-03), there is no gateway-wide default.
	must(st.SaveTenant(ctx, store.Tenant{ID: "t1", Name: "acme", Enabled: true, GroupMode: store.GroupModeSingle}))
	must(st.SaveTenant(ctx, store.Tenant{ID: "t2", Name: "globex", Enabled: true, GroupMode: store.GroupModeSingle}))
	for _, tid := range []string{"t1", "t2"} {
		must(st.SaveMembership(ctx, store.Membership{
			UserID: "u1", TenantID: tid, Type: store.MemberUser, Enabled: true,
			BusinessAccess: store.BusinessAccess{Inherited: true},
		}))
	}
	must(st.SaveRole(ctx, store.Role{ID: "r-ops", Name: "ops"}))
	must(st.SaveRole(ctx, store.Role{ID: "r-sales", Name: "sales"}))
	must(st.SaveGroup(ctx, store.Group{ID: "g-ops", TenantID: "t1", Name: "Operations", RoleIDs: []string{"r-ops"}}))
	must(st.SaveGroup(ctx, store.Group{ID: "g-sales", TenantID: "t1", Name: "Sales", RoleIDs: []string{"r-sales"}}))
	must(st.SaveGroup(ctx, store.Group{ID: "g-lone", TenantID: "t2", Name: "Everyone", RoleIDs: []string{"r-sales"}}))
	must(st.SetMemberGroups(ctx, "t1", "u1", []string{"g-ops", "g-sales"}))
	must(st.SetMemberGroups(ctx, "t2", "u1", []string{"g-lone"}))
	for _, rt := range []store.Route{
		{ID: "opsapp", Name: "opsapp", Order: 1, Enabled: true, IsUI: true,
			Access: store.Access{Roles: []string{"ops"}}, UI: &store.RouteUI{Link: "opsapp"}, Upstream: "http://up.test",
			Predicates: []routing.Spec{{Type: "path", Args: map[string]any{"patterns": []any{"/opsapp/**"}}}}},
		{ID: "salesapp", Name: "salesapp", Order: 2, Enabled: true, IsUI: true,
			Access: store.Access{Roles: []string{"sales"}}, UI: &store.RouteUI{Link: "salesapp"}, Upstream: "http://up.test",
			Predicates: []routing.Spec{{Type: "path", Args: map[string]any{"patterns": []any{"/salesapp/**"}}}}},
	} {
		must(st.SaveRoute(ctx, rt))
	}
	return mux, sm, st
}

func sessionCookieOf(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == session.CookieName {
			return c
		}
	}
	return nil
}

// TestExclusiveGroupFlow drives the whole RBAC-03 SINGLE loop: sign-in lands
// on the group choice, only the chosen group's roles apply, switching tenant
// resets the group (auto-picked when alone, asked again when not).
func TestExclusiveGroupFlow(t *testing.T) {
	mux, sm, _ := groupSetup(t)

	// Multi-tenant sign-in: pick t1 first, WHICH then owes the group choice.
	login := do(t, mux, "POST", "/login", url.Values{"username": {"admin"}, "password": {"s3cret"}, "next": {"/app"}}, nil)
	cookie := sessionCookieOf(login)
	if login.Header().Get("Location") != "/select-tenant" {
		t.Fatalf("login: %q", login.Header().Get("Location"))
	}
	pick := do(t, mux, "POST", "/select-tenant", url.Values{"tenant": {"t1"}}, cookie)
	if loc := pick.Header().Get("Location"); !strings.HasPrefix(loc, "/select-group") {
		t.Fatalf("t1 has two groups: want /select-group, got %q", loc)
	}

	// The choice page lists both groups; an alien group is refused.
	page := do(t, mux, "GET", "/select-group", nil, cookie)
	// bodyString once per recorder: Result() memoizes the response, a second
	// read hits a drained body.
	if body := bodyString(page); page.Code != http.StatusOK ||
		!strings.Contains(body, "Operations") || !strings.Contains(body, "Sales") {
		t.Fatalf("select-group page: %d\n%.400s", page.Code, body)
	}
	if rec := do(t, mux, "POST", "/select-group", url.Values{"group": {"g-lone"}}, cookie); rec.Code != http.StatusForbidden {
		t.Fatalf("alien group: %d, want 403", rec.Code)
	}

	// Pick ops: the session carries it, and ONLY ops roles apply.
	rec := do(t, mux, "POST", "/select-group", url.Values{"group": {"g-ops"}, "next": {"/app"}}, cookie)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/app" {
		t.Fatalf("pick ops: %d -> %q", rec.Code, rec.Header().Get("Location"))
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(cookie)
	sess, err := sm.Resolve(context.Background(), req)
	if err != nil || sess.GroupID != "g-ops" {
		t.Fatalf("session group = %q (%v), want g-ops", sess.GroupID, err)
	}
	hub := do(t, mux, "GET", "/profile", nil, cookie)
	if body := bodyString(hub); !strings.Contains(body, `href="/opsapp"`) || strings.Contains(body, `href="/salesapp"`) {
		t.Fatalf("exclusive roles: want opsapp only:\n%.400s", body)
	}

	// Switching to t2 (one lone group) auto-picks it - no choice step.
	sw := do(t, mux, "POST", "/select-tenant", url.Values{"tenant": {"t2"}, "next": {"/here"}}, cookie)
	if loc := sw.Header().Get("Location"); loc != "/here" {
		t.Fatalf("switch to t2: %q, want /here", loc)
	}
	if sess, _ := sm.Resolve(context.Background(), req); sess.GroupID != "g-lone" {
		t.Fatalf("t2 lone group not auto-picked: %q", sess.GroupID)
	}

	// And back to t1: the group was reset, the choice is owed AGAIN.
	back := do(t, mux, "POST", "/select-tenant", url.Values{"tenant": {"t1"}, "next": {"/there"}}, cookie)
	if loc := back.Header().Get("Location"); !strings.HasPrefix(loc, "/select-group") {
		t.Fatalf("back to t1: %q, want /select-group...", loc)
	}
	if sess, _ := sm.Resolve(context.Background(), req); sess.GroupID != "" {
		t.Fatalf("group must be reset on tenant change, got %q", sess.GroupID)
	}
	// Undecided: NO group roles apply.
	hub = do(t, mux, "GET", "/profile", nil, cookie)
	if body := bodyString(hub); strings.Contains(body, `href="/opsapp"`) || strings.Contains(body, `href="/salesapp"`) {
		t.Fatalf("undecided session must carry no group roles")
	}
}

// TestCumulativeModeUnchanged: in MULTIPLE mode (the default), every group's
// roles cumulate and no group step ever shows.
func TestCumulativeModeUnchanged(t *testing.T) {
	mux, sm, st := groupSetup(t)
	// Force t1 back to cumulative on its own column (the default when unset).
	if err := st.SetGroupMode(context.Background(), "t1", store.GroupModeMultiple); err != nil {
		t.Fatal(err)
	}
	login := do(t, mux, "POST", "/login", url.Values{"username": {"admin"}, "password": {"s3cret"}}, nil)
	cookie := sessionCookieOf(login)
	pick := do(t, mux, "POST", "/select-tenant", url.Values{"tenant": {"t1"}, "next": {"/app"}}, cookie)
	if loc := pick.Header().Get("Location"); loc != "/app" {
		t.Fatalf("cumulative pick: %q, want /app", loc)
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(cookie)
	if sess, _ := sm.Resolve(context.Background(), req); sess.GroupID != "" {
		t.Fatalf("cumulative mode must not stamp a group")
	}
	hub := do(t, mux, "GET", "/profile", nil, cookie)
	if body := bodyString(hub); !strings.Contains(body, `href="/opsapp"`) || !strings.Contains(body, `href="/salesapp"`) {
		t.Fatalf("cumulative roles must open both apps:\n%.400s", body)
	}
}
