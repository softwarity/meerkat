package auth

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/softwarity/meerkat/internal/routing"
	"github.com/softwarity/meerkat/internal/session"
	"github.com/softwarity/meerkat/internal/store"
)

func setup(t *testing.T) (*http.ServeMux, *session.Manager) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	hash, _ := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.MinCost)
	if err := st.CreateUser(context.Background(), store.User{ID: "u1", Username: "admin", PasswordHash: string(hash), Root: true, Enabled: true}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	sm := session.NewManager(st)
	mux := http.NewServeMux()
	New(st, sm).Register(mux)
	return mux, sm
}

func postLogin(t *testing.T, mux *http.ServeMux, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestLoginPageRenders(t *testing.T) {
	mux, _ := setup(t)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/login?next=/app", nil))
	body, _ := io.ReadAll(rec.Result().Body)
	if rec.Code != http.StatusOK || !strings.Contains(string(body), `name="next" value="/app"`) {
		t.Fatalf("code=%d body=%s", rec.Code, body)
	}
}

func TestLoginSuccessSetsSessionAndRedirects(t *testing.T) {
	mux, sm := setup(t)
	rec := postLogin(t, mux, url.Values{"username": {"admin"}, "password": {"s3cret"}, "next": {"/app/x"}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/app/x" {
		t.Fatalf("code=%d loc=%q", rec.Code, rec.Header().Get("Location"))
	}
	// A completed login sets the session plus the durable browser identifier
	// (sign-in history), session first.
	cookies := rec.Result().Cookies()
	if len(cookies) != 2 || cookies[0].Name != session.CookieName || cookies[1].Name != "MEERKAT_BROWSER" {
		t.Fatalf("cookies=%+v", cookies)
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(cookies[0])
	if sess, err := sm.Resolve(context.Background(), req); err != nil || sess.UserID != "u1" {
		t.Fatalf("session not usable: %+v %v", sess, err)
	}
}

func TestLoginFailureSameMessageForUserAndPassword(t *testing.T) {
	mux, _ := setup(t)
	badUser := postLogin(t, mux, url.Values{"username": {"ghost"}, "password": {"s3cret"}})
	badPass := postLogin(t, mux, url.Values{"username": {"admin"}, "password": {"wrong"}})
	for _, rec := range []*httptest.ResponseRecorder{badUser, badPass} {
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("code=%d, want 401", rec.Code)
		}
		if len(rec.Result().Cookies()) != 0 {
			t.Fatal("cookie set on failed login")
		}
	}
	b1, _ := io.ReadAll(badUser.Result().Body)
	b2, _ := io.ReadAll(badPass.Result().Body)
	if string(b1) != string(b2) {
		t.Fatal("unknown-user and wrong-password responses differ (enumeration)")
	}
}

func TestOpenRedirectIsNeutralized(t *testing.T) {
	mux, _ := setup(t)
	for _, next := range []string{"https://evil.example", "//evil.example", "javascript:alert(1)"} {
		rec := postLogin(t, mux, url.Values{"username": {"admin"}, "password": {"s3cret"}, "next": {next}})
		if loc := rec.Header().Get("Location"); loc != "/" {
			t.Fatalf("next=%q redirected to %q", next, loc)
		}
	}
}

func TestLogoutClearsSession(t *testing.T) {
	mux, sm := setup(t)
	rec := postLogin(t, mux, url.Values{"username": {"admin"}, "password": {"s3cret"}})
	cookie := rec.Result().Cookies()[0]

	req := httptest.NewRequest("POST", "/logout", nil)
	req.AddCookie(cookie)
	out := httptest.NewRecorder()
	mux.ServeHTTP(out, req)
	if out.Code != http.StatusSeeOther {
		t.Fatalf("logout code=%d", out.Code)
	}
	check := httptest.NewRequest("GET", "/", nil)
	check.AddCookie(cookie)
	if _, err := sm.Resolve(context.Background(), check); err == nil {
		t.Fatal("session survived logout")
	}
}

func TestSeedAdminOnlyOnEmptyStore(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	t.Setenv("MEERKAT_ADMIN_PASSWORD", "boot-secret")

	if err := SeedAdmin(context.Background(), st); err != nil {
		t.Fatalf("SeedAdmin: %v", err)
	}
	u, err := st.GetUserByUsername(context.Background(), "admin")
	if err != nil || !u.Root {
		t.Fatalf("admin not seeded: %+v %v", u, err)
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte("boot-secret")) != nil {
		t.Fatal("seeded password does not verify")
	}
	// Second call must be a no-op.
	if err := SeedAdmin(context.Background(), st); err != nil {
		t.Fatalf("SeedAdmin (2nd): %v", err)
	}
	if n, _ := st.CountUsers(context.Background()); n != 1 {
		t.Fatalf("users = %d after re-seed", n)
	}
}

// setupFlow is setup with the store exposed, for tenant-flow tests.
func setupFlow(t *testing.T) (*http.ServeMux, *session.Manager, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	hash, _ := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.MinCost)
	if err := st.CreateUser(context.Background(), store.User{ID: "u1", Username: "alice", PasswordHash: string(hash), Enabled: true}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	sm := session.NewManager(st)
	mux := http.NewServeMux()
	New(st, sm).Register(mux)
	return mux, sm, st
}

func addMembership(t *testing.T, st *store.Store, tenantID, name string, ba store.BusinessAccess, ttl string) {
	t.Helper()
	ctx := context.Background()
	if err := st.SaveTenant(ctx, store.Tenant{ID: tenantID, Name: name, Enabled: true,
		BusinessAccess: store.BusinessAccess{Inherited: true}}); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveMembership(ctx, store.Membership{UserID: "u1", TenantID: tenantID,
		Type: store.MemberUser, Enabled: true, BusinessAccess: ba, SessionTTL: ttl}); err != nil {
		t.Fatal(err)
	}
}

func sessionOf(t *testing.T, sm *session.Manager, rec *httptest.ResponseRecorder) store.Session {
	t.Helper()
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("no session cookie")
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(cookies[0])
	sess, err := sm.Resolve(context.Background(), req)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	return sess
}

func TestLoginSingleTenantSetsTenantAndResolvedTTL(t *testing.T) {
	mux, sm, st := setupFlow(t)
	addMembership(t, st, "t1", "acme",
		store.BusinessAccess{Timezone: "UTC", Days: baDays("00:00", "23:59", 1, 2, 3, 4, 5, 6, 7)},
		"PT1H")
	rec := postLogin(t, mux, url.Values{"username": {"alice"}, "password": {"s3cret"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login: %d", rec.Code)
	}
	if sess := sessionOf(t, sm, rec); sess.TenantID != "t1" {
		t.Fatalf("active tenant = %q, want t1", sess.TenantID)
	}
	// The cookie carries the RESOLVED TTL (membership override, 1h).
	if maxAge := rec.Result().Cookies()[0].MaxAge; maxAge != 3600 {
		t.Fatalf("cookie MaxAge = %d, want 3600", maxAge)
	}
}

func TestLoginOutsideWorkingHoursIsRefusedExplicitly(t *testing.T) {
	mux, _, st := setupFlow(t)
	// A window on a single weekday that is NOT today (UTC).
	today := int(time.Now().UTC().Weekday())
	if today == 0 {
		today = 7
	}
	notToday := today%7 + 1
	addMembership(t, st, "t1", "acme",
		store.BusinessAccess{Timezone: "UTC", Days: baDays("00:00", "23:59", notToday)}, "")
	rec := postLogin(t, mux, url.Values{"username": {"alice"}, "password": {"s3cret"}})
	body, _ := io.ReadAll(rec.Result().Body)
	if rec.Code != http.StatusForbidden || !strings.Contains(string(body), "working hours") {
		t.Fatalf("outside hours: %d %s", rec.Code, body)
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Fatalf("no session may be issued outside the window")
	}
}

func TestLoginMultiTenantGoesThroughSelection(t *testing.T) {
	mux, sm, st := setupFlow(t)
	open := store.BusinessAccess{Inherited: true}
	addMembership(t, st, "t1", "acme", open, "")
	addMembership(t, st, "t2", "globex", open, "")

	rec := postLogin(t, mux, url.Values{"username": {"alice"}, "password": {"s3cret"}, "next": {"/app"}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/select-tenant" {
		t.Fatalf("multi-tenant login: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	cookie := rec.Result().Cookies()[0]
	if sess := sessionOf(t, sm, rec); sess.TenantID != "" || sess.Next != "/app" {
		t.Fatalf("tenant pending with next on session: tenant=%q next=%q", sess.TenantID, sess.Next)
	}

	// The page lists both tenants.
	req := httptest.NewRequest("GET", "/select-tenant?next=/app", nil)
	req.AddCookie(cookie)
	page := httptest.NewRecorder()
	mux.ServeHTTP(page, req)
	body, _ := io.ReadAll(page.Result().Body)
	if page.Code != http.StatusOK || !strings.Contains(string(body), "acme") || !strings.Contains(string(body), "globex") {
		t.Fatalf("selection page: %d %s", page.Code, body)
	}

	// Choosing globex stamps the session.
	form := url.Values{"tenant": {"t2"}, "next": {"/app"}}
	req = httptest.NewRequest("POST", "/select-tenant", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	sel := httptest.NewRecorder()
	mux.ServeHTTP(sel, req)
	if sel.Code != http.StatusSeeOther || sel.Header().Get("Location") != "/app" {
		t.Fatalf("selection: %d %q", sel.Code, sel.Header().Get("Location"))
	}
	req = httptest.NewRequest("GET", "/", nil)
	req.AddCookie(cookie)
	if sess, err := sm.Resolve(context.Background(), req); err != nil || sess.TenantID != "t2" {
		t.Fatalf("session tenant = %+v, %v", sess, err)
	}

	// A tenant outside the account is refused.
	form = url.Values{"tenant": {"nope"}, "next": {"/app"}}
	req = httptest.NewRequest("POST", "/select-tenant", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	bad := httptest.NewRecorder()
	mux.ServeHTTP(bad, req)
	if bad.Code != http.StatusForbidden {
		t.Fatalf("foreign tenant: %d", bad.Code)
	}
}

func TestAdminPlaneSkipsTenantFlow(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	hash, _ := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.MinCost)
	if err := st.CreateUser(context.Background(), store.User{ID: "u1", Username: "alice", PasswordHash: string(hash), Enabled: true}); err != nil {
		t.Fatal(err)
	}
	sm := session.NewManager(st)
	mux := http.NewServeMux()
	NewAdmin(st, sm).Register(mux)
	// Two memberships, one with a closed window: the ADMIN plane ignores both
	// the selection step and the working-hours gate.
	addMembership(t, st, "t1", "acme", store.BusinessAccess{Timezone: "UTC", Days: baDays("00:00", "00:00", 1)}, "")
	addMembership(t, st, "t2", "globex", store.BusinessAccess{Inherited: true}, "")

	rec := postLogin(t, mux, url.Values{"username": {"alice"}, "password": {"s3cret"}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Fatalf("admin login: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if sess := sessionOf(t, sm, rec); sess.TenantID != "" {
		t.Fatalf("admin plane must not set a tenant: %q", sess.TenantID)
	}
	// /select-tenant is not mounted on the admin plane.
	req := httptest.NewRequest("GET", "/select-tenant", nil)
	nf := httptest.NewRecorder()
	mux.ServeHTTP(nf, req)
	if nf.Code != http.StatusNotFound {
		t.Fatalf("select-tenant on admin plane: %d", nf.Code)
	}
}

// TestForcedPasswordStepCannotBeBypassed walks AUTH-05 step 1 end to end: a
// temporary password forces /update-password; while pending, the flow pages
// redirect there and the step cannot be skipped; completing it resumes the
// tenant flow.
func TestForcedPasswordStepCannotBeBypassed(t *testing.T) {
	mux, sm, st := setupFlow(t)
	// alice's password becomes temporary (admin reset pattern).
	hash, _ := bcrypt.GenerateFromPassword([]byte("temp0rary"), bcrypt.MinCost)
	if err := st.SetUserPassword(context.Background(), "u1", string(hash), true); err != nil {
		t.Fatal(err)
	}
	open := store.BusinessAccess{Inherited: true}
	addMembership(t, st, "t1", "acme", open, "")
	addMembership(t, st, "t2", "globex", open, "")

	// 1. Login lands on the forced step, session pending.
	rec := postLogin(t, mux, url.Values{"username": {"alice"}, "password": {"temp0rary"}, "next": {"/app"}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/update-password" {
		t.Fatalf("login: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	cookie := rec.Result().Cookies()[0]
	if sess := sessionOf(t, sm, rec); sess.Pending != "update-password" || sess.Next != "/app" {
		t.Fatalf("pending=%q next=%q", sess.Pending, sess.Next)
	}

	// 2. Short-circuit attempt: select-tenant redirects back to the step.
	req := httptest.NewRequest("GET", "/select-tenant?next=/app", nil)
	req.AddCookie(cookie)
	byp := httptest.NewRecorder()
	mux.ServeHTTP(byp, req)
	if byp.Code != http.StatusSeeOther || !strings.HasPrefix(byp.Header().Get("Location"), "/update-password") {
		t.Fatalf("select-tenant while pending: %d %q", byp.Code, byp.Header().Get("Location"))
	}

	// 3. Completing the step resumes the flow (two tenants -> selection).
	form := url.Values{"password": {"brand-new-pass"}, "confirm": {"brand-new-pass"}, "next": {"/app"}}
	req = httptest.NewRequest("POST", "/update-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	done := httptest.NewRecorder()
	mux.ServeHTTP(done, req)
	if done.Code != http.StatusSeeOther || done.Header().Get("Location") != "/select-tenant" {
		t.Fatalf("after change: %d %q", done.Code, done.Header().Get("Location"))
	}
	req = httptest.NewRequest("GET", "/", nil)
	req.AddCookie(cookie)
	sess, err := sm.Resolve(context.Background(), req)
	if err != nil || sess.Pending != "" {
		t.Fatalf("pending must be cleared: %+v %v", sess, err)
	}
	// The old temporary password no longer works, the new one does.
	if again := postLogin(t, mux, url.Values{"username": {"alice"}, "password": {"temp0rary"}}); again.Code != http.StatusUnauthorized {
		t.Fatalf("temporary password must be dead: %d", again.Code)
	}
	if fresh := postLogin(t, mux, url.Values{"username": {"alice"}, "password": {"brand-new-pass"}}); fresh.Code != http.StatusSeeOther {
		t.Fatalf("new password must work: %d", fresh.Code)
	}

	// 4. Without a pending step, the endpoint refuses (hijack guard).
	req = httptest.NewRequest("POST", "/update-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	refuse := httptest.NewRecorder()
	mux.ServeHTTP(refuse, req)
	if refuse.Code != http.StatusForbidden {
		t.Fatalf("update-password without pending must 403: %d", refuse.Code)
	}
}

// TestAdminPlaneKeepsMeerkatChrome: the theme editor restyles the DATA plane
// only - the admin plane's pages keep the built-in identity.
func TestAdminPlaneKeepsMeerkatChrome(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.SetSetting(context.Background(), store.SettingBranding,
		store.Branding{AppName: "ACME PORTAL", Tagline: "custom"}); err != nil {
		t.Fatal(err)
	}
	sm := session.NewManager(st)

	dataMux := http.NewServeMux()
	New(st, sm).Register(dataMux)
	adminMux := http.NewServeMux()
	NewAdmin(st, sm).Register(adminMux)

	rec := httptest.NewRecorder()
	dataMux.ServeHTTP(rec, httptest.NewRequest("GET", "/login", nil))
	if body, _ := io.ReadAll(rec.Result().Body); !strings.Contains(string(body), "ACME PORTAL") {
		t.Fatalf("data plane must wear the integrator branding")
	}
	rec = httptest.NewRecorder()
	adminMux.ServeHTTP(rec, httptest.NewRequest("GET", "/login", nil))
	body, _ := io.ReadAll(rec.Result().Body)
	if !strings.Contains(string(body), "MEERKAT") || strings.Contains(string(body), "ACME PORTAL") {
		t.Fatalf("admin plane must keep the Meerkat identity")
	}
}

// TestDataPlaneDefaultBrandingIsPlaceholder: a fresh gateway shows "MY APP" on
// the application login - an obvious nudge that the name is the integrator's
// to set - while the admin plane wears MEERKAT.
func TestDataPlaneDefaultBrandingIsPlaceholder(t *testing.T) {
	mux, _ := setup(t)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/login", nil))
	body, _ := io.ReadAll(rec.Result().Body)
	if !strings.Contains(string(body), "MY APP") || strings.Contains(string(body), ">MEERKAT<") {
		t.Fatalf("data plane default must be the MY APP placeholder")
	}
}

func TestSafeNextRejectsOpenRedirect(t *testing.T) {
	keep := []string{"/", "/app", "/app/x", "/secure/x?a=1&b=2"}
	for _, n := range keep {
		if got := safeNext(n); got != n {
			t.Errorf("safeNext(%q) = %q, want it kept", n, got)
		}
	}
	// Open-redirect vectors must all collapse to "/".
	reject := []string{
		"", "app", "https://evil.com", "http://evil.com",
		"//evil.com", "///evil.com",
		"/\\evil.com", "/\\/evil.com", "\\/evil.com", "/a\\b", // backslash folds to "/"
		"/a\tb", "/a\nb", "/a\rb", // control chars get stripped by browsers
		"javascript:alert(1)",
	}
	for _, n := range reject {
		if got := safeNext(n); got != "/" {
			t.Errorf("safeNext(%q) = %q, want %q", n, got, "/")
		}
	}
}

// baDays builds one identical hour range per listed day.
func baDays(from, to string, days ...int) []store.DayRange {
	out := make([]store.DayRange, 0, len(days))
	for _, d := range days {
		out = append(out, store.DayRange{Day: d, From: from, To: to})
	}
	return out
}

// The login page offers the enabled, unauthenticated UI routes as links;
// API routes and authenticated routes stay out (AUTH/ROUTE public entry).
func TestLoginPageOffersPublicUIRoutes(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	save := func(r store.Route) {
		t.Helper()
		if err := st.SaveRoute(ctx, r); err != nil {
			t.Fatalf("SaveRoute: %v", err)
		}
	}
	pathPred := func(pattern string) []routing.Spec {
		return []routing.Spec{{Type: "path", Args: map[string]any{"patterns": []any{pattern}}}}
	}
	save(store.Route{ID: "pub", Name: "docs", Order: 1, Enabled: true, IsUI: true,
		UI: &store.RouteUI{Link: "docs"}, Upstream: "http://up", Predicates: pathPred("/docs/**")})
	save(store.Route{ID: "api", Name: "openapi", Order: 2, Enabled: true,
		Upstream: "http://up", Predicates: pathPred("/api/**")})
	save(store.Route{ID: "sec", Name: "vault", Order: 3, Enabled: true,
		Access: store.Access{Level: store.AccessAuth},
		IsUI:   true, Upstream: "http://up", Predicates: pathPred("/secure/**")})

	mux := http.NewServeMux()
	New(st, session.NewManager(st)).Register(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/login", nil))
	body := rec.Body.String()
	if !strings.Contains(body, `href="/docs"`) {
		t.Fatalf("public UI route missing from login page:\n%s", body)
	}
	if strings.Contains(body, `href="/secure"`) || strings.Contains(body, `href="/api"`) {
		t.Fatalf("non-public routes leaked onto the login page:\n%s", body)
	}
}

// Passkey ceremonies: the login start is public and serves WebAuthn options;
// the register start demands a session and requires a RESIDENT key (the
// usernameless flow depends on it).
func TestPasskeyStartEndpoints(t *testing.T) {
	mux, sm := setup(t)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("POST", "/login/passkey/start", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "publicKey") {
		t.Fatalf("login start: %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("POST", "/profile/passkeys/register/start", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous register start must be 401, got %d", rec.Code)
	}

	seed := httptest.NewRecorder()
	if _, err := sm.Issue(context.Background(), seed, httptest.NewRequest("POST", "/login", nil), "u1"); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	req := httptest.NewRequest("POST", "/profile/passkeys/register/start", nil)
	req.AddCookie(seed.Result().Cookies()[0])
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, `"residentKey":"required"`) {
		t.Fatalf("register start: %d %s", rec.Code, body)
	}
}
