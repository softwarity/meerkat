package auth

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

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
	if err := st.CreateUser(context.Background(), store.User{ID: "u1", Username: "admin", PasswordHash: string(hash), Root: true}); err != nil {
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
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != session.CookieName {
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
