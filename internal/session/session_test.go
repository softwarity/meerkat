package session

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/softwarity/meerkat/internal/store"
)

func setup(t *testing.T, opts ...Option) (*Manager, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.CreateUser(context.Background(), store.User{ID: "u1", Username: "admin", PasswordHash: "x", Root: true}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return NewManager(st, opts...), st
}

func issue(t *testing.T, m *Manager) *http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/login", nil)
	if _, err := m.Issue(context.Background(), rec, req, "u1"); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != CookieName {
		t.Fatalf("expected one session cookie, got %+v", cookies)
	}
	return cookies[0]
}

func requestWith(c *http.Cookie) *http.Request {
	req := httptest.NewRequest("GET", "/", nil)
	if c != nil {
		req.AddCookie(c)
	}
	return req
}

func TestIssueResolveRoundTrip(t *testing.T) {
	m, _ := setup(t)
	c := issue(t, m)
	if !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookie flags wrong: %+v", c)
	}
	sess, err := m.Resolve(context.Background(), requestWith(c))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if sess.UserID != "u1" {
		t.Fatalf("UserID = %q", sess.UserID)
	}
}

func TestResolveWithoutCookie(t *testing.T) {
	m, _ := setup(t)
	if _, err := m.Resolve(context.Background(), requestWith(nil)); !errors.Is(err, ErrNoSession) {
		t.Fatalf("want ErrNoSession, got %v", err)
	}
}

func TestResolveGarbageToken(t *testing.T) {
	m, _ := setup(t)
	c := &http.Cookie{Name: CookieName, Value: "forged"}
	if _, err := m.Resolve(context.Background(), requestWith(c)); !errors.Is(err, ErrNoSession) {
		t.Fatalf("want ErrNoSession, got %v", err)
	}
}

func TestExpiryBeatsCache(t *testing.T) {
	now := time.Now()
	clock := &now
	m, _ := setup(t,
		WithTTL(10*time.Minute),
		WithCacheTTL(time.Hour), // cache would happily serve stale — expiry must win
		WithClock(func() time.Time { return *clock }),
	)
	c := issue(t, m)
	if _, err := m.Resolve(context.Background(), requestWith(c)); err != nil {
		t.Fatalf("fresh session rejected: %v", err)
	}
	later := now.Add(11 * time.Minute)
	clock = &later
	if _, err := m.Resolve(context.Background(), requestWith(c)); !errors.Is(err, ErrNoSession) {
		t.Fatalf("expired session served: %v", err)
	}
}

func TestDestroyRevokesImmediately(t *testing.T) {
	m, _ := setup(t, WithCacheTTL(time.Hour))
	c := issue(t, m)
	if _, err := m.Resolve(context.Background(), requestWith(c)); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	rec := httptest.NewRecorder()
	if err := m.Destroy(context.Background(), rec, requestWith(c)); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	// Despite the 1h cache window, the eviction makes revocation immediate.
	if _, err := m.Resolve(context.Background(), requestWith(c)); !errors.Is(err, ErrNoSession) {
		t.Fatalf("revoked session still served: %v", err)
	}
	// And the cookie is cleared.
	cleared := rec.Result().Cookies()
	if len(cleared) != 1 || cleared[0].MaxAge != -1 {
		t.Fatalf("cookie not cleared: %+v", cleared)
	}
}

func TestPurgeExpired(t *testing.T) {
	now := time.Now()
	clock := &now
	m, st := setup(t, WithTTL(time.Minute), WithClock(func() time.Time { return *clock }))
	_ = issue(t, m)
	later := now.Add(2 * time.Minute)
	clock = &later
	n, err := m.PurgeExpired(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("PurgeExpired = %d, %v", n, err)
	}
	if n, _ := st.PurgeExpiredSessions(context.Background(), later.Unix()); n != 0 {
		t.Fatalf("second purge removed %d", n)
	}
}
