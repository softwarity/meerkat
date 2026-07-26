// Package session implements Meerkat's web sessions, as decided in the
// requirements (Q6): an opaque httpOnly cookie whose state lives in the
// store — revocation is immediate — fronted by a small in-memory cache so
// the hot path does not pay a database read on every request. JWTs are for
// the API path and upstream propagation, never for the browser.
package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/softwarity/meerkat/internal/store"
)

// Cookie names, one per plane: cookies are NOT port-scoped, so on a same-host
// deployment the two ports would otherwise share the browser's session.
const (
	CookieName      = "MEERKAT_SESSION"       // data plane
	AdminCookieName = "MEERKAT_ADMIN_SESSION" // control plane
)

// Planes stamped on every stored session — Resolve refuses a token from the
// other plane even if someone copies the cookie across.
const (
	DataPlane  = "data"
	AdminPlane = "admin"
)

// ErrNoSession is returned when the request carries no valid session.
var ErrNoSession = errors.New("session: none")

// Manager issues, resolves and revokes sessions for ONE plane.
type Manager struct {
	st         *store.Store
	ttl        time.Duration // session lifetime
	cacheTTL   time.Duration // how long a store read may be served from memory
	now        func() time.Time
	cookieName string
	plane      string

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	sess    store.Session
	readAt  time.Time
	invalid bool // negative cache: known-absent token
}

// Option tweaks a Manager (tests mostly).
type Option func(*Manager)

// WithTTL sets the session lifetime (default 30m — the V1 default).
func WithTTL(d time.Duration) Option { return func(m *Manager) { m.ttl = d } }

// WithCacheTTL sets the memory-cache window (default 5s).
func WithCacheTTL(d time.Duration) Option { return func(m *Manager) { m.cacheTTL = d } }

// WithClock overrides time.Now (tests).
func WithClock(now func() time.Time) Option { return func(m *Manager) { m.now = now } }

// ForAdminPlane scopes the manager to the control plane: its own cookie name
// and its own session plane — the two ports never share a browser session.
func ForAdminPlane() Option {
	return func(m *Manager) { m.cookieName, m.plane = AdminCookieName, AdminPlane }
}

// NewManager builds a Manager over the store.
func NewManager(st *store.Store, opts ...Option) *Manager {
	m := &Manager{
		st:         st,
		ttl:        30 * time.Minute,
		cacheTTL:   5 * time.Second,
		now:        time.Now,
		cookieName: CookieName,
		plane:      DataPlane,
		cache:      map[string]cacheEntry{},
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

// Issue creates a session for userID with the manager's default TTL and no
// active tenant, and sets the cookie on w.
func (m *Manager) Issue(ctx context.Context, w http.ResponseWriter, r *http.Request, userID string) (string, error) {
	return m.IssueWith(ctx, w, r, userID, "", "", m.ttl, "", "")
}

// IssueWith creates a session with an explicit active tenant and lifetime —
// the login flow passes the RESOLVED TTL (membership → tenant → global,
// TENANT-05). The returned token is the raw cookie value (only its hash is
// persisted).
func (m *Manager) IssueWith(ctx context.Context, w http.ResponseWriter, r *http.Request, userID, tenantID, groupID string, ttl time.Duration, pending, next string) (string, error) {
	if ttl <= 0 {
		ttl = m.ttl
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	sess := store.Session{
		TokenHash: hashToken(token),
		UserID:    userID,
		TenantID:  tenantID,
		GroupID:   groupID,
		Pending:   pending,
		Next:      next,
		ExpiresAt: m.now().Add(ttl).Unix(),
		Plane:     m.plane,
	}
	if err := m.st.CreateSession(ctx, sess); err != nil {
		return "", err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	})
	return token, nil
}

// ClearPending marks the request's session as done with its current
// login-flow step (AUTH-05) and refreshes the cache.
func (m *Manager) ClearPending(ctx context.Context, r *http.Request) error {
	return m.SetPending(ctx, r, "")
}

// SetPending advances the request's session to the next login-flow step
// (AUTH-05) — e.g. from the password step to the MFA step — without issuing a
// new session. "" clears the step (flow complete). Refreshes the cache.
func (m *Manager) SetPending(ctx context.Context, r *http.Request, step string) error {
	c, err := r.Cookie(m.cookieName)
	if err != nil || c.Value == "" {
		return ErrNoSession
	}
	th := hashToken(c.Value)
	if err := m.st.SetSessionPending(ctx, th, step); err != nil {
		return err
	}
	m.mu.Lock()
	delete(m.cache, th)
	m.mu.Unlock()
	return nil
}

// SetTenant records the active tenant on the request's session (the
// select-tenant step — TENANT-03) and refreshes the cache.
func (m *Manager) SetTenant(ctx context.Context, r *http.Request, tenantID string) error {
	c, err := r.Cookie(m.cookieName)
	if err != nil || c.Value == "" {
		return ErrNoSession
	}
	th := hashToken(c.Value)
	if err := m.st.SetSessionTenant(ctx, th, tenantID); err != nil {
		return err
	}
	m.mu.Lock()
	delete(m.cache, th)
	m.mu.Unlock()
	return nil
}

// SetGroup records the ACTIVE group on the request's session (the
// select-group step, exclusive mode — RBAC-03) and refreshes the cache.
func (m *Manager) SetGroup(ctx context.Context, r *http.Request, groupID string) error {
	c, err := r.Cookie(m.cookieName)
	if err != nil || c.Value == "" {
		return ErrNoSession
	}
	th := hashToken(c.Value)
	if err := m.st.SetSessionGroup(ctx, th, groupID); err != nil {
		return err
	}
	m.mu.Lock()
	delete(m.cache, th)
	m.mu.Unlock()
	return nil
}

// Resolve returns the session carried by the request, or ErrNoSession. Reads
// are served from the memory cache within cacheTTL; expiry is always checked
// against the wall clock, so a cached session never outlives its TTL.
func (m *Manager) Resolve(ctx context.Context, r *http.Request) (store.Session, error) {
	c, err := r.Cookie(m.cookieName)
	if err != nil || c.Value == "" {
		// No browser session: an API token may authenticate (AUTH-16), but only
		// one scoped to THIS plane — a data token never opens the admin port and
		// an admin (control-plane) token never opens the data port.
		if sess, ok := m.resolveToken(ctx, r); ok {
			return sess, nil
		}
		return store.Session{}, ErrNoSession
	}
	th := hashToken(c.Value)
	now := m.now()

	m.mu.Lock()
	entry, hit := m.cache[th]
	m.mu.Unlock()
	if hit && now.Sub(entry.readAt) < m.cacheTTL {
		if entry.invalid || now.Unix() >= entry.sess.ExpiresAt {
			return store.Session{}, ErrNoSession
		}
		return entry.sess, nil
	}

	sess, err := m.st.GetSession(ctx, th)
	if err != nil || sess.Plane != m.plane {
		// Unknown token OR a token from the other plane (a copied cookie):
		// both answer exactly "no session".
		m.remember(th, cacheEntry{invalid: true, readAt: now})
		return store.Session{}, ErrNoSession
	}
	m.remember(th, cacheEntry{sess: sess, readAt: now})
	if now.Unix() >= sess.ExpiresAt {
		return store.Session{}, ErrNoSession
	}
	return sess, nil
}

// apiTokenPrefix marks Meerkat personal access tokens — greppable in logs,
// detectable by secret scanners, distinct from a session cookie value.
const apiTokenPrefix = "mk_"

// resolveToken authenticates an "Authorization: Bearer mk_…" request against
// a live API token, synthesizing the session context the token captured
// (tenant + group). NOT cached: a revoke or disable takes effect on the very
// next request. The user is re-checked live so a disabled account's tokens
// stop at once.
func (m *Manager) resolveToken(ctx context.Context, r *http.Request) (store.Session, bool) {
	auth := r.Header.Get("Authorization")
	const bearer = "Bearer "
	if !strings.HasPrefix(auth, bearer) {
		return store.Session{}, false
	}
	raw := strings.TrimSpace(auth[len(bearer):])
	if !strings.HasPrefix(raw, apiTokenPrefix) {
		return store.Session{}, false
	}
	now := m.now()
	tok, err := m.st.ResolveAPIToken(ctx, hashToken(raw), now.Unix())
	if err != nil {
		return store.Session{}, false
	}
	// A token authenticates ONLY on its own plane — this is the isolation
	// between the data port and the admin port.
	if tok.Plane != m.plane {
		return store.Session{}, false
	}
	// The gateway-wide personal-token policy (AUTH-16) gates DATA tokens only;
	// admin (control-plane) tokens are a root capability, not that policy's.
	if m.plane == DataPlane && !m.st.APITokensAllowed(ctx) {
		return store.Session{}, false
	}
	u, err := m.st.GetUserByID(ctx, tok.UserID)
	if err != nil || !u.Enabled {
		return store.Session{}, false
	}
	// Last-use stamp, throttled to at most once a minute (avoid a write per
	// request); best-effort, a failure never blocks the call.
	if now.Unix()-tok.LastUsedAt >= 60 {
		_ = m.st.TouchAPIToken(ctx, tok.ID, now.Unix())
	}
	return store.Session{
		UserID: tok.UserID, TenantID: tok.TenantID, GroupID: tok.GroupID,
		Plane: m.plane, ExpiresAt: now.Add(m.ttl).Unix(),
	}, true
}

// Destroy revokes the request's session (if any), evicts it from the cache
// and clears the cookie. Revocation is immediate on this node; other nodes
// converge within cacheTTL (LISTEN/NOTIFY-style invalidation comes with the
// cluster backend).
func (m *Manager) Destroy(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	c, err := r.Cookie(m.cookieName)
	if err == nil && c.Value != "" {
		th := hashToken(c.Value)
		if err := m.st.DeleteSession(ctx, th); err != nil {
			return err
		}
		m.mu.Lock()
		delete(m.cache, th)
		m.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	return nil
}

// PurgeExpired removes expired sessions from the store (periodic upkeep).
func (m *Manager) PurgeExpired(ctx context.Context) (int64, error) {
	return m.st.PurgeExpiredSessions(ctx, m.now().Unix())
}

func (m *Manager) remember(th string, e cacheEntry) {
	m.mu.Lock()
	m.cache[th] = e
	m.mu.Unlock()
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
