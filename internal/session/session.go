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
	"sync"
	"time"

	"github.com/softwarity/meerkat/internal/store"
)

// CookieName is the session cookie set on the gateway's own host.
const CookieName = "MEERKAT_SESSION"

// ErrNoSession is returned when the request carries no valid session.
var ErrNoSession = errors.New("session: none")

// Manager issues, resolves and revokes sessions.
type Manager struct {
	st       *store.Store
	ttl      time.Duration // session lifetime
	cacheTTL time.Duration // how long a store read may be served from memory
	now      func() time.Time

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

// NewManager builds a Manager over the store.
func NewManager(st *store.Store, opts ...Option) *Manager {
	m := &Manager{
		st:       st,
		ttl:      30 * time.Minute,
		cacheTTL: 5 * time.Second,
		now:      time.Now,
		cache:    map[string]cacheEntry{},
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

// Issue creates a session for userID and sets the cookie on w. The returned
// token is the raw cookie value (only its hash is persisted).
func (m *Manager) Issue(ctx context.Context, w http.ResponseWriter, r *http.Request, userID string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	sess := store.Session{
		TokenHash: hashToken(token),
		UserID:    userID,
		ExpiresAt: m.now().Add(m.ttl).Unix(),
	}
	if err := m.st.CreateSession(ctx, sess); err != nil {
		return "", err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(m.ttl.Seconds()),
	})
	return token, nil
}

// Resolve returns the session carried by the request, or ErrNoSession. Reads
// are served from the memory cache within cacheTTL; expiry is always checked
// against the wall clock, so a cached session never outlives its TTL.
func (m *Manager) Resolve(ctx context.Context, r *http.Request) (store.Session, error) {
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" {
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
	if err != nil {
		m.remember(th, cacheEntry{invalid: true, readAt: now})
		return store.Session{}, ErrNoSession
	}
	m.remember(th, cacheEntry{sess: sess, readAt: now})
	if now.Unix() >= sess.ExpiresAt {
		return store.Session{}, ErrNoSession
	}
	return sess, nil
}

// Destroy revokes the request's session (if any), evicts it from the cache
// and clears the cookie. Revocation is immediate on this node; other nodes
// converge within cacheTTL (LISTEN/NOTIFY-style invalidation comes with the
// cluster backend).
func (m *Manager) Destroy(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	c, err := r.Cookie(CookieName)
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
		Name:     CookieName,
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
