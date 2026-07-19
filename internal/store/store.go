// Package store is Meerkat's embedded storage: a single SQLite file, pure Go
// (no CGO), transactional. It is the zero-dependency default backend; an
// external database backend (for clustering) will plug behind the same
// interface later.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"

	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

// Store wraps the embedded database.
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the embedded database inside dataDir and
// applies migrations.
func Open(dataDir string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)",
		filepath.Join(dataDir, "meerkat.db"))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	// SQLite serializes writers; a single connection avoids SQLITE_BUSY storms
	// while the skeleton has no connection-pool needs.
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the underlying database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS routes (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL UNIQUE,
  ord           INTEGER NOT NULL DEFAULT 0,
  enabled       INTEGER NOT NULL DEFAULT 1,
  path_prefix   TEXT NOT NULL,
  strip_prefix  INTEGER NOT NULL DEFAULT 0,
  upstream      TEXT NOT NULL,
  inject_head   TEXT NOT NULL DEFAULT '',
  authenticated INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  username      TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  root          INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_expires ON sessions(expires_at);`)
	if err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	return nil
}

// Route is a routing rule: match by path prefix, proxy to the upstream.
// This is the walking-skeleton shape — predicates, services and filters from
// the requirements will grow it.
type Route struct {
	ID            string
	Name          string
	Order         int
	Enabled       bool
	PathPrefix    string
	StripPrefix   bool
	Upstream      string
	InjectHead    string
	Authenticated bool
}

// ListRoutes returns every route ordered by ascending Order.
func (s *Store) ListRoutes(ctx context.Context) ([]Route, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, ord, enabled, path_prefix, strip_prefix, upstream, inject_head, authenticated
		 FROM routes ORDER BY ord ASC, name ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: list routes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var routes []Route
	for rows.Next() {
		var r Route
		if err := rows.Scan(&r.ID, &r.Name, &r.Order, &r.Enabled, &r.PathPrefix,
			&r.StripPrefix, &r.Upstream, &r.InjectHead, &r.Authenticated); err != nil {
			return nil, fmt.Errorf("store: scan route: %w", err)
		}
		routes = append(routes, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list routes: %w", err)
	}
	return routes, nil
}

// SaveRoute inserts or replaces a route by ID.
func (s *Store) SaveRoute(ctx context.Context, r Route) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO routes (id, name, ord, enabled, path_prefix, strip_prefix, upstream, inject_head, authenticated)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		   name = excluded.name, ord = excluded.ord, enabled = excluded.enabled,
		   path_prefix = excluded.path_prefix, strip_prefix = excluded.strip_prefix,
		   upstream = excluded.upstream, inject_head = excluded.inject_head,
		   authenticated = excluded.authenticated`,
		r.ID, r.Name, r.Order, r.Enabled, r.PathPrefix, r.StripPrefix, r.Upstream, r.InjectHead, r.Authenticated)
	if err != nil {
		return fmt.Errorf("store: save route %q: %w", r.Name, err)
	}
	return nil
}

// CountRoutes reports how many routes exist (seed decision at first start).
func (s *Store) CountRoutes(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM routes`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count routes: %w", err)
	}
	return n, nil
}

// User is a local Meerkat account (the nominal identity model — §1.3 of the
// requirements). Password is stored as a bcrypt hash, never in clear.
type User struct {
	ID           string
	Username     string
	PasswordHash string
	Root         bool
}

// CreateUser inserts a new user.
func (s *Store) CreateUser(ctx context.Context, u User) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO users (id, username, password_hash, root) VALUES (?, ?, ?, ?)`,
		u.ID, u.Username, u.PasswordHash, u.Root)
	if err != nil {
		return fmt.Errorf("store: create user %q: %w", u.Username, err)
	}
	return nil
}

// GetUserByUsername returns the user or sql.ErrNoRows wrapped.
func (s *Store) GetUserByUsername(ctx context.Context, username string) (User, error) {
	var u User
	err := s.db.QueryRowContext(ctx,
		`SELECT id, username, password_hash, root FROM users WHERE username = ?`, username).
		Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Root)
	if err != nil {
		return User{}, fmt.Errorf("store: get user %q: %w", username, err)
	}
	return u, nil
}

// CountUsers reports how many users exist (admin seed decision).
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count users: %w", err)
	}
	return n, nil
}

// Session is the persisted server-side state behind an opaque cookie. Only a
// hash of the token is stored — a database leak reveals no usable cookies.
type Session struct {
	TokenHash string
	UserID    string
	ExpiresAt int64 // unix seconds
}

// CreateSession persists a session.
func (s *Store) CreateSession(ctx context.Context, sess Session) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)`,
		sess.TokenHash, sess.UserID, sess.ExpiresAt)
	if err != nil {
		return fmt.Errorf("store: create session: %w", err)
	}
	return nil
}

// GetSession returns the session for a token hash, or an error wrapping
// sql.ErrNoRows when absent (revoked or never issued).
func (s *Store) GetSession(ctx context.Context, tokenHash string) (Session, error) {
	var sess Session
	err := s.db.QueryRowContext(ctx,
		`SELECT token_hash, user_id, expires_at FROM sessions WHERE token_hash = ?`, tokenHash).
		Scan(&sess.TokenHash, &sess.UserID, &sess.ExpiresAt)
	if err != nil {
		return Session{}, fmt.Errorf("store: get session: %w", err)
	}
	return sess, nil
}

// DeleteSession revokes a single session. Deleting an absent session is not
// an error.
func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash); err != nil {
		return fmt.Errorf("store: delete session: %w", err)
	}
	return nil
}

// PurgeExpiredSessions removes every session past its expiry (TTL upkeep,
// STORE-04) and reports how many were removed.
func (s *Store) PurgeExpiredSessions(ctx context.Context, now int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`, now)
	if err != nil {
		return 0, fmt.Errorf("store: purge sessions: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
