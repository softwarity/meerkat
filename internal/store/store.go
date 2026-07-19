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
  id           TEXT PRIMARY KEY,
  name         TEXT NOT NULL UNIQUE,
  ord          INTEGER NOT NULL DEFAULT 0,
  enabled      INTEGER NOT NULL DEFAULT 1,
  path_prefix  TEXT NOT NULL,
  strip_prefix INTEGER NOT NULL DEFAULT 0,
  upstream     TEXT NOT NULL,
  inject_head  TEXT NOT NULL DEFAULT ''
);`)
	if err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	return nil
}

// Route is a routing rule: match by path prefix, proxy to the upstream.
// This is the walking-skeleton shape — predicates, services and filters from
// the requirements will grow it.
type Route struct {
	ID          string
	Name        string
	Order       int
	Enabled     bool
	PathPrefix  string
	StripPrefix bool
	Upstream    string
	InjectHead  string
}

// ListRoutes returns every route ordered by ascending Order.
func (s *Store) ListRoutes(ctx context.Context) ([]Route, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, ord, enabled, path_prefix, strip_prefix, upstream, inject_head
		 FROM routes ORDER BY ord ASC, name ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: list routes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var routes []Route
	for rows.Next() {
		var r Route
		if err := rows.Scan(&r.ID, &r.Name, &r.Order, &r.Enabled, &r.PathPrefix,
			&r.StripPrefix, &r.Upstream, &r.InjectHead); err != nil {
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
		`INSERT INTO routes (id, name, ord, enabled, path_prefix, strip_prefix, upstream, inject_head)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		   name = excluded.name, ord = excluded.ord, enabled = excluded.enabled,
		   path_prefix = excluded.path_prefix, strip_prefix = excluded.strip_prefix,
		   upstream = excluded.upstream, inject_head = excluded.inject_head`,
		r.ID, r.Name, r.Order, r.Enabled, r.PathPrefix, r.StripPrefix, r.Upstream, r.InjectHead)
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
