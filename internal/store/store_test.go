package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/softwarity/meerkat/internal/routing"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSaveListRoundTrip(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	want := Route{
		ID: "r1", Name: "demo", Order: 2, Enabled: true, Authenticated: true,
		Upstream: "https://example.com",
		Predicates: []routing.Spec{
			{Type: "path", Args: map[string]any{"patterns": []any{"/demo/**"}}},
			{Type: "method", Args: map[string]any{"methods": []any{"GET"}}},
		},
		Filters: []routing.Spec{
			{Type: "strip-prefix", Args: map[string]any{"parts": float64(1)}},
		},
	}
	if err := s.SaveRoute(ctx, want); err != nil {
		t.Fatalf("SaveRoute: %v", err)
	}
	if err := s.SaveRoute(ctx, Route{ID: "r0", Name: "first", Order: 1, Upstream: "http://a"}); err != nil {
		t.Fatalf("SaveRoute: %v", err)
	}

	routes, err := s.ListRoutes(ctx)
	if err != nil {
		t.Fatalf("ListRoutes: %v", err)
	}
	if len(routes) != 2 || routes[0].Name != "first" || routes[1].Name != "demo" {
		t.Fatalf("wrong list: %+v", routes)
	}
	got := routes[1]
	if !reflect.DeepEqual(got.Predicates, want.Predicates) || !reflect.DeepEqual(got.Filters, want.Filters) {
		t.Fatalf("specs round trip mismatch:\n got %+v\nwant %+v", got, want)
	}
	if got.Filters[0].Args["parts"] != float64(1) {
		t.Fatalf("numeric arg lost: %+v", got.Filters[0].Args)
	}
}

func TestSaveRouteUpsertsByID(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	r := Route{ID: "r1", Name: "demo", Upstream: "http://a"}
	if err := s.SaveRoute(ctx, r); err != nil {
		t.Fatalf("SaveRoute: %v", err)
	}
	r.Upstream = "http://b"
	if err := s.SaveRoute(ctx, r); err != nil {
		t.Fatalf("SaveRoute (update): %v", err)
	}
	routes, err := s.ListRoutes(ctx)
	if err != nil {
		t.Fatalf("ListRoutes: %v", err)
	}
	if len(routes) != 1 || routes[0].Upstream != "http://b" {
		t.Fatalf("upsert failed: %+v", routes)
	}
}

func TestCountRoutes(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	if n, err := s.CountRoutes(ctx); err != nil || n != 0 {
		t.Fatalf("CountRoutes empty = %d, %v", n, err)
	}
	if err := s.SaveRoute(ctx, Route{ID: "r1", Name: "demo", Upstream: "http://a"}); err != nil {
		t.Fatalf("SaveRoute: %v", err)
	}
	if n, err := s.CountRoutes(ctx); err != nil || n != 1 {
		t.Fatalf("CountRoutes = %d, %v", n, err)
	}
}

// TestMigratesWalkingSkeletonSchema opens a database created by the
// pre-versioning skeleton and checks its routes come out converted to the
// declarative model (DEPLOY-06: upgrades without intervention).
func TestMigratesWalkingSkeletonSchema(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "meerkat.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
CREATE TABLE routes (
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
INSERT INTO routes VALUES
  ('demo', 'demo', 100, 1, '/demo', 1, 'https://httpbin.org', '<script>x</script>', 0),
  ('sec',  'sec',  101, 1, '/secure', 0, 'https://httpbin.org', '', 1);`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open (migrating): %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	routes, err := s.ListRoutes(context.Background())
	if err != nil {
		t.Fatalf("ListRoutes: %v", err)
	}
	if len(routes) != 2 {
		t.Fatalf("got %d routes, want 2", len(routes))
	}
	demo := routes[0]
	if demo.Name != "demo" ||
		demo.Predicates[0].Type != "path" ||
		demo.Filters[0].Type != "strip-prefix" ||
		demo.Filters[1].Type != "inject-head" {
		t.Fatalf("demo not converted: %+v", demo)
	}
	pats := demo.Predicates[0].Args["patterns"].([]any)
	if len(pats) != 1 || pats[0] != "/demo/**" {
		t.Fatalf("pattern = %v", pats)
	}
	sec := routes[1]
	if !sec.Authenticated || len(sec.Filters) != 0 {
		t.Fatalf("sec not converted: %+v", sec)
	}

	// Reopening must be a no-op (idempotent migration).
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	t.Cleanup(func() { _ = s2.Close() })
	if again, err := s2.ListRoutes(context.Background()); err != nil || len(again) != 2 {
		t.Fatalf("after reopen: %d routes, %v", len(again), err)
	}
}
