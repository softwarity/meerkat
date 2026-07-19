package store

import (
	"context"
	"testing"
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
		ID: "r1", Name: "demo", Order: 2, Enabled: true,
		PathPrefix: "/demo", StripPrefix: true,
		Upstream: "https://example.com", InjectHead: "<script></script>",
	}
	if err := s.SaveRoute(ctx, want); err != nil {
		t.Fatalf("SaveRoute: %v", err)
	}
	if err := s.SaveRoute(ctx, Route{ID: "r0", Name: "first", Order: 1, Enabled: false, PathPrefix: "/a", Upstream: "http://a"}); err != nil {
		t.Fatalf("SaveRoute: %v", err)
	}

	routes, err := s.ListRoutes(ctx)
	if err != nil {
		t.Fatalf("ListRoutes: %v", err)
	}
	if len(routes) != 2 {
		t.Fatalf("got %d routes, want 2", len(routes))
	}
	if routes[0].Name != "first" || routes[1].Name != "demo" {
		t.Fatalf("wrong order: %q, %q", routes[0].Name, routes[1].Name)
	}
	if routes[1] != want {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", routes[1], want)
	}
}

func TestSaveRouteUpsertsByID(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	r := Route{ID: "r1", Name: "demo", PathPrefix: "/demo", Upstream: "http://a"}
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

	n, err := s.CountRoutes(ctx)
	if err != nil || n != 0 {
		t.Fatalf("CountRoutes empty = %d, %v", n, err)
	}
	if err := s.SaveRoute(ctx, Route{ID: "r1", Name: "demo", PathPrefix: "/", Upstream: "http://a"}); err != nil {
		t.Fatalf("SaveRoute: %v", err)
	}
	if n, err = s.CountRoutes(ctx); err != nil || n != 1 {
		t.Fatalf("CountRoutes = %d, %v", n, err)
	}
}
