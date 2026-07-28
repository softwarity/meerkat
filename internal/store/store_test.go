package store

import (
	"context"
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
		ID: "r1", Name: "demo", Order: 2, Enabled: true, Access: Access{Authenticated: true},
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
