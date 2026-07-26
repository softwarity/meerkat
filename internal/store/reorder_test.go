package store

import (
	"context"
	"reflect"
	"testing"
)

func TestReorderRoutes(t *testing.T) {
	s, ctx := rbacStore(t)
	for i, name := range []string{"a", "b", "c"} {
		if err := s.SaveRoute(ctx, Route{ID: name, Name: name, Order: i, Upstream: "http://x"}); err != nil {
			t.Fatalf("SaveRoute %s: %v", name, err)
		}
	}
	// ListRoutes is ordered by ord — initially insertion order.
	if got := routeIDs(ctx, t, s); !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Fatalf("initial order = %v", got)
	}

	if err := s.ReorderRoutes(ctx, []string{"c", "a", "b"}); err != nil {
		t.Fatalf("ReorderRoutes: %v", err)
	}
	if got := routeIDs(ctx, t, s); !reflect.DeepEqual(got, []string{"c", "a", "b"}) {
		t.Fatalf("after reorder order = %v, want [c a b]", got)
	}
}

func routeIDs(ctx context.Context, t *testing.T, s *Store) []string {
	t.Helper()
	routes, err := s.ListRoutes(ctx)
	if err != nil {
		t.Fatalf("ListRoutes: %v", err)
	}
	ids := make([]string, 0, len(routes))
	for _, r := range routes {
		ids = append(ids, r.ID)
	}
	return ids
}
