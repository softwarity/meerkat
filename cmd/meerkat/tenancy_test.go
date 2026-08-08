package main

import (
	"context"
	"testing"

	"github.com/softwarity/meerkat/internal/features"
	"github.com/softwarity/meerkat/internal/store"
)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// The flag SEEDS the mode on a first boot and steps aside afterwards: the
// console owns it, because a mode read per request can be switched and undone
// in a click. Nothing here refuses to start - a gateway that will not boot
// because a flag disagrees with its database turns a configuration mistake
// into an outage.
func TestSettleTenancy(t *testing.T) {
	ctx := context.Background()

	t.Run("single is the default and needs no license", func(t *testing.T) {
		t.Cleanup(features.Reset)
		st := openStore(t)
		if err := settleTenancy(ctx, st, store.TenancySingle); err != nil {
			t.Fatal(err)
		}
		if mode := st.Tenancy(ctx); mode != store.TenancySingle {
			t.Fatalf("recorded %q, want single", mode)
		}
	})

	t.Run("multi without the feature starts single instead of refusing", func(t *testing.T) {
		t.Cleanup(features.Reset)
		st := openStore(t)
		if err := settleTenancy(ctx, st, store.TenancyMulti); err != nil {
			t.Fatalf("a gateway must start: %v", err)
		}
		if mode := st.Tenancy(ctx); mode != store.TenancySingle {
			t.Fatalf("recorded %q, want single", mode)
		}
	})

	t.Run("multi is seeded when the feature is there", func(t *testing.T) {
		t.Cleanup(features.Reset)
		features.Enable(features.MultiTenant)
		st := openStore(t)
		if err := settleTenancy(ctx, st, store.TenancyMulti); err != nil {
			t.Fatal(err)
		}
		if mode := st.Tenancy(ctx); mode != store.TenancyMulti {
			t.Fatalf("recorded %q, want multi", mode)
		}
	})

	t.Run("once chosen, the flag no longer decides", func(t *testing.T) {
		t.Cleanup(features.Reset)
		features.Enable(features.MultiTenant)
		st := openStore(t)
		// The console had the last word...
		if err := st.SetTenancy(ctx, store.TenancyMulti); err != nil {
			t.Fatal(err)
		}
		// ...and a compose file still says single. The database wins.
		if err := settleTenancy(ctx, st, store.TenancySingle); err != nil {
			t.Fatal(err)
		}
		if mode := st.Tenancy(ctx); mode != store.TenancyMulti {
			t.Fatalf("recorded %q: the flag must not override a chosen mode", mode)
		}
	})

	t.Run("an unknown mode is refused rather than guessed", func(t *testing.T) {
		t.Cleanup(features.Reset)
		st := openStore(t)
		if err := settleTenancy(ctx, st, "mono"); err == nil {
			t.Fatal("a typo must not silently fall back to a mode")
		}
	})
}
