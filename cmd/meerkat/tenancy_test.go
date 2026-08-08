package main

import (
	"context"
	"strings"
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

// What an installation IS gets decided here, once, before it answers anything.
// The rule is not "the mode never changes" but "the mode never changes under
// data that would stop being visible": with one organisation the two shapes
// hold exactly the same thing, and only the vocabulary differs.
func TestSettleTenancy(t *testing.T) {
	ctx := context.Background()

	t.Run("single is the default and needs no license", func(t *testing.T) {
		t.Cleanup(features.Reset)
		st := openStore(t)
		if err := settleTenancy(ctx, st, store.TenancySingle); err != nil {
			t.Fatalf("single must always be available: %v", err)
		}
		if mode := st.Tenancy(ctx); mode != store.TenancySingle {
			t.Fatalf("recorded %q, want single", mode)
		}
	})

	t.Run("multi is refused without the feature, and names it", func(t *testing.T) {
		t.Cleanup(features.Reset)
		st := openStore(t)
		err := settleTenancy(ctx, st, store.TenancyMulti)
		if err == nil {
			t.Fatal("multi must be refused in the community edition")
		}
		if !strings.Contains(err.Error(), features.MultiTenant) {
			t.Fatalf("error = %q, want it to name the feature", err)
		}
		if mode := st.Tenancy(ctx); mode != store.TenancySingle {
			t.Fatalf("a refused boot must record nothing: %q", mode)
		}
	})

	t.Run("multi is settled and remembered", func(t *testing.T) {
		t.Cleanup(features.Reset)
		features.Enable(features.MultiTenant)
		st := openStore(t)
		if err := settleTenancy(ctx, st, store.TenancyMulti); err != nil {
			t.Fatal(err)
		}
		if mode := st.Tenancy(ctx); mode != store.TenancyMulti {
			t.Fatalf("recorded %q, want multi", mode)
		}
		// Booting the same way again is a no-op, not a second decision.
		if err := settleTenancy(ctx, st, store.TenancyMulti); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("back to single with one organisation is allowed", func(t *testing.T) {
		t.Cleanup(features.Reset)
		features.Enable(features.MultiTenant)
		st := openStore(t)
		if err := settleTenancy(ctx, st, store.TenancyMulti); err != nil {
			t.Fatal(err)
		}
		features.Reset() // the license is gone; the data is not
		if err := settleTenancy(ctx, st, store.TenancySingle); err != nil {
			t.Fatalf("nothing would be hidden, so nothing should refuse: %v", err)
		}
		if mode := st.Tenancy(ctx); mode != store.TenancySingle {
			t.Fatalf("recorded %q, want single", mode)
		}
	})

	t.Run("back to single with several organisations is refused", func(t *testing.T) {
		t.Cleanup(features.Reset)
		features.Enable(features.MultiTenant)
		st := openStore(t)
		if err := settleTenancy(ctx, st, store.TenancyMulti); err != nil {
			t.Fatal(err)
		}
		if err := st.SaveTenant(ctx, store.Tenant{ID: "acme", Name: "Acme", Enabled: true}); err != nil {
			t.Fatal(err)
		}
		err := settleTenancy(ctx, st, store.TenancySingle)
		if err == nil {
			t.Fatal("organisations would still exist with no screen naming them")
		}
		if !strings.Contains(err.Error(), "2 organisations") {
			t.Fatalf("error = %q, want it to say how many are in the way", err)
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
