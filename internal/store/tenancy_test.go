package store

import (
	"context"
	"testing"
)

// Every installation owns one organisation from its first boot, single mode or
// not. It is what lets groups, memberships and roles work unchanged while the
// console never says the word: there is no "no organisation" branch anywhere.
func TestDefaultTenantExistsOnAFreshDatabase(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	ctx := context.Background()

	tenants, err := s.ListTenants(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(tenants) != 1 || tenants[0].ID != DefaultTenantID {
		t.Fatalf("tenants = %+v, want exactly the default one", tenants)
	}
	if !tenants[0].Enabled {
		t.Fatal("the default organisation must be enabled: everything hangs off it")
	}
	if mode := s.Tenancy(ctx); mode != TenancySingle {
		t.Fatalf("tenancy = %q, want %q on a fresh install", mode, TenancySingle)
	}
}

// Reopening must not add a second one, nor rename the first: a boot is not a
// creation, and someone who renamed theirs keeps their name.
func TestDefaultTenantIsSeededOnce(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tenant, err := s.GetTenant(ctx, DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	tenant.Name = "Acme"
	if err := s.SaveTenant(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	again, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = again.Close() }()
	n, err := again.CountTenants(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("tenants after reopening = %d, want 1", n)
	}
	back, err := again.GetTenant(ctx, DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	if back.Name != "Acme" {
		t.Fatalf("name = %q, want the one it was given", back.Name)
	}
}

// CountTenants is what the boot checks before accepting single mode on a
// database that grew several organisations under a license.
func TestCountTenantsSeesTheSecondOne(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	ctx := context.Background()

	if err := s.SaveTenant(ctx, Tenant{ID: "acme", Name: "Acme", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	n, err := s.CountTenants(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("CountTenants = %d, want 2", n)
	}
}

// What single-tenant mode serves: the OLDEST organisation, never a hard-coded
// id. An installation that created its own has no "default", and picking by id
// would serve none of them - which is exactly the case of one that ran in
// multi and came back.
func TestPrimaryTenantIsTheOldest(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	ctx := context.Background()

	first, err := s.PrimaryTenant(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != DefaultTenantID {
		t.Fatalf("primary = %q, want the seeded one on a fresh install", first.ID)
	}

	// A younger one does not take over, whatever it is called.
	if err := s.SaveTenant(ctx, Tenant{ID: "aaa-acme", Name: "Acme", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	again, err := s.PrimaryTenant(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != first.ID {
		t.Fatalf("primary = %q, want it to stay %q", again.ID, first.ID)
	}
}

// The mode is a setting the console owns, switchable both ways at any time:
// it is read per request, so it takes effect at once and reverses as fast.
func TestSetTenancyBothWays(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	ctx := context.Background()

	if chosen, _ := s.TenancyWasChosen(ctx); chosen {
		t.Fatal("a fresh install has not chosen anything yet")
	}
	if err := s.SetTenancy(ctx, TenancyMulti); err != nil {
		t.Fatal(err)
	}
	if chosen, _ := s.TenancyWasChosen(ctx); !chosen {
		t.Fatal("the mode must be marked as chosen")
	}
	if mode := s.Tenancy(ctx); mode != TenancyMulti {
		t.Fatalf("tenancy = %q, want multi", mode)
	}
	// Back to single with several organisations: allowed, and it deletes
	// nothing - the others simply stop being served.
	if err := s.SaveTenant(ctx, Tenant{ID: "acme", Name: "Acme", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetTenancy(ctx, TenancySingle); err != nil {
		t.Fatalf("switching back must be allowed: %v", err)
	}
	if n, _ := s.CountTenants(ctx); n != 2 {
		t.Fatalf("tenants = %d, want both still there", n)
	}
	if err := s.SetTenancy(ctx, "mono"); err == nil {
		t.Fatal("an unknown mode must be refused")
	}
}
