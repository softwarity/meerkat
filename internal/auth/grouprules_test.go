package auth

import (
	"context"
	"sort"
	"testing"

	"github.com/softwarity/meerkat/internal/idp"
	"github.com/softwarity/meerkat/internal/store"
)

// The case these rules exist for, in François's own words: an application
// managing stations across French coastal ports. One directory for the whole
// organisation, one tenant per port, and someone who works for two ports has
// to end up a member of both - then pick which one they are working in.

func ports(t *testing.T) (*Handler, *store.Store, store.AuthProvider) {
	t.Helper()
	h, st := externalFixture(t)
	ctx := context.Background()
	for _, id := range []string{"brest", "sete", "lorient"} {
		if err := st.SaveTenant(ctx, store.Tenant{ID: id, Name: id, Enabled: true}); err != nil {
			t.Fatal(err)
		}
		if err := st.SaveGroup(ctx, store.Group{ID: id + "-agents", TenantID: id, Name: "Agents"}); err != nil {
			t.Fatal(err)
		}
	}
	p, err := st.GetAuthProvider(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	return h, st, p
}

func rule(t *testing.T, st *store.Store, id, tenant, external, group string) {
	t.Helper()
	if err := st.SaveGroupRule(context.Background(), store.GroupRule{
		ID: id, TenantID: tenant, External: external, GroupID: group,
	}); err != nil {
		t.Fatal(err)
	}
}

func tenantsOf(t *testing.T, st *store.Store, userID string) []string {
	t.Helper()
	ts, err := st.ListUserTenants(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.TenantID)
	}
	sort.Strings(out)
	return out
}

func TestPortsGetTheirPeopleFromTheDirectory(t *testing.T) {
	h, st, p := ports(t)
	ctx := context.Background()
	rule(t, st, "r-brest", "brest", "cn=brest-agents", "brest-agents")
	rule(t, st, "r-sete", "sete", "cn=sete-agents", "sete-agents")

	// Someone who works for two ports signs in.
	id := idp.Identity{Subject: "sub-1", Username: "jdoe",
		Groups: []string{"cn=brest-agents", "cn=sete-agents"}}
	user, _, err := h.linkOrCreate(ctx, p, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SyncMappedGroups(ctx, user.ID, p.ID, id.Groups); err != nil {
		t.Fatal(err)
	}
	if got := tenantsOf(t, st, user.ID); len(got) != 2 || got[0] != "brest" || got[1] != "sete" {
		t.Fatalf("both ports expected, got %v", got)
	}
	// And the group INSIDE each port, which is what says what they may do there.
	for _, port := range []string{"brest", "sete"} {
		groups, err := st.MemberGroups(ctx, port, user.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(groups) != 1 || groups[0].Name != "Agents" {
			t.Fatalf("%s: %v", port, groups)
		}
	}

	// They leave Sète upstream. The next sign-in takes it back: a rule that
	// stopped applying has to stop granting, or nothing upstream ever revokes.
	left := []string{"cn=brest-agents"}
	if _, err := st.SyncMappedGroups(ctx, user.ID, p.ID, left); err != nil {
		t.Fatal(err)
	}
	if got := tenantsOf(t, st, user.ID); len(got) != 1 || got[0] != "brest" {
		t.Fatalf("Sète should be gone, got %v", got)
	}
	if groups, _ := st.MemberGroups(ctx, "sete", user.ID); len(groups) != 0 {
		t.Fatalf("the groups go with the membership, got %v", groups)
	}
}

// TestHandPlacedMembershipSurvivesTheRules is the other half of the deal: an
// administrator's decision is never undone by a synchronisation, or nobody
// could ever place someone the directory does not know about.
func TestHandPlacedMembershipSurvivesTheRules(t *testing.T) {
	h, st, p := ports(t)
	ctx := context.Background()
	rule(t, st, "r-brest", "brest", "cn=brest-agents", "brest-agents")

	id := idp.Identity{Subject: "sub-1", Username: "jdoe", Groups: []string{"cn=brest-agents"}}
	user, _, err := h.linkOrCreate(ctx, p, id)
	if err != nil {
		t.Fatal(err)
	}
	// An admin places them in a third port by hand, with its group.
	if err := st.SaveMembership(ctx, store.Membership{
		UserID: user.ID, TenantID: "lorient", Type: "USER", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetMemberGroups(ctx, "lorient", user.ID, []string{"lorient-agents"}); err != nil {
		t.Fatal(err)
	}

	// A sign-in that grants Brest must leave Lorient exactly as it was, even
	// though no rule mentions it.
	if _, err := st.SyncMappedGroups(ctx, user.ID, p.ID, id.Groups); err != nil {
		t.Fatal(err)
	}
	if got := tenantsOf(t, st, user.ID); len(got) != 2 || got[0] != "brest" || got[1] != "lorient" {
		t.Fatalf("the hand-placed port must survive, got %v", got)
	}
	if groups, _ := st.MemberGroups(ctx, "lorient", user.ID); len(groups) != 1 {
		t.Fatalf("its groups too, got %v", groups)
	}
	// And an admin editing the groups of a mapped port does not wipe what the
	// rule granted: it would simply come back at the next sign-in.
	if err := st.SetMemberGroups(ctx, "brest", user.ID, nil); err != nil {
		t.Fatal(err)
	}
	if groups, _ := st.MemberGroups(ctx, "brest", user.ID); len(groups) != 1 {
		t.Fatalf("a rule's group is not the admin's to remove here, got %v", groups)
	}
}

// TestOneDirectoryPerPort covers the other shape François described: rather
// than per-port groups in one directory, each port brings its own authority.
// Same mechanism - a rule with no group name means "anyone from here".
func TestOneDirectoryPerPort(t *testing.T) {
	h, st, p := ports(t)
	ctx := context.Background()
	if err := st.SaveGroupRule(ctx, store.GroupRule{
		ID: "r-any", TenantID: "brest", ProviderID: p.ID, GroupID: "brest-agents",
	}); err != nil {
		t.Fatal(err)
	}
	// No group reported at all, and it still works: the authority IS the
	// discriminant.
	id := idp.Identity{Subject: "sub-2", Username: "mdupont"}
	user, _, err := h.linkOrCreate(ctx, p, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SyncMappedGroups(ctx, user.ID, p.ID, nil); err != nil {
		t.Fatal(err)
	}
	if got := tenantsOf(t, st, user.ID); len(got) != 1 || got[0] != "brest" {
		t.Fatalf("the authority alone should place them, got %v", got)
	}
	// Someone arriving through ANOTHER authority is not concerned.
	if _, err := st.SyncMappedGroups(ctx, user.ID, "other-idp", nil); err != nil {
		t.Fatal(err)
	}
	if got := tenantsOf(t, st, user.ID); len(got) != 0 {
		t.Fatalf("another authority grants nothing here, got %v", got)
	}
}

// TestARuleMatchingEverythingIsRefused: a rule with neither an authority nor a
// group name would hand the tenant to anyone the gateway ever authenticates,
// including through an authority added later for something else.
func TestARuleMatchingEverythingIsRefused(t *testing.T) {
	_, st, _ := ports(t)
	err := st.SaveGroupRule(context.Background(), store.GroupRule{
		ID: "r-all", TenantID: "brest", GroupID: "brest-agents",
	})
	if err == nil {
		t.Fatal("a rule matching every authority and every group must be refused")
	}
}
