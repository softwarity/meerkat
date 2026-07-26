package store

import (
	"context"
	"reflect"
	"testing"
)

func rbacStore(t *testing.T) (*Store, context.Context) {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, context.Background()
}

// admin ⊃ editor ⊃ viewer: holding a role grants it and every descendant.
func seedHierarchy(ctx context.Context, t *testing.T, s *Store) {
	t.Helper()
	for _, r := range []Role{
		{ID: "admin", Name: "admin"},
		{ID: "editor", Name: "editor", ParentID: "admin"},
		{ID: "viewer", Name: "viewer", ParentID: "editor"},
	} {
		if err := s.SaveRole(ctx, r); err != nil {
			t.Fatalf("SaveRole %s: %v", r.ID, err)
		}
	}
}

func TestEffectiveRolesClosure(t *testing.T) {
	s, ctx := rbacStore(t)
	seedHierarchy(ctx, t, s)
	if err := s.SaveTenant(ctx, Tenant{ID: "t1", Name: "acme", Enabled: true}); err != nil {
		t.Fatalf("SaveTenant: %v", err)
	}
	// A group granting "editor" must resolve to editor + viewer (its descendant),
	// not admin (its ancestor).
	if err := s.SaveGroup(ctx, Group{ID: "g1", TenantID: "t1", Name: "staff", RoleIDs: []string{"editor"}}); err != nil {
		t.Fatalf("SaveGroup: %v", err)
	}
	got, err := s.EffectiveRoleNames(ctx, []string{"g1"})
	if err != nil {
		t.Fatalf("EffectiveRoleNames: %v", err)
	}
	if want := []string{"editor", "viewer"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("effective roles = %v, want %v", got, want)
	}
	// "admin" pulls the whole chain.
	if err := s.SaveGroup(ctx, Group{ID: "g2", TenantID: "t1", Name: "ops", RoleIDs: []string{"admin"}}); err != nil {
		t.Fatalf("SaveGroup: %v", err)
	}
	got, _ = s.EffectiveRoleNames(ctx, []string{"g2"})
	if want := []string{"admin", "editor", "viewer"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("effective roles = %v, want %v", got, want)
	}
}

func TestRoleCycleRejected(t *testing.T) {
	s, ctx := rbacStore(t)
	seedHierarchy(ctx, t, s)
	// admin is viewer's ancestor → making admin a child of viewer is a cycle.
	err := s.SaveRole(ctx, Role{ID: "admin", Name: "admin", ParentID: "viewer"})
	if err == nil {
		t.Fatal("expected a cycle error, got nil")
	}
	// Self-parenting is also rejected.
	if err := s.SaveRole(ctx, Role{ID: "editor", Name: "editor", ParentID: "editor"}); err == nil {
		t.Fatal("expected self-parent to be rejected")
	}
}

func TestSystemRoleProtected(t *testing.T) {
	s, ctx := rbacStore(t)
	if err := s.SaveRole(ctx, Role{ID: "sys", Name: "authenticated", System: true}); err != nil {
		t.Fatalf("SaveRole: %v", err)
	}
	if _, err := s.DeleteRole(ctx, "sys"); err == nil {
		t.Fatal("expected system role deletion to be refused")
	}
	if _, err := s.GetRole(ctx, "sys"); err != nil {
		t.Fatalf("system role should still exist: %v", err)
	}
}

func TestDeletedRoleReparentsChildren(t *testing.T) {
	s, ctx := rbacStore(t)
	seedHierarchy(ctx, t, s)
	if _, err := s.DeleteRole(ctx, "editor"); err != nil {
		t.Fatalf("DeleteRole: %v", err)
	}
	// viewer survives, promoted to the top level (ON DELETE SET NULL).
	v, err := s.GetRole(ctx, "viewer")
	if err != nil {
		t.Fatalf("GetRole viewer: %v", err)
	}
	if v.ParentID != "" {
		t.Fatalf("viewer should be top-level after its parent is deleted, got parent %q", v.ParentID)
	}
}

func TestMemberGroupsPerTenant(t *testing.T) {
	s, ctx := rbacStore(t)
	seedHierarchy(ctx, t, s)
	if err := s.CreateUser(ctx, User{ID: "u1", Username: "alice", PasswordHash: "h", Enabled: true}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	for _, id := range []string{"t1", "t2"} {
		if err := s.SaveTenant(ctx, Tenant{ID: id, Name: id, Enabled: true}); err != nil {
			t.Fatalf("SaveTenant %s: %v", id, err)
		}
	}
	// Different groups (hence different roles) per tenant for the same user.
	if err := s.SaveGroup(ctx, Group{ID: "g-t1", TenantID: "t1", Name: "admins", RoleIDs: []string{"admin"}}); err != nil {
		t.Fatalf("SaveGroup t1: %v", err)
	}
	if err := s.SaveGroup(ctx, Group{ID: "g-t2", TenantID: "t2", Name: "readers", RoleIDs: []string{"viewer"}}); err != nil {
		t.Fatalf("SaveGroup t2: %v", err)
	}
	if err := s.SetMemberGroups(ctx, "t1", "u1", []string{"g-t1"}); err != nil {
		t.Fatalf("SetMemberGroups t1: %v", err)
	}
	if err := s.SetMemberGroups(ctx, "t2", "u1", []string{"g-t2"}); err != nil {
		t.Fatalf("SetMemberGroups t2: %v", err)
	}

	g1, _ := s.MemberGroupIDs(ctx, "t1", "u1")
	r1, _ := s.EffectiveRoleNames(ctx, g1)
	if want := []string{"admin", "editor", "viewer"}; !reflect.DeepEqual(r1, want) {
		t.Fatalf("t1 roles = %v, want %v", r1, want)
	}
	g2, _ := s.MemberGroupIDs(ctx, "t2", "u1")
	r2, _ := s.EffectiveRoleNames(ctx, g2)
	if want := []string{"viewer"}; !reflect.DeepEqual(r2, want) {
		t.Fatalf("t2 roles = %v, want %v", r2, want)
	}
}

func TestGroupModePerTenant(t *testing.T) {
	s, ctx := rbacStore(t)
	if err := s.SaveTenant(ctx, Tenant{ID: "t1", Name: "acme", Enabled: true}); err != nil {
		t.Fatalf("SaveTenant: %v", err)
	}
	// Tri-state: an unset tenant mode INHERITS the gateway-wide setting
	// (defaulting to cumulative).
	if m, _ := s.GetGroupMode(ctx, "t1"); m != "" {
		t.Fatalf("default group mode = %q, want empty (inherit)", m)
	}
	if m := s.EffectiveGroupMode(ctx, "t1"); m != GroupModeMultiple {
		t.Fatalf("effective default = %q, want MULTIPLE", m)
	}
	if err := s.SetSetting(ctx, SettingGroupMode, GroupModeSingle); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	if m := s.EffectiveGroupMode(ctx, "t1"); m != GroupModeSingle {
		t.Fatalf("inherited effective = %q, want SINGLE", m)
	}
	// A forced tenant value wins over the global.
	if err := s.SetGroupMode(ctx, "t1", GroupModeMultiple); err != nil {
		t.Fatalf("SetGroupMode: %v", err)
	}
	if m := s.EffectiveGroupMode(ctx, "t1"); m != GroupModeMultiple {
		t.Fatalf("forced effective = %q, want MULTIPLE", m)
	}
	// And back to inherit.
	if err := s.SetGroupMode(ctx, "t1", ""); err != nil {
		t.Fatalf("SetGroupMode(inherit): %v", err)
	}
	if m := s.EffectiveGroupMode(ctx, "t1"); m != GroupModeSingle {
		t.Fatalf("re-inherited effective = %q, want SINGLE", m)
	}
	if err := s.SetGroupMode(ctx, "t1", "BOGUS"); err == nil {
		t.Fatal("expected invalid group mode to be rejected")
	}
}
