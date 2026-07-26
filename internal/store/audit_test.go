package store

import (
	"context"
	"testing"
)

func TestAuditTrail(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	if err := s.CreateUser(ctx, User{ID: "u1", Username: "alice", PasswordHash: "h", Enabled: true}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Three events at different times, one by a since-deleted actor.
	must := func(ev AuditEvent) {
		t.Helper()
		if err := s.AddAuditEvent(ctx, ev); err != nil {
			t.Fatalf("AddAuditEvent: %v", err)
		}
	}
	must(AuditEvent{At: 100, ActorID: "u1", Action: "tenant.update", Target: "tenant", TargetID: "t1", TargetName: "acme", TenantID: "t1",
		Changes: []FieldChange{{Field: "groupMode", From: "MULTIPLE", To: "SINGLE"}}})
	must(AuditEvent{At: 150, ActorID: "gone", Action: "group.create", Target: "group", TargetID: "g1", TenantID: "t2"})
	must(AuditEvent{At: 200, ActorID: "u1", Action: "settings.update", Target: "settings"})

	// Newest first, actor username joined (empty when the actor is gone, id kept).
	all, err := s.ListAuditEvents(ctx, AuditFilter{})
	if err != nil || len(all) != 3 {
		t.Fatalf("list all = %d, %v", len(all), err)
	}
	if all[0].Action != "settings.update" || all[0].ActorName != "alice" {
		t.Fatalf("order/actor join: %+v", all[0])
	}
	if all[1].ActorID != "gone" || all[1].ActorName != "" {
		t.Fatalf("deleted actor must keep id, no name: %+v", all[1])
	}
	// The diff round-trips.
	if len(all[2].Changes) != 1 || all[2].Changes[0].Field != "groupMode" || all[2].Changes[0].To != "SINGLE" {
		t.Fatalf("changes round-trip: %+v", all[2])
	}

	// Tenant scope narrows to the given tenants; an empty scope lists nothing.
	scoped, _ := s.ListAuditEvents(ctx, AuditFilter{Scope: &AuditScope{TenantIDs: []string{"t2"}}})
	if len(scoped) != 1 || scoped[0].Target != "group" {
		t.Fatalf("scope t2: %+v", scoped)
	}
	if none, _ := s.ListAuditEvents(ctx, AuditFilter{Scope: &AuditScope{}}); len(none) != 0 {
		t.Fatalf("empty scope must list nothing: %+v", none)
	}
	// A domain scope (by target) is an OR with the tenant scope: settings +
	// this tenant's group event, but not the other tenant's.
	dom, _ := s.ListAuditEvents(ctx, AuditFilter{Scope: &AuditScope{Targets: []string{"settings"}, TenantIDs: []string{"t1"}}})
	if len(dom) != 2 {
		t.Fatalf("domain OR tenant scope: %+v", dom)
	}

	// Actor and target filters.
	if byActor, _ := s.ListAuditEvents(ctx, AuditFilter{ActorID: "u1"}); len(byActor) != 2 {
		t.Fatalf("by actor u1: %d", len(byActor))
	}
	if byTarget, _ := s.ListAuditEvents(ctx, AuditFilter{Target: "settings"}); len(byTarget) != 1 {
		t.Fatalf("by target settings: %d", len(byTarget))
	}

	// Retention purge drops everything older than the cutoff.
	n, err := s.PurgeAuditEventsBefore(ctx, 175)
	if err != nil || n != 2 {
		t.Fatalf("purge before 175 = %d, %v", n, err)
	}
	left, _ := s.ListAuditEvents(ctx, AuditFilter{})
	if len(left) != 1 || left[0].At != 200 {
		t.Fatalf("after purge: %+v", left)
	}
}
