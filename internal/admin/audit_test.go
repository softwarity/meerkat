package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/softwarity/meerkat/internal/store"
)

// diffFields records only the changed fields, ignores identifiers/timestamps,
// and redacts secrets wherever they hide.
func TestDiffFields(t *testing.T) {
	old := map[string]any{
		"name": "acme", "groupMode": "MULTIPLE", "enabled": true,
		"updatedAt": 100, "id": "t1", "ownerName": "alice",
	}
	neu := map[string]any{
		"name": "acme", "groupMode": "SINGLE", "enabled": true,
		"updatedAt": 200, "id": "t1", "ownerName": "bob",
	}
	changes := diffFields(old, neu)
	if len(changes) != 1 {
		t.Fatalf("only groupMode changed, got %d: %+v", len(changes), changes)
	}
	c := changes[0]
	if c.Field != "groupMode" || c.From != "MULTIPLE" || c.To != "SINGLE" {
		t.Fatalf("diff = %+v", c)
	}

	// Nested secrets are redacted; a real change is still surfaced.
	oldS := map[string]any{"smtp": map[string]any{"host": "old", "password": "s3cr3t"}}
	newS := map[string]any{"smtp": map[string]any{"host": "new", "password": "n3w"}}
	sc := diffFields(oldS, newS)
	if len(sc) != 1 || sc[0].Field != "smtp" {
		t.Fatalf("smtp change: %+v", sc)
	}
	blob, _ := json.Marshal(sc[0])
	if strings.Contains(string(blob), "s3cr3t") || strings.Contains(string(blob), "n3w") {
		t.Fatalf("password leaked into the audit: %s", blob)
	}
	if !strings.Contains(string(blob), "***") || !strings.Contains(string(blob), `"new"`) {
		t.Fatalf("want redacted password and visible host change: %s", blob)
	}
}

// A tenant update records the exact field-level change, and the viewer is
// scoped: root sees the event, an unrelated tenant admin does not.
func TestAuditViewerScope(t *testing.T) {
	f := setup(t)

	// root creates a tenant and makes bob its ADMIN.
	code, body := f.call(t, "POST", "/api/tenants", `{"name":"acme"}`, f.rootC)
	if code != http.StatusCreated {
		t.Fatalf("create tenant: %d %s", code, body)
	}
	var acme store.Tenant
	if err := json.Unmarshal([]byte(body), &acme); err != nil {
		t.Fatal(err)
	}
	if code, _ = f.call(t, "PUT", "/api/tenants/"+acme.ID+"/members/bob",
		`{"type":"ADMIN","enabled":true,"businessAccess":{"inherited":true}}`, f.rootC); code != http.StatusOK {
		t.Fatalf("add member: %d", code)
	}

	// root flips the group mode — exactly the François example.
	code, body = f.call(t, "PUT", "/api/tenants/"+acme.ID,
		`{"name":"acme","enabled":true,"businessAccess":{"inherited":true},"sessionTTL":"","groupMode":"SINGLE"}`, f.rootC)
	if code != http.StatusOK {
		t.Fatalf("update tenant: %d %s", code, body)
	}

	// The trail shows the change as groupMode: → SINGLE, not "tenant modified".
	_, body = f.call(t, "GET", "/api/audit", "", f.rootC)
	var events []store.AuditEvent
	if err := json.Unmarshal([]byte(body), &events); err != nil {
		t.Fatalf("decode audit: %v (%s)", err, body)
	}
	var upd *store.AuditEvent
	for i := range events {
		if events[i].Action == "tenant.update" {
			upd = &events[i]
			break
		}
	}
	if upd == nil {
		t.Fatalf("no tenant.update event: %s", body)
	}
	if upd.ActorName != "root" || upd.TargetName != "acme" || upd.TenantID != acme.ID {
		t.Fatalf("event metadata: %+v", upd)
	}
	if len(upd.Changes) != 1 || upd.Changes[0].Field != "groupMode" || upd.Changes[0].To != "SINGLE" {
		t.Fatalf("want groupMode diff, got: %+v", upd.Changes)
	}

	// bob (ADMIN of acme) sees his tenant's events.
	if _, b := f.call(t, "GET", "/api/audit", "", f.plainC); !strings.Contains(b, "tenant.update") {
		t.Fatalf("tenant admin must see their tenant's events: %s", b)
	}

	// A second tenant bob does not administer: its events are invisible to him.
	_, body = f.call(t, "POST", "/api/tenants", `{"name":"globex"}`, f.rootC)
	var globex store.Tenant
	_ = json.Unmarshal([]byte(body), &globex)
	f.call(t, "PUT", "/api/tenants/"+globex.ID,
		`{"name":"globex","enabled":true,"businessAccess":{"inherited":true},"sessionTTL":"","groupMode":"SINGLE"}`, f.rootC)
	_, bobView := f.call(t, "GET", "/api/audit", "", f.plainC)
	if strings.Contains(bobView, globex.ID) {
		t.Fatalf("tenant admin must not see another tenant's events: %s", bobView)
	}
}

// Each capability sees its own domain (RBAC-05): a infra-admin sees routing
// events but not identity ones, an app-admin the reverse, and a plain user is
// refused outright.
func TestAuditDomainScope(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if err := f.api.st.CreateUser(ctx, store.User{ID: "gwa", Username: "gwa", PasswordHash: "x", InfraAdmin: true, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := f.api.st.CreateUser(ctx, store.User{ID: "apa", Username: "apa", PasswordHash: "x", AppAdmin: true, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	gwC := issue(t, f.api.sm, "gwa")
	apC := issue(t, f.api.sm, "apa")

	// root generates one gateway event (a route) and one application event (a user).
	if code, body := f.call(t, "PUT", "/api/routes/r1", `{"name":"r1","enabled":true,"upstream":"http://x","predicates":[{"type":"path","args":{"patterns":["/x/**"]}}]}`, f.rootC); code != http.StatusOK {
		t.Fatalf("create route: %d %s", code, body)
	}
	if code, body := f.call(t, "POST", "/api/users", `{"username":"carol","timezone":"UTC"}`, f.rootC); code != http.StatusCreated {
		t.Fatalf("create user: %d %s", code, body)
	}

	// infra-admin sees the route, not the user.
	_, gw := f.call(t, "GET", "/api/audit", "", gwC)
	if !strings.Contains(gw, `"route.create"`) || strings.Contains(gw, `"user.create"`) {
		t.Fatalf("infra-admin must see routes, not identity: %s", gw)
	}
	// app-admin sees the user, not the route.
	_, ap := f.call(t, "GET", "/api/audit", "", apC)
	if !strings.Contains(ap, `"user.create"`) || strings.Contains(ap, `"route.create"`) {
		t.Fatalf("app-admin must see identity, not routes: %s", ap)
	}
	// A plain user administers nothing → refused.
	if code, _ := f.call(t, "GET", "/api/audit", "", f.plainC); code != http.StatusForbidden {
		t.Fatalf("plain user must be refused: %d", code)
	}
}
