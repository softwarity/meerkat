package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/softwarity/meerkat/internal/store"
)

func TestMeReportsIdentityAndTenants(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if err := f.api.st.SaveTenant(ctx, store.Tenant{ID: "t1", Name: "acme", Enabled: true,
		BusinessAccess: store.BusinessAccess{Inherited: true}}); err != nil {
		t.Fatal(err)
	}
	if err := f.api.st.SaveMembership(ctx, store.Membership{
		UserID: "bob", TenantID: "t1", Type: store.MemberAdmin, Enabled: true,
		BusinessAccess: store.BusinessAccess{Inherited: true}}); err != nil {
		t.Fatal(err)
	}

	code, body := f.call(t, "GET", "/api/me", "", f.plainC)
	if code != http.StatusOK {
		t.Fatalf("me: %d %s", code, body)
	}
	var me struct {
		User    store.User         `json:"user"`
		Tenants []store.UserTenant `json:"tenants"`
	}
	if err := json.Unmarshal([]byte(body), &me); err != nil {
		t.Fatal(err)
	}
	if me.User.Username != "bob" || len(me.Tenants) != 1 || me.Tenants[0].Type != "ADMIN" {
		t.Fatalf("me payload: %s", body)
	}
	if strings.Contains(body, "password") {
		t.Fatalf("me must never leak password material: %s", body)
	}
	if code, _ := f.call(t, "GET", "/api/me", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("anonymous me must 401")
	}
}

func TestUsersCRUDIsRootScoped(t *testing.T) {
	f := setup(t)

	if code, _ := f.call(t, "GET", "/api/users", "", f.plainC); code != http.StatusForbidden {
		t.Fatalf("non-root list users must 403")
	}

	code, body := f.call(t, "POST", "/api/users",
		`{"username":"carol","fullname":"Carol C","email":"c@example.com","enabled":true,"dev":true}`, f.rootC)
	if code != http.StatusCreated {
		t.Fatalf("create user: %d %s", code, body)
	}
	var created struct {
		User     store.User `json:"user"`
		Password string     `json:"password"`
	}
	if err := json.Unmarshal([]byte(body), &created); err != nil {
		t.Fatal(err)
	}
	if created.Password == "" || !created.User.Dev || created.User.ID == "" {
		t.Fatalf("create payload: %s", body)
	}

	// Update: grant tester, then reset password.
	code, body = f.call(t, "PUT", "/api/users/"+created.User.ID,
		`{"username":"carol","fullname":"Carol C","email":"c@example.com","enabled":true,"dev":true,"tester":true,"timezone":"UTC"}`, f.rootC)
	if code != http.StatusOK || !strings.Contains(body, `"tester":true`) {
		t.Fatalf("update user: %d %s", code, body)
	}
	if code, body = f.call(t, "POST", "/api/users/"+created.User.ID+"/reset-password", "", f.rootC); code != http.StatusOK || !strings.Contains(body, "password") {
		t.Fatalf("reset password: %d %s", code, body)
	}

	// Lockout guards: self-demotion is refused (self-guard fires first), and
	// the last enabled root can never be deleted.
	code, body = f.call(t, "PUT", "/api/users/root",
		`{"username":"root","enabled":true,"root":false,"timezone":"UTC"}`, f.rootC)
	if code != http.StatusUnprocessableEntity || !strings.Contains(body, "your own") {
		t.Fatalf("self-demotion must be refused: %d %s", code, body)
	}
	if code, _ = f.call(t, "DELETE", "/api/users/root", "", f.rootC); code != http.StatusUnprocessableEntity {
		t.Fatalf("last-root deletion must be refused: %d", code)
	}
}

func TestTenantScoping(t *testing.T) {
	f := setup(t)

	// bob has no tenant-creator superpower.
	if code, _ := f.call(t, "POST", "/api/tenants", `{"name":"acme"}`, f.plainC); code != http.StatusForbidden {
		t.Fatalf("bob creating a tenant must 403")
	}

	// root creates two tenants.
	code, body := f.call(t, "POST", "/api/tenants", `{"name":"acme"}`, f.rootC)
	if code != http.StatusCreated {
		t.Fatalf("root create tenant: %d %s", code, body)
	}
	var acme store.Tenant
	if err := json.Unmarshal([]byte(body), &acme); err != nil {
		t.Fatal(err)
	}
	if !acme.BusinessAccess.Inherited {
		t.Fatalf("default business access must inherit: %s", body)
	}
	_, body2 := f.call(t, "POST", "/api/tenants", `{"name":"globex"}`, f.rootC)
	var globex store.Tenant
	if err := json.Unmarshal([]byte(body2), &globex); err != nil {
		t.Fatal(err)
	}

	// bob becomes ADMIN of acme.
	code, body = f.call(t, "PUT", "/api/tenants/"+acme.ID+"/members/bob",
		`{"type":"ADMIN","enabled":true,"businessAccess":{"inherited":true}}`, f.rootC)
	if code != http.StatusOK {
		t.Fatalf("add member: %d %s", code, body)
	}

	// Scoped listing: root sees both, bob sees only acme.
	if _, body = f.call(t, "GET", "/api/tenants", "", f.rootC); !strings.Contains(body, "globex") {
		t.Fatalf("root must list every tenant: %s", body)
	}
	if code, body = f.call(t, "GET", "/api/tenants", "", f.plainC); code != http.StatusOK || strings.Contains(body, "globex") || !strings.Contains(body, "acme") {
		t.Fatalf("tenant admin must list only their tenants: %d %s", code, body)
	}

	// Scoped access: bob configures acme, never globex.
	if code, _ = f.call(t, "GET", "/api/tenants/"+acme.ID, "", f.plainC); code != http.StatusOK {
		t.Fatalf("admin must read their tenant: %d", code)
	}
	code, body = f.call(t, "PUT", "/api/tenants/"+acme.ID,
		`{"name":"acme","enabled":true,"businessAccess":{"inherited":false,"timezone":"Europe/Paris","days":[{"day":1,"from":"08:00","to":"18:00"},{"day":2,"from":"08:00","to":"18:00"},{"day":3,"from":"08:00","to":"18:00"},{"day":4,"from":"08:00","to":"18:00"},{"day":5,"from":"08:00","to":"18:00"}]},"sessionTTL":"PT1H"}`, f.plainC)
	if code != http.StatusOK || !strings.Contains(body, "Europe/Paris") {
		t.Fatalf("admin must configure their tenant: %d %s", code, body)
	}
	if code, _ = f.call(t, "GET", "/api/tenants/"+globex.ID, "", f.plainC); code != http.StatusForbidden {
		t.Fatalf("admin of acme must not read globex: %d", code)
	}

	// ADMIN cannot destroy the tenant (that is for root or the owner)…
	if code, _ = f.call(t, "DELETE", "/api/tenants/"+acme.ID, "", f.plainC); code != http.StatusForbidden {
		t.Fatalf("ADMIN deleting the tenant must 403: %d", code)
	}
	// …nor transfer ownership — only root or the current owner may.
	if code, _ = f.call(t, "POST", "/api/tenants/"+acme.ID+"/owner",
		`{"userId":"bob"}`, f.plainC); code != http.StatusForbidden {
		t.Fatalf("ADMIN transferring ownership must 403: %d", code)
	}

	// root created acme, so root owns it even though root is NOT a member
	// (ownership is decoupled from membership). Transfer ownership to bob.
	if _, body = f.call(t, "GET", "/api/tenants/"+acme.ID, "", f.rootC); !strings.Contains(body, `"ownerName":"root"`) {
		t.Fatalf("root-created tenant must be owned by root: %s", body)
	}
	code, body = f.call(t, "POST", "/api/tenants/"+acme.ID+"/owner", `{"userId":"bob"}`, f.rootC)
	if code != http.StatusOK || !strings.Contains(body, `"ownerName":"bob"`) {
		t.Fatalf("root transferring ownership: %d %s", code, body)
	}
	// The transfer leaves bob's membership untouched (still ADMIN, not a type
	// change) — ownership no longer rides on the membership.
	_, members := f.call(t, "GET", "/api/tenants/"+acme.ID+"/members", "", f.rootC)
	if !strings.Contains(members, `"userId":"bob","tenantId":"`+acme.ID+`","type":"ADMIN"`) {
		t.Fatalf("transfer must not change membership type: %s", members)
	}

	// The owner (bob) may now destroy their tenant.
	if code, _ = f.call(t, "DELETE", "/api/tenants/"+acme.ID, "", f.plainC); code != http.StatusNoContent {
		t.Fatalf("owner deleting their tenant: %d", code)
	}
}

func TestTenantCreatorSuperpower(t *testing.T) {
	f := setup(t)
	// Grant bob the tenant-creator superpower; his creation makes him the owner
	// (owner_id) AND an ADMIN member (he works in his tenant).
	code, body := f.call(t, "PUT", "/api/users/bob",
		`{"username":"bob","enabled":true,"tenantCreator":true,"timezone":"UTC"}`, f.rootC)
	if code != http.StatusOK {
		t.Fatalf("grant tenantCreator: %d %s", code, body)
	}
	code, body = f.call(t, "POST", "/api/tenants", `{"name":"bobco"}`, f.plainC)
	if code != http.StatusCreated {
		t.Fatalf("creator create tenant: %d %s", code, body)
	}
	var tn store.Tenant
	if err := json.Unmarshal([]byte(body), &tn); err != nil {
		t.Fatal(err)
	}
	if tn.OwnerID != "bob" {
		t.Fatalf("creator must own their tenant: ownerId=%q", tn.OwnerID)
	}
	_, members := f.call(t, "GET", "/api/tenants/"+tn.ID+"/members", "", f.plainC)
	if !strings.Contains(members, `"type":"ADMIN"`) || !strings.Contains(members, `"username":"bob"`) {
		t.Fatalf("creator must be an ADMIN member of their tenant: %s", members)
	}
}

func TestGlobalSettings(t *testing.T) {
	f := setup(t)
	code, body := f.call(t, "GET", "/api/settings", "", f.plainC)
	if code != http.StatusOK || !strings.Contains(body, `"sessionTTL":"PT30M"`) {
		t.Fatalf("settings defaults: %d %s", code, body)
	}
	if code, _ = f.call(t, "PUT", "/api/settings", `{"businessAccess":{"inherited":false,"timezone":"UTC","days":[{"day":1,"from":"07:00","to":"19:00"},{"day":2,"from":"07:00","to":"19:00"},{"day":3,"from":"07:00","to":"19:00"},{"day":4,"from":"07:00","to":"19:00"},{"day":5,"from":"07:00","to":"19:00"}]},"sessionTTL":"PT2H"}`, f.plainC); code != http.StatusForbidden {
		t.Fatalf("non-root settings write must 403: %d", code)
	}
	code, body = f.call(t, "PUT", "/api/settings",
		`{"businessAccess":{"inherited":false,"timezone":"UTC","days":[{"day":1,"from":"07:00","to":"19:00"},{"day":2,"from":"07:00","to":"19:00"},{"day":3,"from":"07:00","to":"19:00"},{"day":4,"from":"07:00","to":"19:00"},{"day":5,"from":"07:00","to":"19:00"}]},"sessionTTL":"PT2H"}`, f.rootC)
	if code != http.StatusOK {
		t.Fatalf("root settings write: %d %s", code, body)
	}
	if _, body = f.call(t, "GET", "/api/settings", "", f.plainC); !strings.Contains(body, `"PT2H"`) {
		t.Fatalf("settings write lost: %s", body)
	}
}

func TestUserLookupScope(t *testing.T) {
	f := setup(t)
	// A plain user (no administered tenant) must not probe usernames.
	if code, _ := f.call(t, "GET", "/api/users/lookup?username=root", "", f.plainC); code != http.StatusForbidden {
		t.Fatalf("plain user lookup must 403: %d", code)
	}
	// Once bob administers a tenant, lookup answers a minimal identity.
	ctx := context.Background()
	if err := f.api.st.SaveTenant(ctx, store.Tenant{ID: "t1", Name: "acme", Enabled: true,
		BusinessAccess: store.BusinessAccess{Inherited: true}}); err != nil {
		t.Fatal(err)
	}
	if err := f.api.st.SaveMembership(ctx, store.Membership{UserID: "bob", TenantID: "t1",
		Type: store.MemberAdmin, Enabled: true, BusinessAccess: store.BusinessAccess{Inherited: true}}); err != nil {
		t.Fatal(err)
	}
	code, body := f.call(t, "GET", "/api/users/lookup?username=root", "", f.plainC)
	if code != http.StatusOK || !strings.Contains(body, `"username":"root"`) || strings.Contains(body, "root\":true") {
		t.Fatalf("lookup: %d %s", code, body)
	}
}

func TestSelfLockoutGuards(t *testing.T) {
	f := setup(t)
	// Even with bob promoted root (another enabled root exists), root cannot
	// disable itself nor drop its own root flag.
	if code, _ := f.call(t, "PUT", "/api/users/bob",
		`{"username":"bob","enabled":true,"root":true,"timezone":"UTC"}`, f.rootC); code != http.StatusOK {
		t.Fatalf("promote bob: %d", code)
	}
	code, body := f.call(t, "PUT", "/api/users/root",
		`{"username":"root","enabled":false,"root":true,"timezone":"UTC"}`, f.rootC)
	if code != http.StatusUnprocessableEntity || !strings.Contains(body, "your own") {
		t.Fatalf("self-disable must be refused: %d %s", code, body)
	}
	code, body = f.call(t, "PUT", "/api/users/root",
		`{"username":"root","enabled":true,"root":false,"timezone":"UTC"}`, f.rootC)
	if code != http.StatusUnprocessableEntity || !strings.Contains(body, "your own") {
		t.Fatalf("self-demote must be refused: %d %s", code, body)
	}
	// Another root CAN disable this one (bob acts on root).
	bobC := issue(t, f.api.sm, "bob")
	if code, body = f.call(t, "PUT", "/api/users/root",
		`{"username":"root","enabled":false,"root":true,"timezone":"UTC"}`, bobC); code != http.StatusOK {
		t.Fatalf("other-root disable: %d %s", code, body)
	}
}
