package session

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/softwarity/meerkat/internal/store"
)

func bearer(token string) *http.Request {
	req := httptest.NewRequest("GET", "/api/x", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

// mintToken stores a token whose CLEAR value is "mk_<secret>" and returns the
// secret value - the hash matches what the resolver computes (sha256 hex).
func mintToken(t *testing.T, st *store.Store, userID, tenantID, groupID string, expiresAt int64) string {
	t.Helper()
	secret := "mk_" + "secret-" + userID + "-" + groupID + tenantID
	if err := st.AddAPIToken(context.Background(), "tok-"+userID+groupID+tenantID, userID, "test",
		hashToken(secret), secret[:10], store.PlaneData, tenantID, groupID, expiresAt); err != nil {
		t.Fatalf("AddAPIToken: %v", err)
	}
	return secret
}

func enabledUser(t *testing.T, st *store.Store, id string) {
	t.Helper()
	if err := st.CreateUser(context.Background(), store.User{ID: id, Username: id, PasswordHash: "x", Enabled: true}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
}

func TestBearerTokenResolves(t *testing.T) {
	m, st := setup(t)
	enabledUser(t, st, "alice")
	secret := mintToken(t, st, "alice", "t1", "g1", 0)

	sess, err := m.Resolve(context.Background(), bearer(secret))
	if err != nil {
		t.Fatalf("resolve token: %v", err)
	}
	if sess.UserID != "alice" || sess.TenantID != "t1" || sess.GroupID != "g1" {
		t.Fatalf("token session = %+v, want alice/t1/g1", sess)
	}
}

func TestBearerTokenRevokedAndDisabled(t *testing.T) {
	m, st := setup(t)
	enabledUser(t, st, "alice")
	secret := mintToken(t, st, "alice", "t1", "", 0)
	ctx := context.Background()

	// Disabled -> refused; re-enabled -> works again. (id = tok-alice + "" + t1)
	const id = "tok-alicet1"
	if _, err := st.SetAPITokenEnabled(ctx, "alice", id, false); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Resolve(ctx, bearer(secret)); err == nil {
		t.Fatalf("a disabled token must not resolve")
	}
	if _, err := st.SetAPITokenEnabled(ctx, "alice", id, true); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Resolve(ctx, bearer(secret)); err != nil {
		t.Fatalf("a re-enabled token must resolve: %v", err)
	}
	// Revoked -> gone.
	if _, err := st.RevokeAPIToken(ctx, "alice", id); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Resolve(ctx, bearer(secret)); err == nil {
		t.Fatalf("a revoked token must not resolve")
	}
}

// A token authenticates ONLY on its own plane: a data token never opens the
// admin port, an admin (control-plane) token never opens the data port.
func TestBearerTokenPlaneIsolation(t *testing.T) {
	dataM, st := setup(t)
	adminM := NewManager(st, ForAdminPlane()) // same store, admin plane
	ctx := context.Background()
	enabledUser(t, st, "root")

	// A DATA token resolves on the data plane but not the admin plane.
	dataClear := mintToken(t, st, "root", "", "", 0) // minted with PlaneData
	if _, err := dataM.Resolve(ctx, bearer(dataClear)); err != nil {
		t.Fatalf("data token on the data plane must resolve: %v", err)
	}
	if _, err := adminM.Resolve(ctx, bearer(dataClear)); err == nil {
		t.Fatalf("a data token must NOT open the admin plane")
	}

	// An ADMIN token resolves on the admin plane but not the data plane.
	adminClear := "mk_admin-secret-value"
	if err := st.AddAPIToken(ctx, "atok", "root", "cli", hashToken(adminClear), adminClear[:10], store.PlaneAdmin, "", "", 0); err != nil {
		t.Fatalf("AddAPIToken(admin): %v", err)
	}
	if _, err := adminM.Resolve(ctx, bearer(adminClear)); err != nil {
		t.Fatalf("admin token on the admin plane must resolve: %v", err)
	}
	if _, err := dataM.Resolve(ctx, bearer(adminClear)); err == nil {
		t.Fatalf("an admin token must NOT open the data plane")
	}
}

func TestBearerTokenExpiredDisabledUserAndPolicy(t *testing.T) {
	m, st := setup(t)
	enabledUser(t, st, "alice")
	ctx := context.Background()

	// Expired.
	expired := mintToken(t, st, "alice", "t1", "", time.Now().Add(-time.Hour).Unix())
	if _, err := m.Resolve(ctx, bearer(expired)); err == nil {
		t.Fatalf("an expired token must not resolve")
	}

	// A live token, then the OWNER is disabled -> tokens stop at once.
	live := mintToken(t, st, "alice", "t2", "", 0) // different group => different id
	if _, err := m.Resolve(ctx, bearer(live)); err != nil {
		t.Fatalf("live token should resolve: %v", err)
	}
	if err := st.UpdateUser(ctx, store.User{ID: "alice", Username: "alice", Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Resolve(ctx, bearer(live)); err == nil {
		t.Fatalf("a disabled account's token must not resolve")
	}

	// Policy off -> no token authenticates, even a live one.
	if err := st.UpdateUser(ctx, store.User{ID: "alice", Username: "alice", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting(ctx, store.SettingAPITokens, false); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Resolve(ctx, bearer(live)); err == nil {
		t.Fatalf("policy off must refuse every token")
	}
}

func TestBearerRejectedOnAdminPlane(t *testing.T) {
	m, st := setup(t, ForAdminPlane())
	enabledUser(t, st, "alice")
	secret := mintToken(t, st, "alice", "t1", "", 0)
	if _, err := m.Resolve(context.Background(), bearer(secret)); err == nil {
		t.Fatalf("the admin plane must never accept a personal API token")
	}
}
