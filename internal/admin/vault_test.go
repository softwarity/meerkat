package admin

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/softwarity/meerkat/internal/store"
	"github.com/softwarity/meerkat/internal/vault"
)

// TestVaultReferenceReachesTheDataPlane is the whole point of the vault: a
// route stores "$name", the database never holds the value, and the data plane
// still reaches the real upstream because the gateway expands the reference
// when it loads the configuration.
func TestVaultReferenceReachesTheDataPlane(t *testing.T) {
	f := setup(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "up:"+r.Header.Get("X-Api-Key"))
	}))
	t.Cleanup(up.Close)

	// A plain value (the upstream) and a secret (an API key sent upstream).
	host := strings.TrimPrefix(up.URL, "http://")
	if code, out := f.call(t, "PUT", "/api/vault/infra/api-host",
		fmt.Sprintf(`{"kind":"value","value":%q}`, host), f.rootC); code != http.StatusOK {
		t.Fatalf("put value: %d %s", code, out)
	}
	if code, out := f.call(t, "PUT", "/api/vault/infra/api-key",
		`{"kind":"secret","value":"s3cr3t-key"}`, f.rootC); code != http.StatusOK {
		t.Fatalf("put secret: %d %s", code, out)
	}

	// A route referencing both — the upstream by ${name} flush against a scheme,
	// the secret inside a filter argument.
	route := `{
	  "name":"api","order":1,"enabled":true,"upstream":"http://${api-host}",
	  "predicates":[{"type":"path","args":{"patterns":["/api/**"]}}],
	  "filters":[
	    {"type":"strip-prefix","args":{"parts":1}},
	    {"type":"add-request-header","args":{"name":"X-Api-Key","value":"$api-key"}}
	  ]
	}`
	if code, out := f.call(t, "PUT", "/api/routes/r1", route, f.rootC); code != http.StatusOK {
		t.Fatalf("put route: %d %s", code, out)
	}

	// The STORED route still carries the references: no secret in the database.
	code, stored := f.call(t, "GET", "/api/routes/r1", "", f.rootC)
	if code != http.StatusOK {
		t.Fatalf("get route: %d %s", code, stored)
	}
	if !strings.Contains(stored, "$api-key") || strings.Contains(stored, "s3cr3t-key") {
		t.Fatalf("the stored route should keep the reference, not the secret: %s", stored)
	}

	// The DATA PLANE resolved both: it reached the real upstream and carried the
	// decrypted key.
	res, err := http.Get(f.appSrv.URL + "/api/ping")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if got := string(body); got != "up:s3cr3t-key" {
		t.Fatalf("data plane got %q, want the expanded upstream and secret", got)
	}

	// Listing never returns a secret's value, but says it holds one and where
	// it is used.
	code, list := f.call(t, "GET", "/api/vault", "", f.rootC)
	if code != http.StatusOK {
		t.Fatalf("list vault: %d %s", code, list)
	}
	if strings.Contains(list, "s3cr3t-key") {
		t.Fatalf("the listing leaked a secret value: %s", list)
	}
	if !strings.Contains(list, `"hasValue":true`) || !strings.Contains(list, `route: api`) {
		t.Fatalf("listing lacks hasValue/usedBy: %s", list)
	}

	// A referenced entry cannot be deleted out from under the routes.
	if code, out := f.call(t, "DELETE", "/api/vault/infra/api-key", "", f.rootC); code != http.StatusConflict {
		t.Fatalf("delete in use: %d %s, want 409", code, out)
	}

	// A typo in a reference is caught when the route is saved, not at runtime.
	bad := strings.Replace(route, "$api-key", "$api-kye", 1)
	if code, out := f.call(t, "PUT", "/api/routes/r2", bad, f.rootC); code != http.StatusUnprocessableEntity {
		t.Fatalf("unknown reference: %d %s, want 422", code, out)
	}

	// Non-root cannot write to the vault.
	if code, _ := f.call(t, "PUT", "/api/vault/infra/x", `{"kind":"value","value":"y"}`, f.plainC); code != http.StatusForbidden {
		t.Fatalf("vault authz: %d, want 403", code)
	}
}

// TestVaultScopesShadowByName proves the model François asked for: a name is
// unique PER SCOPE, so the same "db-password" means a different thing for two
// organisations, and a tenant entry SHADOWS the application one it inherits.
func TestVaultScopesShadowByName(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	for _, id := range []string{"t1", "t2"} {
		if err := f.api.st.SaveTenant(ctx, store.Tenant{ID: id, Name: id, Enabled: true, OwnerID: "root"}); err != nil {
			t.Fatal(err)
		}
	}

	// The same name in three scopes.
	put := func(scope, value string) {
		t.Helper()
		body := fmt.Sprintf(`{"kind":"value","value":%q}`, value)
		if code, out := f.call(t, "PUT", "/api/vault/"+scope+"/db-password", body, f.rootC); code != http.StatusOK {
			t.Fatalf("put %s: %d %s", scope, code, out)
		}
	}
	put("app", "global")
	put("tenant:t1", "for-t1")
	put("tenant:t2", "for-t2")

	// Each scope resolves its own; a tenant without its own falls back to app.
	for scope, want := range map[string]string{
		"app":        "global",
		"tenant:t1":  "for-t1",
		"tenant:t2":  "for-t2",
		"tenant:t99": "global", // no entry of its own: inherits
	} {
		values, err := f.api.st.VaultValues(ctx, scope)
		if err != nil {
			t.Fatalf("VaultValues(%s): %v", scope, err)
		}
		if got := values["db-password"]; got != want {
			t.Fatalf("%s resolves db-password to %q, want %q", scope, got, want)
		}
	}

	// The infra plane does NOT inherit the application value: planes stay apart.
	values, err := f.api.st.VaultValues(ctx, vault.ScopeInfra)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := values["db-password"]; ok {
		t.Fatal("the infra scope must not see the application entry")
	}
}
