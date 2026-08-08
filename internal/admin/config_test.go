package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/softwarity/meerkat/internal/mail"
	"github.com/softwarity/meerkat/internal/routing"
	"github.com/softwarity/meerkat/internal/store"
	"github.com/softwarity/meerkat/internal/vault"
)

// TestConfigExportImportRoundTrip walks the whole loop through the API: export
// a gateway, import the file into another, and get the same configuration.
func TestConfigExportImportRoundTrip(t *testing.T) {
	from := setup(t)
	ctx := context.Background()
	if err := from.api.st.SaveRoute(ctx, store.Route{
		ID: "api", Name: "api", Order: 1, Enabled: true, Upstream: "http://up.invalid",
		Predicates: []routing.Spec{{Type: "path", Args: map[string]any{"patterns": []any{"/api/**"}}}},
	}); err != nil {
		t.Fatal(err)
	}

	code, file := from.call(t, "GET", "/api/config/export", "", from.rootC)
	if code != http.StatusOK {
		t.Fatalf("export: %d %s", code, file)
	}
	if !strings.Contains(file, "id: api") {
		t.Fatalf("the export should carry the route:\n%s", file)
	}

	to := setup(t)
	code, out := to.call(t, "POST", "/api/config/import", file, to.rootC)
	if code != http.StatusOK {
		t.Fatalf("import: %d %s", code, out)
	}
	routes, err := to.api.st.ListRoutes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 || routes[0].ID != "api" {
		t.Fatalf("the route did not travel: %v", routes)
	}
	// And the data plane is serving it: an import applies, like every other save.
	code, again := to.call(t, "GET", "/api/config/export", "", to.rootC)
	if code != http.StatusOK {
		t.Fatalf("export: %d %s", code, again)
	}
	if again != file {
		t.Fatalf("the round trip changed the configuration:\n--- a ---\n%s\n--- b ---\n%s", file, again)
	}
}

// TestConfigPreviewWritesNothing: the preview is what an admin looks at before
// deciding, so it must be exactly as informative and exactly as harmless.
func TestConfigPreviewWritesNothing(t *testing.T) {
	f := setup(t)
	ctx := context.Background()

	file := "version: 1\nroles:\n  - id: ops\n    name: Ops\n"
	code, out := f.call(t, "POST", "/api/config/preview", file, f.rootC)
	if code != http.StatusOK {
		t.Fatalf("preview: %d %s", code, out)
	}
	var plan struct {
		Changes []struct{ Kind, ID, Action string }
	}
	if err := json.Unmarshal([]byte(out), &plan); err != nil {
		t.Fatal(err)
	}
	if len(plan.Changes) != 1 || plan.Changes[0].Action != "add" || plan.Changes[0].ID != "ops" {
		t.Fatalf("plan = %s", out)
	}
	roles, err := f.api.st.ListRoles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range roles {
		if r.ID == "ops" {
			t.Fatal("the preview wrote the role it was only describing")
		}
	}
}

// TestConfigMissingSecretsAreReported: the import preview is the one moment an
// admin still knows what $ldap-bind was. It has to say what the vault is
// missing, and what kind of entry each one has to be.
func TestConfigMissingSecretsAreReported(t *testing.T) {
	f := setup(t)
	file := `version: 1
authProviders:
  - id: corp
    name: Corp
    kind: oidc
    enabled: true
    config:
      issuer: https://login.corp.example
      clientId: meerkat
      clientSecret: ${corp-secret}
routes:
  - id: api
    name: api
    enabled: true
    upstream: http://${api-host}:8080
    predicates:
      - type: path
        args:
          patterns:
            - /api/**
`
	code, out := f.call(t, "POST", "/api/config/preview", file, f.rootC)
	if code != http.StatusOK {
		t.Fatalf("preview: %d %s", code, out)
	}
	var plan struct {
		Missing []struct {
			Name, Kind string
			Used       []string
		}
	}
	if err := json.Unmarshal([]byte(out), &plan); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"corp-secret": vault.KindSecret, "api-host": vault.KindValue}
	if len(plan.Missing) != 2 {
		t.Fatalf("missing = %s", out)
	}
	for _, m := range plan.Missing {
		if want[m.Name] != m.Kind {
			t.Fatalf("%s should be a %s: %s", m.Name, want[m.Name], out)
		}
		if len(m.Used) == 0 {
			t.Fatalf("%s must say what needs it: %s", m.Name, out)
		}
	}

	// Importing reserves them EMPTY rather than refusing: the configuration is
	// there, the holes are visible on the vault screen.
	if code, out := f.call(t, "POST", "/api/config/import", file, f.rootC); code != http.StatusOK {
		t.Fatalf("import: %d %s", code, out)
	}
	for name := range want {
		e, err := f.api.st.GetVaultEntry(context.Background(), vault.ScopeInfra, name)
		if err != nil {
			t.Fatalf("%s was not reserved: %v", name, err)
		}
		if e.Value != "" {
			t.Fatalf("%s must be reserved empty, got %q", name, e.Value)
		}
	}
}

// TestConfigNeverExportsALiteral is the property the feature rests on: whatever
// is in the store, the file that leaves is safe to share.
func TestConfigNeverExportsALiteral(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if err := f.api.st.SetSetting(ctx, store.SettingSMTP, mail.Config{
		Host: "smtp.example.com", Port: 587, Username: "bot", Password: "hunter2",
	}); err != nil {
		t.Fatal(err)
	}
	code, file := f.call(t, "GET", "/api/config/export", "", f.rootC)
	if code != http.StatusOK {
		t.Fatalf("export: %d %s", code, file)
	}
	if strings.Contains(file, "hunter2") {
		t.Fatalf("a literal secret reached the export:\n%s", file)
	}
	// And the report says so, so the admin is not left guessing why the relay
	// will not authenticate wherever this file lands.
	code, report := f.call(t, "GET", "/api/config/report", "", f.rootC)
	if code != http.StatusOK {
		t.Fatalf("report: %d %s", code, report)
	}
	if !strings.Contains(report, "mailrelay") || !strings.Contains(report, "password") {
		t.Fatalf("the left-behind secret must be named: %s", report)
	}
}

// TestConfigIsRootOnly: a document crosses both planes, so administering one is
// not enough - an infra admin importing a file that rewrites the sign-in
// authorities would be a way around RBAC-05.
func TestConfigIsRootOnly(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if err := f.api.st.UpdateUser(ctx, store.User{
		ID: "bob", Username: "bob", Enabled: true, InfraAdmin: true,
	}); err != nil {
		t.Fatal(err)
	}
	for _, call := range []struct{ method, path, body string }{
		{"GET", "/api/config/export", ""},
		{"GET", "/api/config/report", ""},
		{"POST", "/api/config/preview", "version: 1\nroles: []\n"},
		{"POST", "/api/config/import", "version: 1\nroles: []\n"},
	} {
		if code, _ := f.call(t, call.method, call.path, call.body, f.plainC); code != http.StatusForbidden {
			t.Fatalf("%s %s: %d, want 403", call.method, call.path, code)
		}
	}
}

// TestConfigRefusesNonsense: a file written by hand gets refused with the word
// that is wrong in it, never half-applied.
func TestConfigRefusesNonsense(t *testing.T) {
	f := setup(t)
	for _, tc := range []struct{ file, wants string }{
		{"version: 1\nrouts: []\n", "routs"},
		{"version: 99\nroles: []\n", "99"},
		{"version: 1\nsettings:\n  nope: true\n", "nope"},
		{"version: 1\nroutes:\n  - id: x\n    name: x\n", "predicate"},
		{": : :\n", "YAML"},
	} {
		code, out := f.call(t, "POST", "/api/config/import", tc.file, f.rootC)
		if code == http.StatusOK {
			t.Fatalf("%q was accepted", tc.file)
		}
		if !strings.Contains(out, tc.wants) {
			t.Fatalf("%q should be refused mentioning %q, got %s", tc.file, tc.wants, out)
		}
	}
}
