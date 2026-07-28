package admin

import (
	"context"
	"net/http"
	"testing"

	"github.com/softwarity/meerkat/internal/store"
)

// TestSplitAdministrationScopes locks the RBAC-05 access matrix: the INFRA
// plane (routes, mail relay) answers to root or infra-admin, the APPLICATION
// (identity, theme, branding) to root or app-admin, and neither capability
// leaks into the other scope.
func TestSplitAdministrationScopes(t *testing.T) {
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

	type probe struct {
		name       string
		method     string
		path       string
		body       string
		root, gw   int
		app, plain int
	}
	probes := []probe{
		// Infra scope: routes, catalog, and the mail RELAY (a third party's
		// host and credentials).
		{"catalog", "GET", "/api/catalog", "", 200, 200, 403, 403},
		{"routes", "GET", "/api/routes", "", 200, 200, 403, 403},
		{"mail relay", "GET", "/api/settings/mail-relay", "", 200, 200, 403, 403},
		// Application scope: users, roles, and the product's own face — the
		// built-in pages' theme and branding. The gateway SERVES those pages;
		// serving them is not owning them.
		{"users", "GET", "/api/users", "", 200, 403, 200, 403},
		{"roles", "GET", "/api/roles", "", 200, 403, 200, 403},
		{"themes", "GET", "/api/themes", "", 200, 403, 200, 403},
		{"branding", "GET", "/api/branding", "", 200, 403, 200, 403},
	}
	cookies := []struct {
		who string
		c   *http.Cookie
		get func(p probe) int
	}{
		{"root", f.rootC, func(p probe) int { return p.root }},
		{"infra-admin", gwC, func(p probe) int { return p.gw }},
		{"app-admin", apC, func(p probe) int { return p.app }},
		{"plain", f.plainC, func(p probe) int { return p.plain }},
	}
	for _, p := range probes {
		for _, who := range cookies {
			status, body := f.call(t, p.method, p.path, p.body, who.c)
			if status != who.get(p) {
				t.Errorf("%s as %s: %d, want %d (%s)", p.name, who.who, status, who.get(p), body)
			}
		}
	}

	// Privilege escalation guards: an app-admin manages users but never mints
	// or promotes a root.
	if status, body := f.call(t, "POST", "/api/users", `{"username":"evil","root":true}`, apC); status != http.StatusForbidden {
		t.Fatalf("app-admin creating a root: %d %s", status, body)
	}
	if status, body := f.call(t, "PUT", "/api/users/bob", `{"username":"bob","enabled":true,"root":true}`, apC); status != http.StatusForbidden {
		t.Fatalf("app-admin promoting to root: %d %s", status, body)
	}
	// The same operations without root involved stay allowed.
	if status, body := f.call(t, "POST", "/api/users", `{"username":"newbie"}`, apC); status != http.StatusCreated {
		t.Fatalf("app-admin creating a user: %d %s", status, body)
	}
	if status, body := f.call(t, "PUT", "/api/users/bob", `{"username":"bob","enabled":true,"tester":true}`, apC); status != http.StatusOK {
		t.Fatalf("app-admin editing a user: %d %s", status, body)
	}
	// And root still promotes.
	if status, body := f.call(t, "PUT", "/api/users/bob", `{"username":"bob","enabled":true,"root":true}`, f.rootC); status != http.StatusOK {
		t.Fatalf("root promoting to root: %d %s", status, body)
	}
}
