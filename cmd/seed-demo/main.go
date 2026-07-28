// Command seed-demo fills a Meerkat data directory with a REALISTIC demo
// dataset for live testing: a hierarchical role catalogue, tenants in BOTH
// group modes (cumulative and exclusive), groups, users spanning every
// interesting combination, and two role-gated UI routes.
//
// Idempotent: run it as often as you like (everything demo-* is upserted).
// Run it while the dev gateway is up (SQLite WAL handles the second writer),
// then reload the routes: kill -HUP <pid>, or save anything in the console.
//
//	go run ./cmd/seed-demo [-data data]
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"

	"github.com/softwarity/meerkat/internal/routing"
	"github.com/softwarity/meerkat/internal/store"
)

// One password for every demo account: this is a DEV dataset.
const demoPassword = "demo-Pass-1234"

func main() {
	dataDir := flag.String("data", "data", "data directory of the target gateway")
	flag.Parse()
	if err := run(*dataDir); err != nil {
		fmt.Fprintln(os.Stderr, "seed-demo:", err)
		os.Exit(1)
	}
}

func run(dataDir string) error {
	st, err := store.Open(dataDir)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	ctx := context.Background()

	// ── role catalogue (global, hierarchical, RBAC-01) ──────────────────────
	roles := []store.Role{
		{ID: "demo-r-admin", Name: "app-admin-suite", Description: "Administration umbrella", Tags: []string{"demo"}},
		{ID: "demo-r-billing", Name: "billing-admin", ParentID: "demo-r-admin", Description: "Invoices, payments", Tags: []string{"demo", "billing"}},
		{ID: "demo-r-catalog", Name: "catalog-admin", ParentID: "demo-r-admin", Description: "Product catalogue", Tags: []string{"demo", "catalog"}},
		{ID: "demo-r-ops", Name: "ops", Description: "Operations umbrella", Tags: []string{"demo", "ops"}},
		{ID: "demo-r-ops-read", Name: "ops-read", ParentID: "demo-r-ops", Description: "Read dashboards", Tags: []string{"demo", "ops"}},
		{ID: "demo-r-ops-write", Name: "ops-write", ParentID: "demo-r-ops", Description: "Act on incidents", Tags: []string{"demo", "ops"}},
		{ID: "demo-r-sales", Name: "sales", Description: "Sales tools", Tags: []string{"demo", "sales"}},
		{ID: "demo-r-support", Name: "support", Description: "Customer support", Tags: []string{"demo", "support"}},
		{ID: "demo-r-auditor", Name: "auditor", Description: "Read-only compliance", Tags: []string{"demo", "audit"}},
		{ID: "demo-r-reports", Name: "report-viewer", Description: "Business reports", Tags: []string{"demo"}},
	}
	for _, r := range roles {
		if err := st.SaveRole(ctx, r); err != nil {
			return fmt.Errorf("role %s: %w", r.Name, err)
		}
	}

	// ── tenants: one cumulative (the default), two forced EXCLUSIVE ──────────
	tenants := []store.Tenant{
		{ID: "demo-acme", Name: "acme-demo", Description: "Cumulative mode (the default): group roles merge",
			Enabled: true, BusinessAccess: store.BusinessAccess{Inherited: true}, GroupMode: ""},
		{ID: "demo-globex", Name: "globex-demo", Description: "EXCLUSIVE mode: members pick ONE group at entry",
			Enabled: true, BusinessAccess: store.BusinessAccess{Inherited: true}, GroupMode: store.GroupModeSingle},
		{ID: "demo-initech", Name: "initech-demo", Description: "EXCLUSIVE mode with lone groups: the choice is silent",
			Enabled: true, BusinessAccess: store.BusinessAccess{Inherited: true}, GroupMode: store.GroupModeSingle},
	}
	for _, t := range tenants {
		if err := st.SaveTenant(ctx, t); err != nil {
			return fmt.Errorf("tenant %s: %w", t.Name, err)
		}
	}

	// ── groups per tenant ────────────────────────────────────────────────────
	groups := []store.Group{
		{ID: "demo-g-acme-support", TenantID: "demo-acme", Name: "Support", RoleIDs: []string{"demo-r-support", "demo-r-reports"}},
		{ID: "demo-g-acme-sales", TenantID: "demo-acme", Name: "Sales", RoleIDs: []string{"demo-r-sales", "demo-r-reports"}},
		{ID: "demo-g-acme-ops", TenantID: "demo-acme", Name: "Ops", RoleIDs: []string{"demo-r-ops-write"}},
		{ID: "demo-g-glx-traders", TenantID: "demo-globex", Name: "Traders", RoleIDs: []string{"demo-r-sales"}},
		{ID: "demo-g-glx-auditors", TenantID: "demo-globex", Name: "Auditors", RoleIDs: []string{"demo-r-auditor", "demo-r-reports"}},
		{ID: "demo-g-glx-managers", TenantID: "demo-globex", Name: "Managers", RoleIDs: []string{"demo-r-billing", "demo-r-reports"}},
		{ID: "demo-g-ini-staff", TenantID: "demo-initech", Name: "Staff", RoleIDs: []string{"demo-r-support"}},
	}
	for _, g := range groups {
		if err := st.SaveGroup(ctx, g); err != nil {
			return fmt.Errorf("group %s: %w", g.Name, err)
		}
	}

	// ── users (password demo-Pass-1234 for every one of them) ───────────────
	hash, err := bcrypt.GenerateFromPassword([]byte(demoPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	type seedUser struct {
		id, username, fullname string
		memberships            map[string][]string // tenantID -> group ids
	}
	users := []seedUser{
		{"demo-u-marc", "marc", "Marc Dubois", map[string][]string{
			"demo-acme":   {"demo-g-acme-support", "demo-g-acme-sales"},  // cumulative: merged roles
			"demo-globex": {"demo-g-glx-traders", "demo-g-glx-auditors"}, // exclusive: pick one
		}},
		{"demo-u-nadia", "nadia", "Nadia Cherif", map[string][]string{
			"demo-globex": {"demo-g-glx-traders", "demo-g-glx-managers"}, // exclusive, choice at sign-in
		}},
		{"demo-u-leo", "leo", "Léo Martin", map[string][]string{
			"demo-initech": {"demo-g-ini-staff"},    // exclusive but alone: silent pick
			"demo-globex":  {"demo-g-glx-auditors"}, // exclusive but alone here too
		}},
		{"demo-u-zoe", "zoe", "Zoé Bernard", map[string][]string{
			"demo-acme": {"demo-g-acme-ops"}, // plain single-tenant cumulative
		}},
	}
	for _, u := range users {
		if _, err := st.GetUserByUsername(ctx, u.username); err != nil {
			if err := st.CreateUser(ctx, store.User{
				ID: u.id, Username: u.username, Fullname: u.fullname,
				PasswordHash: string(hash), Enabled: true, EmailVerified: true,
			}); err != nil {
				return fmt.Errorf("user %s: %w", u.username, err)
			}
		}
		for tid, gids := range u.memberships {
			if err := st.SaveMembership(ctx, store.Membership{
				UserID: u.id, TenantID: tid, Type: store.MemberUser, Enabled: true,
				BusinessAccess: store.BusinessAccess{Inherited: true},
			}); err != nil {
				return fmt.Errorf("membership %s@%s: %w", u.username, tid, err)
			}
			if err := st.SetMemberGroups(ctx, tid, u.id, gids); err != nil {
				return fmt.Errorf("groups %s@%s: %w", u.username, tid, err)
			}
		}
	}

	// ── two role-gated UI routes: watch them appear/disappear with the group ─
	routes := []store.Route{
		{ID: "demo-sales-app", Name: "sales-app", Order: 40, Enabled: true, IsUI: true,
			Access: store.Access{Roles: []string{"sales"}}, UI: &store.RouteUI{Link: "Sales app"}, Upstream: "https://httpbin.org",
			Predicates: []routing.Spec{{Type: "path", Args: map[string]any{"patterns": []any{"/sales-app/**"}}}},
			Filters:    []routing.Spec{{Type: "strip-prefix", Args: map[string]any{"parts": 1}}}},
		{ID: "demo-ops-app", Name: "ops-app", Order: 41, Enabled: true, IsUI: true,
			Access: store.Access{Roles: []string{"ops-write"}}, UI: &store.RouteUI{Link: "Ops app"}, Upstream: "https://httpbin.org",
			Predicates: []routing.Spec{{Type: "path", Args: map[string]any{"patterns": []any{"/ops-app/**"}}}},
			Filters:    []routing.Spec{{Type: "strip-prefix", Args: map[string]any{"parts": 1}}}},
	}
	for _, rt := range routes {
		if err := st.SaveRoute(ctx, rt); err != nil {
			return fmt.Errorf("route %s: %w", rt.Name, err)
		}
	}

	fmt.Println(`demo dataset seeded (idempotent). Accounts — password: ` + demoPassword + `

  marc   acme-demo(Support+Sales, CUMULATIVE) + globex-demo(Traders|Auditors, EXCLUSIVE)
         -> in acme-demo roles merge; entering globex-demo asks WHICH group; switching
            tenants from the user button re-asks.
  nadia  globex-demo(Traders|Managers, EXCLUSIVE) -> group choice right at sign-in.
  leo    initech-demo(Staff) + globex-demo(Auditors), both EXCLUSIVE with ONE group
         -> the pick is silent, no step shown.
  zoe    acme-demo(Ops), cumulative single-tenant -> nothing new.

Role-gated demo routes: /sales-app (role sales), /ops-app (role ops-write).
Reload the routes: kill -HUP the gateway, or re-save any route in the console.`)
	return nil
}
