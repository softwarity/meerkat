package store

import (
	"slices"
	"testing"
)

// The access rule's two axes (RBAC-06), and the hole they were written to
// close: a confirmed account that belongs to NO organisation used to reach
// anything gated on "authenticated" while the console showed it the waiting
// room - and it arrived upstream with no tenant and no role, so every
// role-based decision inside the application read as "this person has nothing".
func TestAccessLevels(t *testing.T) {
	pending := Caller{Authenticated: true, Username: "newcomer"}
	member := Caller{Authenticated: true, Username: "jane", TenantID: "acme", Roles: []string{"reader"}}
	admin := Caller{Authenticated: true, Username: "boss", TenantID: "globex", Roles: []string{"admin"}}
	anon := Caller{}

	for _, tc := range []struct {
		name  string
		rule  Access
		grant map[string]bool // caller name -> expected
	}{
		{
			// No rule at all: the gateway does not decide, the upstream keeps
			// its own security. Anonymous included - this is NOT "public",
			// it is "not my call".
			name:  "delegated lets everything through",
			rule:  Access{},
			grant: map[string]bool{"anon": true, "pending": true, "member": true},
		},
		{
			name:  "public opens without a session",
			rule:  Access{Level: AccessPublic},
			grant: map[string]bool{"anon": true, "pending": true, "member": true},
		},
		{
			// Deliberate: this is how one serves the page that explains how to
			// ask for access. "auth" says who it is, and nothing more.
			name:  "auth takes anyone signed in, waiting room included",
			rule:  Access{Level: AccessAuth},
			grant: map[string]bool{"anon": false, "pending": true, "member": true},
		},
		{
			name:  "tenant turns away the account that belongs nowhere",
			rule:  Access{Level: AccessTenant},
			grant: map[string]bool{"anon": false, "pending": false, "member": true, "admin": true},
		},
		{
			name:  "tenants names which organisations",
			rule:  Access{Level: AccessTenants, Tenants: []string{"acme"}},
			grant: map[string]bool{"pending": false, "member": true, "admin": false},
		},
		{
			// The role catalogue is GLOBAL while groups are per-organisation,
			// so a bare role gate means "an admin of ANY organisation" - a
			// cross-org administration UI.
			name:  "roles alone accept the holder from any organisation",
			rule:  Access{Level: AccessAuth, Roles: []string{"admin"}},
			grant: map[string]bool{"pending": false, "member": false, "admin": true},
		},
		{
			// The two axes ANDed: admin OF acme. Neither axis alone says it.
			name:  "tenants and roles cross",
			rule:  Access{Level: AccessTenants, Tenants: []string{"acme"}, Roles: []string{"admin"}},
			grant: map[string]bool{"member": false, "admin": false},
		},
		{
			// The exception: named users pass whatever the level asks. A UI
			// dedicated to one person, a service account, a support login.
			name:  "a named user passes a level they do not satisfy",
			rule:  Access{Level: AccessTenants, Tenants: []string{"acme"}, Users: []string{"newcomer"}},
			grant: map[string]bool{"anon": false, "pending": true, "admin": false},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for who, want := range tc.grant {
				c := map[string]Caller{"anon": anon, "pending": pending, "member": member, "admin": admin}[who]
				if got := tc.rule.Grants(c); got != want {
					t.Errorf("Grants(%s) = %v, want %v", who, got, want)
				}
			}
		})
	}
}

// Switchable is what keeps a refusal from being a dead end: someone who
// belongs to an accepted organisation but is active in another one is offered
// the choice rather than a 403 they cannot act on.
func TestAccessSwitchable(t *testing.T) {
	both := Caller{Authenticated: true, TenantID: "globex", Memberships: []string{"acme", "globex"}}
	if offer := (Access{Level: AccessTenants, Tenants: []string{"acme"}}).Switchable(both); !slices.Equal(offer, []string{"acme"}) {
		t.Fatalf("offer = %v, want [acme]", offer)
	}
	// Nothing to switch TO: the refusal is final and the caller must be told so.
	outsider := Caller{Authenticated: true, TenantID: "globex", Memberships: []string{"globex"}}
	if offer := (Access{Level: AccessTenants, Tenants: []string{"acme"}}).Switchable(outsider); len(offer) != 0 {
		t.Fatalf("offer = %v, want none", offer)
	}
	// A member who has not chosen yet, on a rule that just wants AN
	// organisation: every membership is a valid answer.
	unchosen := Caller{Authenticated: true, Memberships: []string{"acme", "globex"}}
	if offer := (Access{Level: AccessTenant}).Switchable(unchosen); len(offer) != 2 {
		t.Fatalf("offer = %v, want both", offer)
	}
	// The waiting room has nowhere to go: this is the /account-pending case,
	// not the chooser.
	if offer := (Access{Level: AccessTenant}).Switchable(Caller{Authenticated: true}); len(offer) != 0 {
		t.Fatalf("offer = %v, want none", offer)
	}
}
