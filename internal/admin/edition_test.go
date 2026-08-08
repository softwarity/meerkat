package admin

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/softwarity/meerkat/internal/features"
	"github.com/softwarity/meerkat/internal/store"
)

// The community edition, with nothing unlocked. setup() enables everything, so
// these turn it back off: what is pinned here is the refusal itself, and above
// all WHERE it falls - on writes, never on what already runs.
func communityFixture(t *testing.T) fixture {
	t.Helper()
	f := setup(t)
	features.Reset()
	return f
}

func TestCommunityEditionRefusesWhatItDoesNotSell(t *testing.T) {
	t.Run("a second organisation", func(t *testing.T) {
		f := communityFixture(t)
		// The first one is seeded at boot, so any creation is the second.
		code, body := f.call(t, "POST", "/api/tenants", `{"name":"acme"}`, f.rootC)
		if code != http.StatusForbidden {
			t.Fatalf("create tenant = %d, want 403", code)
		}
		if !strings.Contains(body, features.MultiTenant) {
			t.Fatalf("body = %s, want it to name the feature", body)
		}
	})

	t.Run("switching to multi-tenant", func(t *testing.T) {
		f := communityFixture(t)
		if code, _ := f.call(t, "PUT", "/api/settings/tenancy", `{"tenancy":"multi"}`, f.rootC); code != http.StatusForbidden {
			t.Fatalf("switch = %d, want 403", code)
		}
		// And single stays available: it is the community shape.
		if code, _ := f.call(t, "PUT", "/api/settings/tenancy", `{"tenancy":"single"}`, f.rootC); code != http.StatusOK {
			t.Fatalf("staying single = %d, want 200", code)
		}
	})

	t.Run("declaring a directory, while OIDC stays free", func(t *testing.T) {
		f := communityFixture(t)
		ldap := `{"id":"dir","kind":"ldap","name":"Corp","enabled":true,"config":{"url":"ldap://x"}}`
		if code, body := f.call(t, "PUT", "/api/auth-providers/dir", ldap, f.rootC); code != http.StatusForbidden {
			t.Fatalf("declare LDAP = %d %s, want 403", code, body)
		}
		// Without a free path to a modern provider this would be a toll, not
		// an edition: OIDC must go through.
		oidc := `{"id":"okta","kind":"oidc","name":"Okta","enabled":true,` +
			`"config":{"issuer":"https://example.test","clientId":"meerkat","clientSecret":"s3cret"}}`
		if code, body := f.call(t, "PUT", "/api/auth-providers/okta", oidc, f.rootC); code != http.StatusOK {
			t.Fatalf("declare OIDC = %d %s, want 200", code, body)
		}
	})

	t.Run("changing the working hours, while the rest of the settings save", func(t *testing.T) {
		f := communityFixture(t)
		hours := `{"businessAccess":{"inherited":false,"timezone":"Europe/Paris","days":[{"day":1,"from":"09:00","to":"18:00"}]},` +
			`"sessionTTL":"PT30M","mfaRequired":false,"passkeysAllowed":true,"languages":[]}`
		if code, body := f.call(t, "PUT", "/api/settings", hours, f.rootC); code != http.StatusForbidden {
			t.Fatalf("set hours = %d %s, want 403", code, body)
		}
		// Saving the settings WITHOUT touching the hours is not a change, and
		// must not be refused: every screen carrying them saves them along
		// with everything else. This is the seeded window, sent back verbatim.
		open := `{"day":1,"from":"00:00","to":"23:59"}`
		for d := 2; d <= 7; d++ {
			open += `,{"day":` + strconv.Itoa(d) + `,"from":"00:00","to":"23:59"}`
		}
		same := `{"businessAccess":{"timezone":"UTC","days":[` + open + `]},` +
			`"sessionTTL":"PT45M","mfaRequired":false,"passkeysAllowed":true,"languages":[]}`
		if code, body := f.call(t, "PUT", "/api/settings", same, f.rootC); code != http.StatusOK {
			t.Fatalf("save without touching the hours = %d %s, want 200", code, body)
		}
	})
}

// What the console asks before drawing anything: one endpoint, so a locked
// control here and a hidden menu entry there cannot drift apart.
func TestEditionReportsWhatThisInstallationIs(t *testing.T) {
	f := communityFixture(t)

	code, body := f.call(t, "GET", "/api/edition", "", f.rootC)
	if code != http.StatusOK {
		t.Fatalf("GET /api/edition = %d %s", code, body)
	}
	for _, want := range []string{
		`"enterprise":false`,
		`"tenancy":"` + store.TenancySingle + `"`,
		`"tenancyLocked":true`,
		`"primaryTenant":"` + store.DefaultTenantID + `"`,
		features.WhiteLabel, // the roster of what exists, unlocked or not
	} {
		if !strings.Contains(body, want) {
			t.Errorf("edition body misses %q: %s", want, body)
		}
	}

	// With the feature, the switch opens and the mode follows immediately -
	// it is read per request, which is what makes it reversible in a click.
	features.Enable(features.MultiTenant)
	if code, body := f.call(t, "PUT", "/api/settings/tenancy", `{"tenancy":"multi"}`, f.rootC); code != http.StatusOK ||
		!strings.Contains(body, `"tenancy":"`+store.TenancyMulti+`"`) {
		t.Fatalf("switch to multi = %d %s", code, body)
	}
	if code, body := f.call(t, "GET", "/api/edition", "", f.rootC); !strings.Contains(body, `"tenancy":"`+store.TenancyMulti+`"`) {
		t.Fatalf("edition after the switch = %d %s", code, body)
	}
}

// Going back to single with organisations in the way is allowed and deletes
// nothing - they stop being served, and the count is what the console's banner
// says out loud.
func TestSingleModeReportsWhatItHoldsBack(t *testing.T) {
	f := communityFixture(t)
	features.Enable(features.MultiTenant)

	if code, body := f.call(t, "POST", "/api/tenants", `{"name":"acme"}`, f.rootC); code != http.StatusCreated {
		t.Fatalf("create tenant = %d %s", code, body)
	}
	if code, _ := f.call(t, "PUT", "/api/settings/tenancy", `{"tenancy":"single"}`, f.rootC); code != http.StatusOK {
		t.Fatal("switching back must be allowed: nothing is deleted")
	}
	code, body := f.call(t, "GET", "/api/edition", "", f.rootC)
	if code != http.StatusOK || !strings.Contains(body, `"hiddenTenants":1`) {
		t.Fatalf("edition = %d %s, want it to count what is held back", code, body)
	}
	// Still there, just not served.
	if code, body := f.call(t, "GET", "/api/tenants", "", f.rootC); !strings.Contains(body, "acme") {
		t.Fatalf("tenants = %d %s, want acme still stored", code, body)
	}
}

// The stamp is where the console learns what it is BEFORE its first paint.
// Reading /api/edition instead would show the multi-organisation console for a
// frame and then take it away, which reads as a glitch - and a locked control
// appearing unlocked for a frame reads as a tease.
func TestConsoleStampCarriesTheEdition(t *testing.T) {
	f := communityFixture(t)

	stamp := func() string {
		t.Helper()
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(f.rootC)
		return consoleBodyAttrs(req, f.api.st, f.api.sm)
	}

	body := stamp()
	if body == "" {
		t.Fatal("a signed-in console request must be stamped")
	}
	if strings.Contains(body, "multi-tenant") {
		t.Fatalf("single mode must not stamp the multi class: %q", body)
	}
	if strings.Contains(body, "ee-") {
		t.Fatalf("community must stamp no feature class: %q", body)
	}
	if !strings.Contains(body, `data-meerkat-primary-tenant="`+store.DefaultTenantID+`"`) {
		t.Fatalf("the served organisation must travel: %q", body)
	}

	features.Enable(features.MultiTenant, features.Directories)
	if code, _ := f.call(t, "PUT", "/api/settings/tenancy", `{"tenancy":"multi"}`, f.rootC); code != http.StatusOK {
		t.Fatal("switch to multi")
	}
	body = stamp()
	for _, want := range []string{`multi-tenant`, "ee-multi-tenant", "ee-directories"} {
		if !strings.Contains(body, want) {
			t.Errorf("stamp misses %q: %s", want, body)
		}
	}
}
