package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/softwarity/meerkat/internal/idp"
	"github.com/softwarity/meerkat/internal/session"
	"github.com/softwarity/meerkat/internal/store"
)

// The rule this whole feature exists for: an authority proves WHO someone is,
// it never decides what they may do here. A first sign-in therefore behaves
// exactly like a self-registration — an account appears, it reaches nothing,
// and an admin has to place it.

func externalFixture(t *testing.T) (*Handler, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	h := New(st, session.NewManager(st))
	if err := st.SaveAuthProvider(context.Background(), store.AuthProvider{
		ID: "acme", Kind: store.ProviderOIDC, Name: "Acme SSO", Enabled: true, AutoCreate: true,
		Config: map[string]any{"issuer": "https://issuer.test", "clientId": "meerkat"},
	}); err != nil {
		t.Fatal(err)
	}
	return h, st
}

func TestFirstExternalSignInCreatesAPendingAccount(t *testing.T) {
	h, st := externalFixture(t)
	ctx := context.Background()
	p, err := st.GetAuthProvider(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}

	id := idp.Identity{
		Subject: "sub-1", Username: "jdoe", Email: "jdoe@acme.io",
		EmailVerified: true, Fullname: "J. Doe", Groups: []string{"staff"},
	}
	user, created, err := h.linkOrCreate(ctx, p, id)
	if err != nil {
		t.Fatalf("first sign-in: %v", err)
	}
	if !created {
		t.Fatal("a first sign-in must create the account")
	}
	if user.Username != "jdoe" || user.Email != "jdoe@acme.io" {
		t.Fatalf("account: %+v", user)
	}
	// No local password: this account only comes in through its authority.
	if user.PasswordHash != "" {
		t.Fatal("an external account must carry no local password")
	}
	// The authority vouched for the address, so no confirmation mail is owed.
	if !user.EmailVerified {
		t.Fatal("a verified address must not be re-confirmed by us")
	}
	// And it reaches NOTHING until an admin acts: that is the waiting room.
	if !waitingRoom(user, 0) {
		t.Fatalf("a fresh external account must land in the waiting room: %+v", user)
	}

	// Signing in again finds the SAME account through the link, and creates
	// nothing — even if the authority renamed the person meanwhile.
	renamed := id
	renamed.Username = "john.doe"
	again, created, err := h.linkOrCreate(ctx, p, renamed)
	if err != nil {
		t.Fatalf("second sign-in: %v", err)
	}
	if created || again.ID != user.ID {
		t.Fatalf("the subject must key the account, got created=%v id=%s want %s", created, again.ID, user.ID)
	}
}

// TestReportedGroupsFollowEverySignIn: what the authority says about someone's
// groups is a fact of the LAST sign-in. Recording it only on the day the link
// was made would describe someone who has since changed teams, and every
// mapping written against it would act on stale membership.
func TestReportedGroupsFollowEverySignIn(t *testing.T) {
	h, st := externalFixture(t)
	ctx := context.Background()
	p, err := st.GetAuthProvider(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	id := idp.Identity{Subject: "sub-1", Username: "jdoe", Groups: []string{"staff", "eng"}}
	user, _, err := h.linkOrCreate(ctx, p, id)
	if err != nil {
		t.Fatal(err)
	}
	groupsOf := func() []string {
		links, err := st.IdentitiesOfUser(ctx, user.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(links) != 1 {
			t.Fatalf("want one identity link, got %d", len(links))
		}
		return links[0].Groups
	}
	if got := groupsOf(); !reflect.DeepEqual(got, []string{"staff", "eng"}) {
		t.Fatalf("groups at creation: %v", got)
	}

	// The person moves team upstream, and signs in again.
	moved := id
	moved.Groups = []string{"staff", "support"}
	if _, created, err := h.linkOrCreate(ctx, p, moved); err != nil || created {
		t.Fatalf("second sign-in: created=%v err=%v", created, err)
	}
	if got := groupsOf(); !reflect.DeepEqual(got, []string{"staff", "support"}) {
		t.Fatalf("groups must follow the authority, got %v", got)
	}

	// And an authority that stops reporting any group clears them rather than
	// leaving a membership nobody can see the source of.
	silent := id
	silent.Groups = nil
	if _, _, err := h.linkOrCreate(ctx, p, silent); err != nil {
		t.Fatal(err)
	}
	if got := groupsOf(); len(got) != 0 {
		t.Fatalf("no group reported should mean none stored, got %v", got)
	}
}

// TestExternalLinksAVerifiedAddressOnly is the account-takeover guard: an
// authority that does NOT vouch for an address must never inherit the local
// account holding it.
func TestExternalLinksAVerifiedAddressOnly(t *testing.T) {
	h, st := externalFixture(t)
	ctx := context.Background()
	p, _ := st.GetAuthProvider(ctx, "acme")

	local := store.User{
		ID: "local-1", Username: "alice", Email: "alice@acme.io",
		Enabled: true, EmailVerified: true, PasswordHash: "x",
	}
	if err := st.CreateUser(ctx, local); err != nil {
		t.Fatal(err)
	}

	// Unverified: a new account, the local one is left alone.
	got, created, err := h.linkOrCreate(ctx, p, idp.Identity{
		Subject: "sub-evil", Username: "alice", Email: "alice@acme.io", EmailVerified: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !created || got.ID == local.ID {
		t.Fatal("an unverified address must not take over the local account")
	}

	// Verified: the SAME account, now reachable through the authority too, so
	// someone moving to SSO keeps their tenants and their roles.
	got, created, err = h.linkOrCreate(ctx, p, idp.Identity{
		Subject: "sub-alice", Username: "alice", Email: "alice@acme.io", EmailVerified: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if created || got.ID != local.ID {
		t.Fatalf("a verified address must link the existing account, got created=%v id=%s", created, got.ID)
	}
	linked, err := st.UserByIdentity(ctx, "acme", "sub-alice")
	if err != nil || linked.ID != local.ID {
		t.Fatalf("the link was not recorded: %v %+v", err, linked)
	}
}

// TestExternalWithoutAutoCreateRefuses: an authority may authenticate people
// this installation has not invited.
func TestExternalWithoutAutoCreateRefuses(t *testing.T) {
	h, st := externalFixture(t)
	ctx := context.Background()
	p, _ := st.GetAuthProvider(ctx, "acme")
	p.AutoCreate = false
	if err := st.SaveAuthProvider(ctx, p); err != nil {
		t.Fatal(err)
	}
	p, _ = st.GetAuthProvider(ctx, "acme")

	_, _, err := h.linkOrCreate(ctx, p, idp.Identity{
		Subject: "sub-2", Username: "bob", Email: "bob@acme.io", EmailVerified: true,
	})
	if err == nil {
		t.Fatal("without auto-create, an unknown person must be refused")
	}
}

// TestExternalUsernameCollision: two authorities may both know a "jdoe", and
// the second one must not fail nor steal the first one's account.
func TestExternalUsernameCollision(t *testing.T) {
	h, st := externalFixture(t)
	ctx := context.Background()
	if err := st.SaveAuthProvider(ctx, store.AuthProvider{
		ID: "other", Kind: store.ProviderOIDC, Name: "Other", Enabled: true, AutoCreate: true,
		Config: map[string]any{"issuer": "https://other.test", "clientId": "meerkat"},
	}); err != nil {
		t.Fatal(err)
	}
	acme, _ := st.GetAuthProvider(ctx, "acme")
	other, _ := st.GetAuthProvider(ctx, "other")

	first, _, err := h.linkOrCreate(ctx, acme, idp.Identity{Subject: "a1", Username: "jdoe"})
	if err != nil {
		t.Fatal(err)
	}
	second, created, err := h.linkOrCreate(ctx, other, idp.Identity{Subject: "b1", Username: "jdoe"})
	if err != nil {
		t.Fatalf("the second authority must still enrol its own person: %v", err)
	}
	if !created || second.ID == first.ID {
		t.Fatal("two authorities' people must not collapse into one account")
	}
	if second.Username == first.Username {
		t.Fatalf("the second username must be made free, both are %q", first.Username)
	}
	if !strings.HasPrefix(second.Username, "jdoe") {
		t.Fatalf("the suffixed name should still read as the original: %q", second.Username)
	}
}

// TestLoginPageOffersTheAuthorities: an enabled OIDC authority gets a button,
// a directory does not (it answers the ordinary form), and a disabled one is
// nowhere to be seen.
func TestLoginPageOffersTheAuthorities(t *testing.T) {
	h, st := externalFixture(t)
	ctx := context.Background()
	for _, p := range []store.AuthProvider{
		{ID: "dir", Kind: store.ProviderLDAP, Name: "Company directory", Enabled: true,
			Config: map[string]any{"url": "ldap://dir.test", "baseDn": "dc=test"}},
		{ID: "off", Kind: store.ProviderOIDC, Name: "Retired SSO", Enabled: false,
			Config: map[string]any{"issuer": "https://off.test", "clientId": "x"}},
	} {
		if err := st.SaveAuthProvider(ctx, p); err != nil {
			t.Fatal(err)
		}
	}

	rec := httptest.NewRecorder()
	h.showLogin(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
	body := rec.Body.String()
	if !strings.Contains(body, `/login/acme`) || !strings.Contains(body, "Acme SSO") {
		t.Fatalf("the enabled authority has no button:\n%s", body)
	}
	if strings.Contains(body, "Company directory") {
		t.Fatal("a directory needs no button: it answers the ordinary form")
	}
	if strings.Contains(body, "Retired SSO") {
		t.Fatal("a disabled authority must not be offered")
	}
}
