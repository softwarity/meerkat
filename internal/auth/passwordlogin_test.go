package auth

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/softwarity/meerkat/internal/mail"
	"github.com/softwarity/meerkat/internal/session"
	"github.com/softwarity/meerkat/internal/store"
)

// The accounts held here are an AUTHORITY like any other (AUTH-24), and
// disabling it is what makes the remaining ones exclusive. Everything below
// guards the two ways that goes wrong: locking the console out, and closing the
// form a DIRECTORY still needs.

// planes builds a store with one root and one ordinary user, plus the data
// plane and the admin plane serving it.
func planes(t *testing.T) (*store.Store, *http.ServeMux, *http.ServeMux) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	hash, _ := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.MinCost)
	ctx := context.Background()
	for _, u := range []store.User{
		{ID: "root", Username: "admin", PasswordHash: string(hash), Root: true, Enabled: true},
		{ID: "u1", Username: "bob", PasswordHash: string(hash), Enabled: true},
	} {
		if err := st.CreateUser(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	data, admin := http.NewServeMux(), http.NewServeMux()
	New(st, session.NewManager(st)).Register(data)
	NewAdmin(st, session.NewManager(st, session.ForAdminPlane())).Register(admin)
	return st, data, admin
}

func signIn(t *testing.T, mux *http.ServeMux, username string) int {
	t.Helper()
	form := url.Values{"username": {username}, "password": {"s3cret"}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec.Code
}

// setLocalSignIn flips the seeded local-accounts authority, the way the infra
// screen does.
func setLocalSignIn(t *testing.T, st *store.Store, enabled bool) {
	t.Helper()
	ctx := context.Background()
	p, err := st.GetAuthProvider(ctx, store.LocalProviderID)
	if err != nil {
		t.Fatalf("the local authority must be seeded: %v", err)
	}
	p.Enabled = enabled
	if err := st.SaveAuthProvider(ctx, p); err != nil {
		t.Fatal(err)
	}
}

func TestLocalAccountsAuthority(t *testing.T) {
	st, data, admin := planes(t)

	// Seeded and on: an install that never touches it signs in as before.
	if code := signIn(t, data, "bob"); code != http.StatusSeeOther {
		t.Fatalf("the local authority must be enabled out of the box, got %d", code)
	}

	// Disabled: the data plane takes no local password at all, root included.
	// A correct password is refused exactly like a wrong one - nothing is
	// enumerated.
	setLocalSignIn(t, st, false)
	for _, who := range []string{"bob", "admin"} {
		if code := signIn(t, data, who); code != http.StatusUnauthorized {
			t.Fatalf("a disabled local authority must refuse %s on the data plane, got %d", who, code)
		}
	}

	// And THE rule that keeps an installation recoverable: the console still
	// answers a local password. It is what one repairs a broken authority with.
	if code := signIn(t, admin, "admin"); code != http.StatusSeeOther {
		t.Fatalf("the console must stay reachable with the local authority off, got %d", code)
	}
}

// TestClosedPasswordKeepsTheDirectoryForm: the username/password form serves
// TWO mechanisms. Hiding it because the local accounts are off would take the
// directory down with it - the field is how a directory is asked.
func TestClosedPasswordKeepsTheDirectoryForm(t *testing.T) {
	st, data, _ := planes(t)
	setLocalSignIn(t, st, false)

	form := func() string {
		rec := httptest.NewRecorder()
		data.ServeHTTP(rec, httptest.NewRequest("GET", "/login", nil))
		body, _ := io.ReadAll(rec.Result().Body)
		return string(body)
	}
	// No directory: nothing can answer the form, so it goes.
	if strings.Contains(form(), `name="password"`) {
		t.Fatal("with nothing left to answer it, the form must not be shown")
	}

	// A directory appears: the form comes back, because that is how it is
	// asked, even though no LOCAL password is accepted any more.
	if err := st.SaveAuthProvider(context.Background(), store.AuthProvider{
		ID: "acme", Kind: store.ProviderLDAP, Name: "Acme Directory", Enabled: true,
		Config: map[string]any{"url": "ldaps://ldap.acme.io", "baseDn": "dc=acme,dc=io"},
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(form(), `name="password"`) {
		t.Fatal("a directory answers through this form: it must stay")
	}
}

// TestClosingThePasswordClosesTheDeadEnds: the two journeys that succeed at
// every step and help nobody once no local password is accepted.
//
// Signing up mints a LOCAL account with a local password: where that password
// is refused, the newcomer confirms their address, chooses a password, and
// lands on a form that will never take it. Resetting is the same story, one
// step longer.
func TestClosingThePasswordClosesTheDeadEnds(t *testing.T) {
	st, _, _ := planes(t)
	ctx := context.Background()
	// Both journeys need a mailer WIRED, not just a relay configured, so the
	// planes are rebuilt here rather than taken from the helper.
	mailer := func(context.Context, mail.Message) error { return nil }
	h := New(st, session.NewManager(st))
	h.Mailer = mailer
	data := http.NewServeMux()
	h.Register(data)
	ah := NewAdmin(st, session.NewManager(st, session.ForAdminPlane()))
	ah.Mailer = mailer
	admin := http.NewServeMux()
	ah.Register(admin)
	// Both journeys need outbound mail before they are reachable at all.
	if err := st.SetSetting(ctx, store.SettingSMTP, mail.Config{
		Host: "smtp.example.com", Port: 587, From: "no-reply@example.com",
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting(ctx, store.SettingRegistration,
		store.RegistrationPolicy{LocalEnabled: true}); err != nil {
		t.Fatal(err)
	}

	reachable := func(mux *http.ServeMux, path string) bool {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		return rec.Code != http.StatusNotFound
	}

	// Local accounts on: both are open, as they have always been.
	if !reachable(data, "/register") || !reachable(data, "/forgot-password") {
		t.Fatal("nothing should change while the local accounts open the data plane")
	}

	// Off: neither has any purpose left on the data plane.
	setLocalSignIn(t, st, false)
	if reachable(data, "/register") || reachable(data, "/forgot-password") {
		t.Fatal("both must close once no local password opens the data plane")
	}

	// And the admin plane is untouched throughout: it is the tool one repairs a
	// broken authority with.
	if !reachable(admin, "/forgot-password") {
		t.Fatal("the console must keep its own way back in")
	}
}
