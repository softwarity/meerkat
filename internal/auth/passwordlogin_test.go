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

// Closing the local password (AUTH-24) is what makes an external authority
// exclusive. Everything below guards the two ways that goes wrong: locking the
// console out, and closing the form a DIRECTORY still needs.

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

func setPasswordLogin(t *testing.T, st *store.Store, mode string) {
	t.Helper()
	if err := st.SetSetting(context.Background(), store.SettingPasswordLogin,
		store.PasswordLoginPolicy{Mode: mode}); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordLoginModes(t *testing.T) {
	st, data, admin := planes(t)

	// Everyone (the default): unchanged for an install with no authority.
	if code := signIn(t, data, "bob"); code != http.StatusSeeOther {
		t.Fatalf("default mode must let an ordinary user in, got %d", code)
	}

	// Admins only: the operators keep a door, the users go through their
	// authority. A correct password is refused exactly like a wrong one.
	setPasswordLogin(t, st, store.PasswordLoginAdmins)
	if code := signIn(t, data, "bob"); code != http.StatusUnauthorized {
		t.Fatalf("admins-only must refuse an ordinary user, got %d", code)
	}
	if code := signIn(t, data, "admin"); code != http.StatusSeeOther {
		t.Fatalf("admins-only must still let root in, got %d", code)
	}

	// Nobody: the data plane is closed to local passwords, root included.
	setPasswordLogin(t, st, store.PasswordLoginNobody)
	for _, who := range []string{"bob", "admin"} {
		if code := signIn(t, data, who); code != http.StatusUnauthorized {
			t.Fatalf("nobody must refuse %s on the data plane, got %d", who, code)
		}
	}

	// And THE rule that keeps an installation recoverable: whatever the
	// setting, the console still answers a local password. It is what one
	// repairs a broken authority with.
	for _, mode := range []string{store.PasswordLoginAdmins, store.PasswordLoginNobody} {
		setPasswordLogin(t, st, mode)
		if code := signIn(t, admin, "admin"); code != http.StatusSeeOther {
			t.Fatalf("the console must stay reachable in mode %q, got %d", mode, code)
		}
	}
}

// TestClosedPasswordKeepsTheDirectoryForm: the username/password form serves
// TWO mechanisms. Hiding it because the local password is closed would take
// the directory down with it — the field is how a directory is asked.
func TestClosedPasswordKeepsTheDirectoryForm(t *testing.T) {
	st, data, _ := planes(t)
	setPasswordLogin(t, st, store.PasswordLoginNobody)

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
// every step and help nobody once the local password is refused.
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

	// Everyone: both are open, as they have always been.
	setPasswordLogin(t, st, store.PasswordLoginEveryone)
	if !reachable(data, "/register") || !reachable(data, "/forgot-password") {
		t.Fatal("nothing should change while the local password opens the data plane")
	}

	// Admins only: a newcomer is not an administrator, so signing up leads
	// nowhere. Resetting stays: an administrator keeps a password worth
	// resetting.
	setPasswordLogin(t, st, store.PasswordLoginAdmins)
	if reachable(data, "/register") {
		t.Fatal("self-registration must close: a newcomer could not sign in with what it creates")
	}
	if !reachable(data, "/forgot-password") {
		t.Fatal("an administrator still has a password worth resetting")
	}

	// Nobody: neither has any purpose left on the data plane.
	setPasswordLogin(t, st, store.PasswordLoginNobody)
	if reachable(data, "/register") || reachable(data, "/forgot-password") {
		t.Fatal("both must close once no local password opens the data plane")
	}

	// And the admin plane is untouched throughout: it is the tool one repairs a
	// broken authority with.
	if !reachable(admin, "/forgot-password") {
		t.Fatal("the console must keep its own way back in")
	}
}

// TestResetMailFollowsTheAccount: under "admins only" the reset page answers
// the same to everyone — saying otherwise would be a better enumeration oracle
// than the address itself — but only an account that may still USE a password
// is sent one.
func TestResetMailFollowsTheAccount(t *testing.T) {
	st, _, _ := planes(t)
	ctx := context.Background()
	if err := st.SetSetting(ctx, store.SettingSMTP, mail.Config{
		Host: "smtp.example.com", Port: 587, From: "no-reply@example.com",
	}); err != nil {
		t.Fatal(err)
	}
	for id, addr := range map[string]string{"root": "root@example.com", "u1": "bob@example.com"} {
		u, err := st.GetUserByID(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		u.Email, u.EmailVerified = addr, true
		if err := st.UpdateUser(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	setPasswordLogin(t, st, store.PasswordLoginAdmins)

	var sent []string
	h := New(st, session.NewManager(st))
	h.Mailer = func(_ context.Context, msg mail.Message) error {
		sent = append(sent, msg.To...)
		return nil
	}
	mux := http.NewServeMux()
	h.Register(mux)

	ask := func(email string) int {
		form := url.Values{"email": {email}}
		req := httptest.NewRequest("POST", "/forgot-password", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := ask("root@example.com"); code != http.StatusOK {
		t.Fatalf("root: %d", code)
	}
	if code := ask("bob@example.com"); code != http.StatusOK {
		t.Fatalf("bob: %d — the answer must not depend on the account", code)
	}
	if len(sent) != 1 || sent[0] != "root@example.com" {
		t.Fatalf("only the account that may still use a password gets a mail, got %v", sent)
	}
}
