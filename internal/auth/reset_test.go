package auth

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/softwarity/meerkat/internal/store"
)

var resetLink = regexp.MustCompile(`/reset-password\?token=[A-Za-z0-9_-]+`)

// TestForgotPasswordFullFlow: request -> mailed one-shot link (peek on GET,
// consume on POST) -> new password works, old one dies, every session is
// revoked, the owner is notified, the link never replays.
func TestForgotPasswordFullFlow(t *testing.T) {
	mux, sm, st, box := registerSetup(t) // SMTP configured + recording mailbox
	ctx := context.Background()

	// The login page offers the link once SMTP is configured.
	if rec := do(t, mux, "GET", "/login", nil, nil); !strings.Contains(bodyString(rec), "/forgot-password") {
		t.Fatalf("login page must link the reset flow")
	}

	// A real account with a known password and an open session to kill.
	hash, err := bcrypt.GenerateFromPassword([]byte("old-pass-1234"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUser(ctx, store.User{
		ID: "alice", Username: "alice", PasswordHash: string(hash),
		Email: "alice@example.org", Enabled: true, EmailVerified: true,
	}); err != nil {
		t.Fatal(err)
	}
	aliceLogin := do(t, mux, "POST", "/login", url.Values{"username": {"alice"}, "password": {"old-pass-1234"}}, nil)
	if aliceLogin.Code != http.StatusSeeOther {
		t.Fatalf("alice login: %d", aliceLogin.Code)
	}
	aliceCookie := sessionCookieOf(aliceLogin)

	// Ask for a reset: neutral outcome, one mail with the link.
	rec := do(t, mux, "POST", "/forgot-password", url.Values{"email": {"alice@example.org"}}, nil)
	if rec.Code != http.StatusOK || !strings.Contains(bodyString(rec), "Check your inbox") {
		t.Fatalf("forgot: %d", rec.Code)
	}
	mails := box.forRecipient("alice@example.org")
	if len(mails) != 1 {
		t.Fatalf("reset mails: %d, want 1", len(mails))
	}
	link := resetLink.FindString(mails[0].Text)
	if link == "" {
		t.Fatalf("no reset link in %q", mails[0].Text)
	}
	token := strings.TrimPrefix(link, "/reset-password?token=")

	// An unknown address answers the SAME page and sends nothing.
	rec = do(t, mux, "POST", "/forgot-password", url.Values{"email": {"ghost@example.org"}}, nil)
	if rec.Code != http.StatusOK || !strings.Contains(bodyString(rec), "Check your inbox") {
		t.Fatalf("unknown address must answer neutrally: %d", rec.Code)
	}
	if got := box.forRecipient("ghost@example.org"); len(got) != 0 {
		t.Fatalf("nothing may be sent to an unknown address")
	}

	// GET peeks without consuming: twice is fine (mail scanners prefetch).
	for i := 0; i < 2; i++ {
		if page := do(t, mux, "GET", link, nil, nil); page.Code != http.StatusOK {
			t.Fatalf("GET reset #%d: %d", i+1, page.Code)
		}
	}

	// POST consumes and sets the new password.
	form := url.Values{"token": {token}, "password": {"brand-new-pass-1"}, "confirm": {"brand-new-pass-1"}}
	done := do(t, mux, "POST", "/reset-password", form, nil)
	if done.Code != http.StatusOK || !strings.Contains(bodyString(done), "updated") {
		t.Fatalf("reset: %d", done.Code)
	}
	// The owner got the changed-password notice (2 mails total now).
	if got := box.forRecipient("alice@example.org"); len(got) != 2 {
		t.Fatalf("mails after reset: %d, want 2 (link + notice)", len(got))
	}
	// One shot: replaying the link is dead, on GET and POST alike.
	if again := do(t, mux, "GET", link, nil, nil); again.Code != http.StatusUnprocessableEntity {
		t.Fatalf("replayed GET: %d", again.Code)
	}
	if again := do(t, mux, "POST", "/reset-password", form, nil); again.Code != http.StatusUnprocessableEntity {
		t.Fatalf("replayed POST: %d", again.Code)
	}

	// Alice's old session died with the old password.
	if rec := do(t, mux, "GET", "/profile", nil, aliceCookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("old session must be revoked: %d", rec.Code)
	}
	_ = sm
	// Old password refused, new one accepted.
	if rec := do(t, mux, "POST", "/login", url.Values{"username": {"alice"}, "password": {"old-pass-1234"}}, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("old password: %d, want 401", rec.Code)
	}
	if rec := do(t, mux, "POST", "/login", url.Values{"username": {"alice"}, "password": {"brand-new-pass-1"}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("new password: %d, want 303", rec.Code)
	}
}
