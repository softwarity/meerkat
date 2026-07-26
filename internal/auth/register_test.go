package auth

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/softwarity/meerkat/internal/mail"
	"github.com/softwarity/meerkat/internal/session"
	"github.com/softwarity/meerkat/internal/store"
)

// fakeMailbox records outbound mail instead of sending it.
type fakeMailbox struct {
	sync.Mutex
	sent []mail.Message
}

func (f *fakeMailbox) send(_ context.Context, m mail.Message) error {
	f.Lock()
	defer f.Unlock()
	f.sent = append(f.sent, m)
	return nil
}

func (f *fakeMailbox) forRecipient(to string) []mail.Message {
	f.Lock()
	defer f.Unlock()
	var out []mail.Message
	for _, m := range f.sent {
		for _, rcpt := range m.To {
			if rcpt == to {
				out = append(out, m)
			}
		}
	}
	return out
}

// registerSetup opens self-registration (policy + SMTP present) and wires a
// recording mailbox.
func registerSetup(t *testing.T) (*http.ServeMux, *session.Manager, *store.Store, *fakeMailbox) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	if err := st.SetSetting(ctx, store.SettingSMTP, mail.Config{Host: "smtp.test", From: "meerkat@test"}); err != nil {
		t.Fatal(err)
	}
	// Captcha off for the flow tests — TestRegisterCaptcha covers it on.
	if err := st.SetSetting(ctx, store.SettingRegistration,
		store.RegistrationPolicy{LocalEnabled: true, CaptchaDisabled: true}); err != nil {
		t.Fatal(err)
	}
	// One notifiable admin: app-admin with an address.
	if err := st.CreateUser(ctx, store.User{
		ID: "boss", Username: "boss", PasswordHash: "x", Email: "boss@test",
		AppAdmin: true, Enabled: true, EmailVerified: true,
	}); err != nil {
		t.Fatal(err)
	}
	sm := session.NewManager(st)
	mux := http.NewServeMux()
	h := New(st, sm)
	box := &fakeMailbox{}
	h.Mailer = box.send
	h.Register(mux)
	return mux, sm, st, box
}

var confirmLink = regexp.MustCompile(`/confirm\?token=[A-Za-z0-9_-]+`)

func TestSelfRegistrationFullFlow(t *testing.T) {
	mux, _, st, box := registerSetup(t)

	// The register page is served while the policy is on.
	if rec := do(t, mux, "GET", "/register", nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("GET /register: %d", rec.Code)
	}

	form := url.Values{
		"username": {"bob"}, "email": {"bob@example.org"}, "fullname": {"Bob Léponge"},
		"password": {"s3cret-s3cret"}, "confirm": {"s3cret-s3cret"},
	}
	rec := do(t, mux, "POST", "/register", form, nil)
	if rec.Code != http.StatusOK || !strings.Contains(bodyString(rec), "Check your inbox") {
		t.Fatalf("register: %d %s", rec.Code, bodyString(rec))
	}
	mails := box.forRecipient("bob@example.org")
	if len(mails) != 1 {
		t.Fatalf("confirmation mails: %d, want 1", len(mails))
	}
	link := confirmLink.FindString(mails[0].Text)
	if link == "" {
		t.Fatalf("no confirmation link in %q", mails[0].Text)
	}

	// Before confirming: the CORRECT password answers "check your inbox"
	// (and re-sends), never a session.
	login := do(t, mux, "POST", "/login", url.Values{"username": {"bob"}, "password": {"s3cret-s3cret"}}, nil)
	if login.Code != http.StatusOK || !strings.Contains(bodyString(login), "Check your inbox") {
		t.Fatalf("unconfirmed login: %d", login.Code)
	}
	if len(login.Result().Cookies()) != 0 {
		t.Fatalf("no session may be issued before confirmation")
	}

	// The mailed link confirms the account and notifies the app-admin.
	conf := do(t, mux, "GET", link, nil, nil)
	if conf.Code != http.StatusOK || !strings.Contains(bodyString(conf), "confirmed") {
		t.Fatalf("confirm: %d %s", conf.Code, bodyString(conf))
	}
	if notif := box.forRecipient("boss@test"); len(notif) != 1 || !strings.Contains(notif[0].Text, "bob") {
		t.Fatalf("admin notification: %+v", notif)
	}
	// One shot: the same link is dead now.
	if again := do(t, mux, "GET", link, nil, nil); again.Code != http.StatusUnprocessableEntity {
		t.Fatalf("re-used confirm link: %d", again.Code)
	}

	// After confirming: sign-in works and lands on the waiting room (no
	// membership, no capability).
	login = do(t, mux, "POST", "/login", url.Values{"username": {"bob"}, "password": {"s3cret-s3cret"}}, nil)
	if login.Code != http.StatusSeeOther || login.Header().Get("Location") != "/account-pending" {
		t.Fatalf("confirmed login: %d -> %q", login.Code, login.Header().Get("Location"))
	}
	var sessionCookie *http.Cookie
	for _, c := range login.Result().Cookies() {
		if c.Name != browserCookieName {
			sessionCookie = c
		}
	}
	pending := do(t, mux, "GET", "/account-pending", nil, sessionCookie)
	if pending.Code != http.StatusOK || !strings.Contains(bodyString(pending), "awaiting access") {
		t.Fatalf("pending page: %d", pending.Code)
	}

	// Anti-enumeration: retaking the username answers the SAME page and
	// creates nothing.
	rec = do(t, mux, "POST", "/register", form, nil)
	if rec.Code != http.StatusOK || !strings.Contains(bodyString(rec), "Check your inbox") {
		t.Fatalf("duplicate register: %d", rec.Code)
	}
	if _, err := st.GetUserByUsername(context.Background(), "bob"); err != nil {
		t.Fatalf("original bob must survive: %v", err)
	}
}

// TestRegisterCaptcha: with the check on (the default), the page carries the
// image, a wrong copy consumes the challenge and creates nothing, a right
// copy passes, and a challenge can never be replayed.
func TestRegisterCaptcha(t *testing.T) {
	mux, _, st, _ := registerSetup(t)
	ctx := context.Background()
	if err := st.SetSetting(ctx, store.SettingRegistration,
		store.RegistrationPolicy{LocalEnabled: true}); err != nil { // captcha on
		t.Fatal(err)
	}

	page := do(t, mux, "GET", "/register", nil, nil)
	if body := bodyString(page); !strings.Contains(body, `name="captcha_id"`) ||
		!strings.Contains(body, "data:image/png;base64,") {
		t.Fatalf("register page must carry the captcha: status=%d body=%.400s", page.Code, body)
	}

	form := func(id, answer string) url.Values {
		return url.Values{
			"username": {"carl"}, "email": {"carl@example.org"},
			"password": {"s3cret-s3cret"}, "confirm": {"s3cret-s3cret"},
			"captcha_id": {id}, "captcha": {answer},
		}
	}
	// A wrong answer against a planted challenge: refused, nothing created.
	if err := st.PutChallenge(ctx, "captcha:t1", hashTrust("24689"), time.Now().Add(time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}
	rec := do(t, mux, "POST", "/register", form("t1", "11111"), nil)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("wrong captcha: %d, want 422", rec.Code)
	}
	if _, err := st.GetUserByUsername(ctx, "carl"); err == nil {
		t.Fatalf("no account may be created on a wrong captcha")
	}
	// The challenge was consumed: the right answer on the SAME id fails too.
	rec = do(t, mux, "POST", "/register", form("t1", "24689"), nil)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("replayed captcha: %d, want 422", rec.Code)
	}
	// A fresh challenge with the right answer goes through.
	if err := st.PutChallenge(ctx, "captcha:t2", hashTrust("35792"), time.Now().Add(time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}
	rec = do(t, mux, "POST", "/register", form("t2", "35792"), nil)
	if rec.Code != http.StatusOK || !strings.Contains(bodyString(rec), "Check your inbox") {
		t.Fatalf("right captcha: %d", rec.Code)
	}
	if _, err := st.GetUserByUsername(ctx, "carl"); err != nil {
		t.Fatalf("account must exist after a right captcha: %v", err)
	}
}

func TestRegisterClosedWithoutPolicy(t *testing.T) {
	mux, _, st, _ := registerSetup(t)
	if err := st.SetSetting(context.Background(), store.SettingRegistration,
		store.RegistrationPolicy{LocalEnabled: false}); err != nil {
		t.Fatal(err)
	}
	if rec := do(t, mux, "GET", "/register", nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("closed /register: %d, want 404", rec.Code)
	}
	// And the login page offers no register link.
	if rec := do(t, mux, "GET", "/login", nil, nil); strings.Contains(bodyString(rec), "/register") {
		t.Fatalf("login page must not link /register while closed")
	}
}
