package auth

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/softwarity/meerkat/internal/mfa"
	"github.com/softwarity/meerkat/internal/session"
	"github.com/softwarity/meerkat/internal/store"
)

// mfaSetup is like setup but hands back the store so a test can enrol the user
// or flip the global MFA policy.
func mfaSetup(t *testing.T) (*http.ServeMux, *session.Manager, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	hash, _ := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.MinCost)
	if err := st.CreateUser(context.Background(), store.User{ID: "u1", Username: "admin", PasswordHash: string(hash), Root: true, Enabled: true}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	sm := session.NewManager(st)
	mux := http.NewServeMux()
	New(st, sm).Register(mux)
	return mux, sm, st
}

func do(t *testing.T, mux *http.ServeMux, method, path string, form url.Values, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func bodyString(rec *httptest.ResponseRecorder) string {
	b, _ := io.ReadAll(rec.Result().Body)
	return string(b)
}

// enrol turns u1 into a TOTP-enrolled user and returns its secret + one usable
// backup code.
func enrol(t *testing.T, st *store.Store) (secret, scratch string) {
	t.Helper()
	s, err := mfa.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	plain, hashes, err := mfa.NewScratchCodes(3)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.EnableUserTOTP(context.Background(), "u1", s, hashes); err != nil {
		t.Fatalf("EnableUserTOTP: %v", err)
	}
	return s, plain[0]
}

func TestLoginChallengesEnrolledUser(t *testing.T) {
	mux, _, st := mfaSetup(t)
	secret, _ := enrol(t, st)

	rec := postLogin(t, mux, url.Values{"username": {"admin"}, "password": {"s3cret"}, "next": {"/app"}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/totp" {
		t.Fatalf("expected redirect to /totp, got %d %q", rec.Code, rec.Header().Get("Location"))
	}
	cookie := rec.Result().Cookies()[0]

	// The challenge page renders.
	page := do(t, mux, "GET", "/totp", nil, cookie)
	if page.Code != http.StatusOK || !strings.Contains(bodyString(page), "Two-factor") {
		t.Fatalf("challenge page: code=%d", page.Code)
	}

	// A wrong code is refused, no progress.
	bad := do(t, mux, "POST", "/totp", url.Values{"code": {"000001"}}, cookie)
	if bad.Code != http.StatusUnprocessableEntity {
		t.Fatalf("wrong code: code=%d, want 422", bad.Code)
	}

	// The live code completes the flow -> the login destination.
	code, _ := mfa.Code(secret, time.Now())
	ok := do(t, mux, "POST", "/totp", url.Values{"code": {code}}, cookie)
	if ok.Code != http.StatusSeeOther || ok.Header().Get("Location") != "/app" {
		t.Fatalf("valid code: code=%d loc=%q, want 303 /app", ok.Code, ok.Header().Get("Location"))
	}
}

func TestChallengeAcceptsScratchCode(t *testing.T) {
	mux, _, st := mfaSetup(t)
	_, scratch := enrol(t, st)

	rec := postLogin(t, mux, url.Values{"username": {"admin"}, "password": {"s3cret"}})
	cookie := rec.Result().Cookies()[0]

	ok := do(t, mux, "POST", "/totp", url.Values{"code": {scratch}}, cookie)
	if ok.Code != http.StatusSeeOther {
		t.Fatalf("scratch code rejected: code=%d", ok.Code)
	}
	// Burned: the same backup code no longer challenges through.
	rec2 := postLogin(t, mux, url.Values{"username": {"admin"}, "password": {"s3cret"}})
	cookie2 := rec2.Result().Cookies()[0]
	reused := do(t, mux, "POST", "/totp", url.Values{"code": {scratch}}, cookie2)
	if reused.Code != http.StatusUnprocessableEntity {
		t.Fatalf("reused scratch code accepted: code=%d", reused.Code)
	}
}

func TestLoginForcesEnrolmentWhenMandatory(t *testing.T) {
	mux, _, st := mfaSetup(t)
	ctx := context.Background()
	if err := st.SetSetting(ctx, store.SettingMFARequired, true); err != nil {
		t.Fatal(err)
	}

	rec := postLogin(t, mux, url.Values{"username": {"admin"}, "password": {"s3cret"}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/totp-enroll" {
		t.Fatalf("expected forced enrolment, got %d %q", rec.Code, rec.Header().Get("Location"))
	}
	cookie := rec.Result().Cookies()[0]

	// The setup page mints a pending secret and shows a QR.
	page := do(t, mux, "GET", "/totp-enroll", nil, cookie)
	if page.Code != http.StatusOK || !strings.Contains(bodyString(page), "required") {
		t.Fatalf("enrol page: code=%d", page.Code)
	}
	pending, err := st.GetUserTOTP(ctx, "u1")
	if err != nil || pending.Pending == "" {
		t.Fatalf("no pending secret minted: %+v %v", pending, err)
	}

	// Confirming with the live code enrols and reveals the backup codes.
	code, _ := mfa.Code(pending.Pending, time.Now())
	confirm := do(t, mux, "POST", "/totp-enroll", url.Values{"step": {"confirm"}, "code": {code}}, cookie)
	if confirm.Code != http.StatusOK || !strings.Contains(bodyString(confirm), "backup codes") {
		t.Fatalf("confirm: code=%d", confirm.Code)
	}
	if st2, _ := st.GetUserTOTP(ctx, "u1"); !st2.Enrolled || len(st2.Scratch) == 0 {
		t.Fatal("user not enrolled after confirm")
	}

	// Acknowledging the codes completes the login flow.
	ack := do(t, mux, "POST", "/totp-enroll", url.Values{"step": {"ack"}}, cookie)
	if ack.Code != http.StatusSeeOther || ack.Header().Get("Location") != "/" {
		t.Fatalf("ack: code=%d loc=%q", ack.Code, ack.Header().Get("Location"))
	}
}

func TestNoMFAWhenNotRequiredAndNotEnrolled(t *testing.T) {
	mux, _, _ := mfaSetup(t)
	rec := postLogin(t, mux, url.Values{"username": {"admin"}, "password": {"s3cret"}, "next": {"/app"}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/app" {
		t.Fatalf("expected straight-through login, got %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func cookieNamed(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestTrustedBrowserSkipsChallenge(t *testing.T) {
	mux, _, st := mfaSetup(t)
	ctx := context.Background()
	secret, _ := enrol(t, st)
	if err := st.SetSetting(ctx, store.SettingTrustedBrowser, store.TrustedBrowserPolicy{Allowed: true, TTL: "P7D"}); err != nil {
		t.Fatal(err)
	}

	// First login is challenged; the challenge page offers to remember the browser.
	rec := postLogin(t, mux, url.Values{"username": {"admin"}, "password": {"s3cret"}, "next": {"/app"}})
	if rec.Header().Get("Location") != "/totp" {
		t.Fatalf("expected /totp, got %q", rec.Header().Get("Location"))
	}
	session := rec.Result().Cookies()[0]
	page := do(t, mux, "GET", "/totp", nil, session)
	if !strings.Contains(bodyString(page), "Trust this browser") {
		t.Fatal("challenge page missing the trust checkbox")
	}

	// Verify AND trust this browser.
	code, _ := mfa.Code(secret, time.Now())
	ok := do(t, mux, "POST", "/totp", url.Values{"code": {code}, "trust": {"1"}}, session)
	if ok.Code != http.StatusSeeOther {
		t.Fatalf("verify+trust: code=%d", ok.Code)
	}
	trust := cookieNamed(ok, "MEERKAT_TRUST")
	if trust == nil || trust.Value == "" {
		t.Fatal("no trusted-browser cookie issued")
	}

	// A later login carrying the trust cookie skips the challenge entirely.
	skip := do(t, mux, "POST", "/login", url.Values{"username": {"admin"}, "password": {"s3cret"}, "next": {"/app"}}, trust)
	if skip.Code != http.StatusSeeOther || skip.Header().Get("Location") != "/app" {
		t.Fatalf("trusted browser should skip MFA: code=%d loc=%q", skip.Code, skip.Header().Get("Location"))
	}

	// Revoking all trusted browsers brings the challenge back.
	revoke := do(t, mux, "POST", "/profile/mfa", url.Values{"step": {"revoke-all"}}, session)
	if revoke.Code != http.StatusSeeOther {
		t.Fatalf("revoke-all: code=%d", revoke.Code)
	}
	rechallenged := do(t, mux, "POST", "/login", url.Values{"username": {"admin"}, "password": {"s3cret"}}, trust)
	if rechallenged.Header().Get("Location") != "/totp" {
		t.Fatalf("after revoke the browser must be challenged again, got %q", rechallenged.Header().Get("Location"))
	}
}

func TestTrustCheckboxHiddenWhenPolicyDisallows(t *testing.T) {
	mux, _, st := mfaSetup(t)
	enrol(t, st) // policy stays at its default (not allowed)
	rec := postLogin(t, mux, url.Values{"username": {"admin"}, "password": {"s3cret"}})
	session := rec.Result().Cookies()[0]
	page := do(t, mux, "GET", "/totp", nil, session)
	if strings.Contains(bodyString(page), "Trust this browser") {
		t.Fatal("trust checkbox shown while the policy forbids it")
	}
}

func TestProfilePasswordDedicatedPage(t *testing.T) {
	mux, _, _ := mfaSetup(t)
	rec := postLogin(t, mux, url.Values{"username": {"admin"}, "password": {"s3cret"}})
	cookie := rec.Result().Cookies()[0]

	// The profile links to the Security hub, which links the dedicated page.
	prof := do(t, mux, "GET", "/profile", nil, cookie)
	if !strings.Contains(bodyString(prof), `href="/profile/security"`) {
		t.Fatal("profile is missing the Security link")
	}
	sec := do(t, mux, "GET", "/profile/security", nil, cookie)
	if !strings.Contains(bodyString(sec), `href="/profile/password"`) {
		t.Fatal("security page is missing the change-password link")
	}
	page := do(t, mux, "GET", "/profile/password", nil, cookie)
	if page.Code != http.StatusOK || !strings.Contains(bodyString(page), "Change your password") {
		t.Fatalf("dedicated password page: code=%d", page.Code)
	}

	// A wrong current password re-renders the dedicated page with the error.
	bad := do(t, mux, "POST", "/profile/password",
		url.Values{"current": {"wrong"}, "password": {"newpass123"}, "confirm": {"newpass123"}}, cookie)
	if bad.Code != http.StatusUnprocessableEntity || !strings.Contains(bodyString(bad), "current password is incorrect") {
		t.Fatalf("wrong current: code=%d", bad.Code)
	}

	// A valid change returns to the profile.
	ok := do(t, mux, "POST", "/profile/password",
		url.Values{"current": {"s3cret"}, "password": {"newpass123"}, "confirm": {"newpass123"}}, cookie)
	if ok.Code != http.StatusSeeOther || ok.Header().Get("Location") != "/profile" {
		t.Fatalf("valid change: code=%d loc=%q", ok.Code, ok.Header().Get("Location"))
	}
}

func TestProfileShowsMFAState(t *testing.T) {
	mux, _, st := mfaSetup(t)
	rec := postLogin(t, mux, url.Values{"username": {"admin"}, "password": {"s3cret"}})
	cookie := rec.Result().Cookies()[0]

	off := do(t, mux, "GET", "/profile/security", nil, cookie)
	if !strings.Contains(bodyString(off), "Two-factor") {
		t.Fatal("security page missing the two-factor row")
	}

	enrol(t, st)
	manage := do(t, mux, "GET", "/profile/mfa", nil, cookie)
	if manage.Code != http.StatusOK || !strings.Contains(bodyString(manage), "Backup codes remaining") {
		t.Fatalf("manage page: code=%d", manage.Code)
	}
	// Disable turns it off and returns to the profile.
	disable := do(t, mux, "POST", "/profile/mfa", url.Values{"step": {"disable"}}, cookie)
	if disable.Code != http.StatusSeeOther || disable.Header().Get("Location") != "/profile" {
		t.Fatalf("disable: code=%d loc=%q", disable.Code, disable.Header().Get("Location"))
	}
	if s, _ := st.GetUserTOTP(context.Background(), "u1"); s.Enrolled {
		t.Fatal("TOTP still enrolled after disable")
	}
}
