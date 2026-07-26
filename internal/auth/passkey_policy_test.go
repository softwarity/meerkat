package auth

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/softwarity/meerkat/internal/store"
)

// TestPasskeysDisabledHidesAndRefuses: flipping the gateway-wide policy off
// removes the passkey affordances (login button, profile section) AND refuses
// the ceremonies server-side; the default ships on.
func TestPasskeysDisabledHidesAndRefuses(t *testing.T) {
	mux, _, st := mfaSetup(t)

	// Default: the login page offers the passkey sign-in.
	rec := do(t, mux, "GET", "/login", nil, nil)
	if !strings.Contains(bodyString(rec), "pk-login") {
		t.Fatalf("passkeys default on: login page must offer the button")
	}

	if err := st.SetSetting(context.Background(), store.SettingPasskeys, false); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}

	rec = do(t, mux, "GET", "/login", nil, nil)
	if strings.Contains(bodyString(rec), "pk-login") {
		t.Fatalf("passkeys off: the login button must disappear")
	}
	for _, path := range []string{"/login/passkey/start", "/profile/passkeys/register/start"} {
		if rec := do(t, mux, "POST", path, nil, nil); rec.Code != http.StatusForbidden {
			t.Fatalf("%s: %d, want 403", path, rec.Code)
		}
	}

	login := do(t, mux, "POST", "/login", url.Values{"username": {"admin"}, "password": {"s3cret"}}, nil)
	var session *http.Cookie
	for _, c := range login.Result().Cookies() {
		if c.Name != browserCookieName {
			session = c
		}
	}
	sec := do(t, mux, "GET", "/profile/security", nil, session)
	if sec.Code != http.StatusOK || strings.Contains(bodyString(sec), "pk-add") {
		t.Fatalf("passkeys off: the security page must hide the section (%d)", sec.Code)
	}
}
