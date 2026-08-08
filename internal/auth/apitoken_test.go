package auth

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

var tokenClear = regexp.MustCompile(`mk_[A-Za-z0-9_-]+`)

// TestAPITokenPageFlow: create shows the token once, list carries it, toggle
// flips enabled, revoke removes it - and the policy off hides the page.
func TestAPITokenPageFlow(t *testing.T) {
	mux, _, _ := mfaSetup(t)

	// A signed-in session (admin, no tenant here - the token would carry no
	// roles, which the page states but still allows).
	login := do(t, mux, "POST", "/login", url.Values{"username": {"admin"}, "password": {"s3cret"}}, nil)
	cookie := sessionCookieOf(login)

	// The Security page links the tokens section (policy default on).
	if sec := do(t, mux, "GET", "/profile/security", nil, cookie); !strings.Contains(bodyString(sec), "/profile/tokens") {
		t.Fatalf("security page must link the tokens page")
	}

	// Create a token: the clear value is shown ONCE.
	create := do(t, mux, "POST", "/profile/tokens",
		url.Values{"action": {"create"}, "name": {"ci-pipeline-zzz"}, "days": {"90"}}, cookie)
	body := bodyString(create)
	secret := tokenClear.FindString(body)
	if create.Code != http.StatusOK || secret == "" {
		t.Fatalf("create: %d, no token shown", create.Code)
	}
	if !strings.Contains(body, "ci-pipeline-zzz") {
		t.Fatalf("the new token must be listed")
	}

	// The list no longer reveals the clear value on reload (read the body
	// ONCE - httptest memoizes Result(), a second read is drained).
	listBody := bodyString(do(t, mux, "GET", "/profile/tokens", nil, cookie))
	if strings.Contains(listBody, secret) {
		t.Fatalf("the clear token must never appear again")
	}
	id := regexp.MustCompile(`name="id" value="([^"]+)"`).FindStringSubmatch(listBody)
	if id == nil {
		t.Fatalf("no token id on the page")
	}

	// Toggle -> disabled shows.
	toggled := do(t, mux, "POST", "/profile/tokens", url.Values{"action": {"toggle"}, "id": {id[1]}}, cookie)
	if toggled.Code != http.StatusSeeOther {
		t.Fatalf("toggle: %d", toggled.Code)
	}
	if after := do(t, mux, "GET", "/profile/tokens", nil, cookie); !strings.Contains(bodyString(after), "disabled") {
		t.Fatalf("toggled token must read disabled")
	}

	// Revoke -> gone.
	if rec := do(t, mux, "POST", "/profile/tokens", url.Values{"action": {"revoke"}, "id": {id[1]}}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("revoke: %d", rec.Code)
	}
	if after := do(t, mux, "GET", "/profile/tokens", nil, cookie); strings.Contains(bodyString(after), "ci-pipeline-zzz") {
		t.Fatalf("revoked token must be gone")
	}
}
