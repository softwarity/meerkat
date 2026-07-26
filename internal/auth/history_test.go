package auth

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const macChromeUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

// TestSignInHistoryRecordsAndBadgesBrowser: a completed password login lands
// in /profile/history with its browser label, method, IP, CDN-resolved
// country, and the "this browser" badge (via the durable MEERKAT_BROWSER
// cookie minted at login).
func TestSignInHistoryRecordsAndBadgesBrowser(t *testing.T) {
	mux, _, _ := mfaSetup(t)

	form := url.Values{"username": {"admin"}, "password": {"s3cret"}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", macChromeUA)
	req.Header.Set("CF-IPCountry", "fr") // a fronting CDN resolved the viewer
	req.RemoteAddr = "203.0.113.7:4242"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login: %d", rec.Code)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("want session + browser cookies, got %+v", cookies)
	}

	page := httptest.NewRequest("GET", "/profile/history", nil)
	for _, c := range cookies {
		page.AddCookie(c)
	}
	got := httptest.NewRecorder()
	mux.ServeHTTP(got, page)
	body, _ := io.ReadAll(got.Result().Body)
	if got.Code != http.StatusOK {
		t.Fatalf("history page: %d %s", got.Code, body)
	}
	// The fresh sign-in IS this browser: the row simplifies to "This browser"
	// + method, dropping the browser/OS/IP/country (we are on it).
	for _, want := range []string{"This browser", "password"} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("history page is missing %q:\n%s", want, body)
		}
	}
	for _, gone := range []string{"Chrome · macOS", "203.0.113.7"} {
		if strings.Contains(string(body), gone) {
			t.Fatalf("the current-browser row must not carry %q", gone)
		}
	}
}

// TestSignInHistoryOtherBrowserNotBadged: viewed WITHOUT the browser cookie
// that made the sign-in, the row shows but carries no badge.
func TestSignInHistoryOtherBrowserNotBadged(t *testing.T) {
	mux, _, _ := mfaSetup(t)
	rec := do(t, mux, "POST", "/login", url.Values{"username": {"admin"}, "password": {"s3cret"}}, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login: %d", rec.Code)
	}
	var sessionCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name != browserCookieName {
			sessionCookie = c
		}
	}
	got := do(t, mux, "GET", "/profile/history", nil, sessionCookie)
	body := bodyString(got)
	if got.Code != http.StatusOK || !strings.Contains(body, "Unknown browser") {
		t.Fatalf("history page: %d %s", got.Code, body)
	}
	if strings.Contains(body, "This browser") {
		t.Fatalf("badge must not show without the matching browser cookie:\n%s", body)
	}
}
