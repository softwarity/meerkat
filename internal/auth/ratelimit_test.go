package auth

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/softwarity/meerkat/internal/mfa"
	"github.com/softwarity/meerkat/internal/store"
)

// TestLoginRateLimit: after N failed attempts for the same IP+account the
// endpoint answers 429 WITHOUT verifying - even the right password waits for
// the window; a success within the budget clears the counter.
func TestLoginRateLimit(t *testing.T) {
	mux, _, st := mfaSetup(t)
	ctx := context.Background()
	if err := st.SetSetting(ctx, store.SettingRateLimit,
		store.RateLimitPolicy{LoginAttempts: 3, LoginWindow: "PT15M", TotpAttempts: 5}); err != nil {
		t.Fatal(err)
	}

	bad := url.Values{"username": {"admin"}, "password": {"wrong"}}
	good := url.Values{"username": {"admin"}, "password": {"s3cret"}}
	for i := 0; i < 3; i++ {
		if rec := do(t, mux, "POST", "/login", bad, nil); rec.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d: %d, want 401", i+1, rec.Code)
		}
	}
	// Budget burned: even the RIGHT password answers 429 now.
	if rec := do(t, mux, "POST", "/login", good, nil); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over budget: %d, want 429", rec.Code)
	}
	// Another account from the same IP is NOT blocked (key = IP+username).
	if rec := do(t, mux, "POST", "/login", url.Values{"username": {"other"}, "password": {"x"}}, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("other account: %d, want 401", rec.Code)
	}
}

// TestLoginRateLimitForgivesOnSuccess: a success within the budget resets it.
func TestLoginRateLimitForgivesOnSuccess(t *testing.T) {
	mux, _, st := mfaSetup(t)
	ctx := context.Background()
	if err := st.SetSetting(ctx, store.SettingRateLimit,
		store.RateLimitPolicy{LoginAttempts: 3, LoginWindow: "PT15M", TotpAttempts: 5}); err != nil {
		t.Fatal(err)
	}
	bad := url.Values{"username": {"admin"}, "password": {"wrong"}}
	good := url.Values{"username": {"admin"}, "password": {"s3cret"}}
	for i := 0; i < 2; i++ {
		do(t, mux, "POST", "/login", bad, nil)
	}
	if rec := do(t, mux, "POST", "/login", good, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("success within budget: %d, want 303", rec.Code)
	}
	// Counter cleared: two fresh failures still answer 401, not 429.
	for i := 0; i < 2; i++ {
		if rec := do(t, mux, "POST", "/login", bad, nil); rec.Code != http.StatusUnauthorized {
			t.Fatalf("post-success failure %d: %d, want 401", i+1, rec.Code)
		}
	}
}

// TestTotpRateLimit: wrong codes burn the per-account budget, then 429.
func TestTotpRateLimit(t *testing.T) {
	mux, _, st := mfaSetup(t)
	ctx := context.Background()
	if err := st.SetSetting(ctx, store.SettingRateLimit,
		store.RateLimitPolicy{LoginAttempts: 10, LoginWindow: "PT15M", TotpAttempts: 2}); err != nil {
		t.Fatal(err)
	}
	secret, _ := enrol(t, st)

	login := do(t, mux, "POST", "/login", url.Values{"username": {"admin"}, "password": {"s3cret"}}, nil)
	cookie := sessionCookieOf(login)
	if login.Header().Get("Location") != "/totp" {
		t.Fatalf("login: %q", login.Header().Get("Location"))
	}
	for i := 0; i < 2; i++ {
		if rec := do(t, mux, "POST", "/totp", url.Values{"code": {"000000"}}, cookie); rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("wrong code %d: %d, want 422", i+1, rec.Code)
		}
	}
	// Budget burned: even the RIGHT code is refused until the window slides.
	code, err := mfa.Code(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if rec := do(t, mux, "POST", "/totp", url.Values{"code": {code}}, cookie); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over budget: %d, want 429", rec.Code)
	}
}
