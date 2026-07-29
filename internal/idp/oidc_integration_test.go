package idp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/softwarity/meerkat/internal/store"
)

// A whole sign-in against a REAL provider (Dex, in test/ldap/docker-compose.yml):
//
//	make ldap-up && go test ./internal/idp/ -run OIDCAgainstDex -count=1
//
// The unit tests sign their own tokens, which proves the verification logic;
// this proves INTEROPERABILITY, and it exercises RS256 where they exercise
// ES256. It skips when Dex is down, so make test never needs Docker.

const dexDefault = "http://localhost:5556/dex"

func TestOIDCAgainstDex(t *testing.T) {
	issuer := serverOrSkipHTTP(t, "MEERKAT_TEST_OIDC_ISSUER", dexDefault)

	d, err := New(store.AuthProvider{
		ID: "dex", Kind: store.ProviderOIDC, Name: "Dex",
		Config: map[string]any{
			"issuer": issuer, "clientId": "meerkat", "clientSecret": "meerkat-secret",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	o := d.(*oidcProvider)

	req := AuthRequest{
		State: "state-1", Nonce: "nonce-1", Verifier: "a-verifier-long-enough-for-pkce",
		RedirectURI: "http://localhost:9099/login/dex/callback", ProviderID: "dex",
	}
	authURL, err := o.AuthURL(req)
	if err != nil {
		t.Fatalf("authorization URL: %v", err)
	}

	// Walk the browser's part of the flow with an HTTP client: follow the
	// redirects until the provider hands the code back to our callback.
	var code string
	client := &http.Client{
		CheckRedirect: func(r *http.Request, _ []*http.Request) error {
			if strings.HasPrefix(r.URL.String(), req.RedirectURI) {
				code = r.URL.Query().Get("code")
				if got := r.URL.Query().Get("state"); got != req.State {
					t.Errorf("the provider echoed state %q, we sent %q", got, req.State)
				}
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("authorization request: %v", err)
	}
	_ = resp.Body.Close()
	if code == "" {
		t.Fatalf("no authorization code came back (last status %d)", resp.StatusCode)
	}

	// From here on it is our driver's job: exchange the code, fetch the keys,
	// verify the RS256 signature, the issuer, the audience and the nonce.
	cb := httptest.NewRequest("GET", "/login/dex/callback?code="+url.QueryEscape(code)+
		"&state="+url.QueryEscape(req.State), nil)
	id, err := o.Callback(context.Background(), cb, req)
	if err != nil {
		t.Fatalf("callback against a real provider: %v", err)
	}
	if id.Subject == "" {
		t.Fatal("a verified identity must carry the provider's subject")
	}
	if id.Email == "" {
		t.Fatalf("Dex vouches for an address, got %+v", id)
	}

	// And the same code must not work twice: an authorization code is single
	// use, and the provider is the one enforcing it.
	if _, err := o.Callback(context.Background(), cb, req); err == nil {
		t.Fatal("replaying an authorization code must fail")
	}
}

// serverOrSkipHTTP skips unless the HTTP endpoint answers.
func serverOrSkipHTTP(t *testing.T, env, def string) string {
	t.Helper()
	issuer := def
	if v := os.Getenv(env); v != "" {
		issuer = v
	}
	resp, err := http.Get(issuer + "/.well-known/openid-configuration")
	if err != nil {
		t.Skipf("no OIDC provider at %s (run `make ldap-up`): %v", issuer, err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Skipf("the provider at %s answered %d", issuer, resp.StatusCode)
	}
	return issuer
}
