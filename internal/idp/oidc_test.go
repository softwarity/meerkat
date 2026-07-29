package idp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/softwarity/meerkat/internal/store"
)

// fakeIDP is an authority in a box: discovery, JWKS, and a token endpoint that
// signs a real ES256 ID token. It exists so the tests exercise the SIGNATURE
// path rather than a stub that always says yes.
type fakeIDP struct {
	*httptest.Server
	key    *ecdsa.PrivateKey
	claims map[string]any
	// lastForm records what the token endpoint received (PKCE assertions).
	lastForm url.Values
}

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIDP{key: key}
	mux := http.NewServeMux()
	f.Server = httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 f.URL,
			"authorization_endpoint": f.URL + "/authorize",
			"token_endpoint":         f.URL + "/token",
			"jwks_uri":               f.URL + "/keys",
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		// Go 1.26 deprecates the raw X/Y fields: read the coordinates off the
		// uncompressed point (0x04 || X || Y) instead.
		raw, err := key.PublicKey.Bytes()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "EC", "crv": "P-256", "kid": "test-key", "alg": "ES256",
			"x": base64.RawURLEncoding.EncodeToString(raw[1:33]),
			"y": base64.RawURLEncoding.EncodeToString(raw[33:65]),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.lastForm = r.PostForm
		_ = json.NewEncoder(w).Encode(map[string]string{
			"id_token": f.signIDToken(t, f.claims), "access_token": "at", "token_type": "Bearer",
		})
	})
	t.Cleanup(f.Close)
	return f
}

func (f *fakeIDP) signIDToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","kid":"test-key","typ":"JWT"}`))
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	payload := base64.RawURLEncoding.EncodeToString(body)
	sum := sha256.Sum256([]byte(header + "." + payload))
	r, s, err := ecdsa.Sign(rand.Reader, f.key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func driverFor(t *testing.T, f *fakeIDP, extra map[string]any) *oidcProvider {
	t.Helper()
	cfg := map[string]any{"issuer": f.URL, "clientId": "meerkat", "clientSecret": "s3cret"}
	for k, v := range extra {
		cfg[k] = v
	}
	d, err := New(store.AuthProvider{ID: "p1", Kind: store.ProviderOIDC, Name: "Acme SSO", Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	return d.(*oidcProvider)
}

func callbackReq(state string) *http.Request {
	return httptest.NewRequest("GET", "/login/p1/callback?code=abc&state="+url.QueryEscape(state), nil)
}

func baseClaims(f *fakeIDP, nonce string) map[string]any {
	return map[string]any{
		"iss": f.URL, "aud": "meerkat", "sub": "u-42", "nonce": nonce,
		"exp":                time.Now().Add(time.Minute).Unix(),
		"preferred_username": "jdoe", "email": "jdoe@acme.io", "email_verified": true,
		"name": "J. Doe", "groups": []any{"staff", "billing"},
	}
}

// TestOIDCSignInVerifiesTheToken walks a whole sign-in: the authorization URL
// carries PKCE, the exchange sends the verifier, and the identity only comes
// out once the ID token verifies against the published key.
func TestOIDCSignInVerifiesTheToken(t *testing.T) {
	f := newFakeIDP(t)
	o := driverFor(t, f, nil)
	req := AuthRequest{State: "st", Nonce: "no", Verifier: "verifier-123", RedirectURI: "https://gw/cb", ProviderID: "p1"}

	authURL, err := o.AuthURL(req)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	sum := sha256.Sum256([]byte(req.Verifier))
	if q.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(sum[:]) || q.Get("code_challenge_method") != "S256" {
		t.Fatalf("PKCE challenge missing or wrong: %v", q)
	}
	if q.Get("state") != "st" || q.Get("nonce") != "no" || q.Get("client_id") != "meerkat" {
		t.Fatalf("authorization request: %v", q)
	}

	f.claims = baseClaims(f, "no")
	id, err := o.Callback(context.Background(), callbackReq("st"), req)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if id.Subject != "u-42" || id.Username != "jdoe" || id.Email != "jdoe@acme.io" || !id.EmailVerified {
		t.Fatalf("identity: %+v", id)
	}
	if len(id.Groups) != 2 || id.Groups[0] != "staff" {
		t.Fatalf("groups: %+v", id.Groups)
	}
	if f.lastForm.Get("code_verifier") != "verifier-123" {
		t.Fatalf("the exchange did not send the PKCE verifier: %v", f.lastForm)
	}
}

// TestOIDCRefusesTamperedOrReplayedTokens is the point of doing the
// verification ourselves: every one of these must fail closed.
func TestOIDCRefusesTamperedOrReplayedTokens(t *testing.T) {
	f := newFakeIDP(t)
	o := driverFor(t, f, nil)
	req := AuthRequest{State: "st", Nonce: "no", Verifier: "v", RedirectURI: "https://gw/cb"}

	cases := []struct {
		name   string
		claims map[string]any
		state  string
		want   string
	}{
		{"another audience", withClaim(baseClaims(f, "no"), "aud", "someone-else"), "st", "not addressed to this client"},
		{"another issuer", withClaim(baseClaims(f, "no"), "iss", "https://evil.example"), "st", "issued by"},
		{"replayed nonce", baseClaims(f, "an-older-nonce"), "st", "nonce mismatch"},
		{"expired", withClaim(baseClaims(f, "no"), "exp", time.Now().Add(-time.Minute).Unix()), "st", "expired"},
		{"forged state", baseClaims(f, "no"), "not-our-state", "state mismatch"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f.claims = c.claims
			_, err := o.Callback(context.Background(), callbackReq(c.state), req)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error about %q", err, c.want)
			}
		})
	}

	// And a token signed by ANOTHER key, the case that matters most: the
	// claims are perfect, only the signature is not ours.
	other := newFakeIDP(t)
	other.claims = baseClaims(f, "no")
	forged := other.signIDToken(t, other.claims)
	o2 := driverFor(t, f, nil)
	f.claims = baseClaims(f, "no")
	if _, err := o2.Callback(context.Background(), callbackReq("st"), req); err != nil {
		t.Fatalf("sanity: the honest token should pass: %v", err)
	}
	keys, err := o2.jwks(context.Background(), mustMeta(t, o2))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyJWT(forged, keys); err == nil {
		t.Fatal("a token signed by another key must not verify")
	}
}

// TestOIDCDomainAllowList: a shared authority (a public issuer) must not open
// the door to every address it knows.
func TestOIDCDomainAllowList(t *testing.T) {
	f := newFakeIDP(t)
	o := driverFor(t, f, map[string]any{"allowedDomains": []any{"acme.io"}})
	req := AuthRequest{State: "st", Nonce: "no", Verifier: "v", RedirectURI: "https://gw/cb"}

	f.claims = baseClaims(f, "no")
	if _, err := o.Callback(context.Background(), callbackReq("st"), req); err != nil {
		t.Fatalf("an allowed domain must pass: %v", err)
	}
	f.claims = withClaim(baseClaims(f, "no"), "email", "someone@elsewhere.test")
	_, err := o.Callback(context.Background(), callbackReq("st"), req)
	if err == nil || !strings.Contains(err.Error(), "elsewhere.test") {
		t.Fatalf("a foreign domain must be named and refused, got %v", err)
	}
}

func withClaim(c map[string]any, k string, v any) map[string]any {
	out := map[string]any{}
	for key, val := range c {
		out[key] = val
	}
	out[k] = v
	return out
}

func mustMeta(t *testing.T, o *oidcProvider) *oidcMetadata {
	t.Helper()
	m, err := o.metadata(context.Background())
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}
	return m
}
