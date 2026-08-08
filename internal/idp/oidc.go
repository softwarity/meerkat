package idp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/softwarity/meerkat/internal/store"
)

// OIDC: the authorization code flow with PKCE, on net/http alone.
//
// Why OIDC and not "OAuth2": OAuth2 alone says how to get a token, not who the
// person is - every vendor then invents its own userinfo shape. OIDC adds the
// discovery document, the ID token and the JWKS, which is exactly what makes
// an identity verifiable without trusting the network.

// AuthRequest is the per-attempt state the caller mints and hands back on the
// callback. It lives in a signed cookie, never on the server: a sign-in must
// survive a restart, and a gateway has no business keeping session scraps.
type AuthRequest struct {
	State string `json:"state"`
	Nonce string `json:"nonce"`
	// Verifier is the PKCE code_verifier (RFC 7636). Mandatory here: a public
	// redirect is worth protecting even when a client secret is configured.
	Verifier    string `json:"verifier"`
	RedirectURI string `json:"redirectUri"`
	ProviderID  string `json:"providerId"`
}

// oidcConfig is what an admin fills in. Every field may hold a $name vault
// reference; the store resolves them before the driver is built.
type oidcConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	Scopes       []string
	// UsernameClaim picks the local login ("preferred_username" by default,
	// falling back to the address when absent).
	UsernameClaim string
	GroupsClaim   string
	// AllowedDomains restricts which e-mail domains this authority may bring
	// in, for the tenant that runs a shared authority.
	AllowedDomains []string
	// UseUserinfo asks the userinfo endpoint when the ID token is thin, which
	// several authorities are about groups.
	UseUserinfo bool
}

type oidcProvider struct {
	p   store.AuthProvider
	cfg oidcConfig

	mu        sync.Mutex
	meta      *oidcMetadata
	metaAt    time.Time
	keys      []jwk
	keysAt    time.Time
	client    *http.Client
	nowFn     func() time.Time
	discovery string // overridden in tests
}

// oidcMetadata is the slice of the discovery document we act on.
type oidcMetadata struct {
	Issuer        string `json:"issuer"`
	AuthURL       string `json:"authorization_endpoint"`
	TokenURL      string `json:"token_endpoint"`
	JWKSURL       string `json:"jwks_uri"`
	UserinfoURL   string `json:"userinfo_endpoint"`
	EndSessionURL string `json:"end_session_endpoint"`
}

func newOIDC(p store.AuthProvider) (Driver, error) {
	cfg := oidcConfig{
		Issuer:         strings.TrimRight(cfgString(p.Config, "issuer"), "/"),
		ClientID:       cfgString(p.Config, "clientId"),
		ClientSecret:   cfgString(p.Config, "clientSecret"),
		Scopes:         cfgStrings(p.Config, "scopes"),
		UsernameClaim:  cfgString(p.Config, "usernameClaim"),
		GroupsClaim:    cfgString(p.Config, "groupsClaim"),
		AllowedDomains: cfgStrings(p.Config, "allowedDomains"),
		UseUserinfo:    cfgBool(p.Config, "useUserinfo", false),
	}
	if cfg.Issuer == "" || cfg.ClientID == "" {
		return nil, fmt.Errorf("idp: provider %q needs an issuer and a clientId", p.Name)
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile", "email"}
	}
	if cfg.UsernameClaim == "" {
		cfg.UsernameClaim = "preferred_username"
	}
	return &oidcProvider{
		p: p, cfg: cfg,
		client: &http.Client{Timeout: 10 * time.Second},
		nowFn:  time.Now,
	}, nil
}

func (o *oidcProvider) Kind() string { return store.ProviderOIDC }
func (o *oidcProvider) Name() string { return o.p.Name }

// AuthURL builds the authorization request. PKCE is always on.
func (o *oidcProvider) AuthURL(req AuthRequest) (string, error) {
	meta, err := o.metadata(context.Background())
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(req.Verifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {o.cfg.ClientID},
		"redirect_uri":          {req.RedirectURI},
		"scope":                 {strings.Join(o.cfg.Scopes, " ")},
		"state":                 {req.State},
		"nonce":                 {req.Nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	sep := "?"
	if strings.Contains(meta.AuthURL, "?") {
		sep = "&"
	}
	return meta.AuthURL + sep + q.Encode(), nil
}

// Callback validates the authority's answer: the state must be the one we
// minted, the code must exchange, and the ID token must verify against the
// published keys AND name us as its audience for the nonce we sent.
func (o *oidcProvider) Callback(ctx context.Context, r *http.Request, req AuthRequest) (Identity, error) {
	if e := r.URL.Query().Get("error"); e != "" {
		desc := r.URL.Query().Get("error_description")
		return Identity{}, fmt.Errorf("idp: %s refused the sign-in: %s %s", o.p.Name, e, desc)
	}
	if got := r.URL.Query().Get("state"); got == "" || got != req.State {
		return Identity{}, fmt.Errorf("idp: state mismatch, the sign-in did not start here")
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		return Identity{}, fmt.Errorf("idp: %s returned no authorization code", o.p.Name)
	}
	meta, err := o.metadata(ctx)
	if err != nil {
		return Identity{}, err
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {req.RedirectURI},
		"client_id":     {o.cfg.ClientID},
		"code_verifier": {req.Verifier},
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, meta.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return Identity{}, err
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Accept", "application/json")
	if o.cfg.ClientSecret != "" {
		// client_secret_basic is what most authorities expect first.
		httpReq.SetBasicAuth(url.QueryEscape(o.cfg.ClientID), url.QueryEscape(o.cfg.ClientSecret))
	}
	resp, err := o.client.Do(httpReq)
	if err != nil {
		return Identity{}, fmt.Errorf("idp: token exchange with %s: %w", o.p.Name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return Identity{}, fmt.Errorf("idp: %s refused the code exchange (%d): %s",
			o.p.Name, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var tok struct {
		IDToken     string `json:"id_token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return Identity{}, fmt.Errorf("idp: %s returned a malformed token response: %w", o.p.Name, err)
	}
	if tok.IDToken == "" {
		return Identity{}, fmt.Errorf("idp: %s returned no id_token (is the openid scope granted?)", o.p.Name)
	}

	keys, err := o.jwks(ctx, meta)
	if err != nil {
		return Identity{}, err
	}
	claims, err := verifyJWT(tok.IDToken, keys)
	if err != nil {
		return Identity{}, fmt.Errorf("idp: %s: %w", o.p.Name, err)
	}
	if iss := claimString(claims, "iss"); strings.TrimRight(iss, "/") != o.cfg.Issuer {
		return Identity{}, fmt.Errorf("idp: id token issued by %q, expected %q", iss, o.cfg.Issuer)
	}
	if !audienceHas(claims, o.cfg.ClientID) {
		return Identity{}, fmt.Errorf("idp: id token is not addressed to this client")
	}
	if exp, ok := claimTime(claims, "exp"); !ok || o.nowFn().Unix() >= exp {
		return Identity{}, fmt.Errorf("idp: id token has expired")
	}
	if n := claimString(claims, "nonce"); n != req.Nonce {
		return Identity{}, fmt.Errorf("idp: id token nonce mismatch (replay?)")
	}

	if o.cfg.UseUserinfo && meta.UserinfoURL != "" && tok.AccessToken != "" {
		if extra, err := o.userinfo(ctx, meta.UserinfoURL, tok.AccessToken); err == nil {
			for k, v := range extra {
				if _, exists := claims[k]; !exists {
					claims[k] = v
				}
			}
		}
	}

	id := o.identityFrom(claims)
	if err := o.allowed(id); err != nil {
		return Identity{}, err
	}
	return id, nil
}

func (o *oidcProvider) identityFrom(claims map[string]any) Identity {
	email := claimString(claims, "email")
	username := claimString(claims, o.cfg.UsernameClaim)
	if username == "" {
		username = email
	}
	groupsClaim := o.cfg.GroupsClaim
	if groupsClaim == "" {
		groupsClaim = "groups"
	}
	return Identity{
		Subject:       claimString(claims, "sub"),
		Username:      username,
		Email:         email,
		EmailVerified: claimBool(claims, "email_verified"),
		Fullname:      claimString(claims, "name"),
		Groups:        claimStrings(claims, groupsClaim),
		Raw:           claims,
	}
}

// allowed enforces the e-mail domain allow-list, when there is one.
func (o *oidcProvider) allowed(id Identity) error {
	if len(o.cfg.AllowedDomains) == 0 {
		return nil
	}
	at := strings.LastIndexByte(id.Email, '@')
	if at < 0 {
		return fmt.Errorf("idp: %s returned no e-mail address, so the domain allow-list cannot be applied", o.p.Name)
	}
	domain := strings.ToLower(id.Email[at+1:])
	for _, d := range o.cfg.AllowedDomains {
		if strings.EqualFold(strings.TrimPrefix(d, "@"), domain) {
			return nil
		}
	}
	return fmt.Errorf("idp: %s is not open to the domain %q (allowed: %s)",
		o.p.Name, domain, strings.Join(o.cfg.AllowedDomains, ", "))
}

func (o *oidcProvider) userinfo(ctx context.Context, endpoint, accessToken string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := o.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo answered %d", resp.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// metadata fetches (and caches) the discovery document.
func (o *oidcProvider) metadata(ctx context.Context) (*oidcMetadata, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.meta != nil && o.nowFn().Sub(o.metaAt) < time.Hour {
		return o.meta, nil
	}
	endpoint := o.discovery
	if endpoint == "" {
		endpoint = o.cfg.Issuer + "/.well-known/openid-configuration"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := o.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("idp: cannot reach %s discovery at %s: %w", o.p.Name, endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("idp: %s discovery answered %d", o.p.Name, resp.StatusCode)
	}
	var meta oidcMetadata
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&meta); err != nil {
		return nil, fmt.Errorf("idp: %s discovery is malformed: %w", o.p.Name, err)
	}
	if meta.AuthURL == "" || meta.TokenURL == "" || meta.JWKSURL == "" {
		return nil, fmt.Errorf("idp: %s discovery lacks an authorization, token or jwks endpoint", o.p.Name)
	}
	o.meta, o.metaAt = &meta, o.nowFn()
	return o.meta, nil
}

// jwks fetches (and caches) the signing keys. A key rotation upstream is
// picked up within the cache window; an unknown kid forces a refetch.
func (o *oidcProvider) jwks(ctx context.Context, meta *oidcMetadata) ([]jwk, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.keys) > 0 && o.nowFn().Sub(o.keysAt) < 15*time.Minute {
		return o.keys, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, meta.JWKSURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := o.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("idp: cannot reach %s keys: %w", o.p.Name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("idp: %s keys answered %d", o.p.Name, resp.StatusCode)
	}
	var set jwks
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set); err != nil {
		return nil, fmt.Errorf("idp: %s keys are malformed: %w", o.p.Name, err)
	}
	if len(set.Keys) == 0 {
		return nil, fmt.Errorf("idp: %s publishes no signing key", o.p.Name)
	}
	o.keys, o.keysAt = set.Keys, o.nowFn()
	return o.keys, nil
}

// check fetches the discovery document and the keys: everything a sign-in
// needs before a person is even involved.
func (o *oidcProvider) check(ctx context.Context) error {
	meta, err := o.metadata(ctx)
	if err != nil {
		return err
	}
	if _, err := o.jwks(ctx, meta); err != nil {
		return err
	}
	return nil
}
