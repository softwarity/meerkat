package idp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/softwarity/meerkat/internal/store"
)

// OAuth2 WITHOUT OpenID Connect: GitHub today, and the shape for the others.
//
// OAuth2 alone hands out an access token to call an API. It never says who the
// person is, and gives no way to verify such a claim: there is no signed token
// to check, so the trust rests entirely on the code exchange and on TLS to the
// vendor. That is weaker than OIDC, and it is the reason this file exists apart
// rather than as an option of the OIDC driver.
//
// Each vendor is described HERE, in code, not in a form. An admin configuring
// GitHub should type a client id and a secret, not three endpoint URLs and a
// field mapping they have no reason to know. Adding GitLab or Google later is
// one more `vendor` value, not a new screen.

// vendor is everything that differs between one OAuth2 provider and the next.
type vendor struct {
	kind     string
	authURL  string
	tokenURL string
	userURL  string
	scopes   []string
	// identity turns the vendor's own payloads into ours. It receives the
	// authenticated client so it can make the extra calls a vendor requires —
	// GitHub keeps addresses and organisations behind their own endpoints.
	identity func(ctx context.Context, c *oauth2Provider, token string, user map[string]any) (Identity, error)
}

var vendors = map[string]vendor{
	store.ProviderGitHub: {
		kind:     store.ProviderGitHub,
		authURL:  "https://github.com/login/oauth/authorize",
		tokenURL: "https://github.com/login/oauth/access_token",
		userURL:  "https://api.github.com/user",
		// The FLOOR, asked of everyone: /user answers the profile (login, id,
		// name, avatar) with no scope at all, and user:email is what it takes
		// to read the private, verified address. Nothing else is anyone's
		// business — see scopes() for the one thing that may be added.
		scopes:   []string{"user:email"},
		identity: githubIdentity,
	},
}

type oauth2Config struct {
	ClientID     string
	ClientSecret string
	// AllowedOrgs restricts the door to members of those organisations. Empty
	// lets in anyone with an account at the vendor, which on GitHub means
	// anyone at all: the field is the difference between "our team" and "the
	// internet".
	AllowedOrgs []string
}

type oauth2Provider struct {
	p      store.AuthProvider
	v      vendor
	cfg    oauth2Config
	client *http.Client
}

func newOAuth2(p store.AuthProvider) (Driver, error) {
	v, ok := vendors[p.Kind]
	if !ok {
		return nil, fmt.Errorf("idp: no OAuth2 vendor for kind %q", p.Kind)
	}
	cfg := oauth2Config{
		ClientID:     cfgString(p.Config, "clientId"),
		ClientSecret: cfgString(p.Config, "clientSecret"),
		AllowedOrgs:  cfgStrings(p.Config, "allowedOrgs"),
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, fmt.Errorf("idp: provider %q needs a clientId and a clientSecret", p.Name)
	}
	return &oauth2Provider{p: p, v: v, cfg: cfg, client: &http.Client{Timeout: 10 * time.Second}}, nil
}

// scopes is what this authority asks the PERSON to consent to, and it follows
// what the configuration actually uses. Reading someone's organisations is the
// scope that makes a consent screen list their employers, so it is asked for
// only when an organisation allow-list is set — the one setting that cannot
// work without it. Configure that list, and GitHub will ask again: the
// permission really did change.
func (o *oauth2Provider) scopes() []string {
	if len(o.cfg.AllowedOrgs) == 0 {
		return o.v.scopes
	}
	return append(append([]string{}, o.v.scopes...), "read:org")
}

// wantsGroups: the organisations and teams are collected for the same reason
// they are asked for, and never behind the person's back.
func (o *oauth2Provider) wantsGroups() bool {
	return len(o.cfg.AllowedOrgs) > 0
}

func (o *oauth2Provider) Kind() string { return o.v.kind }
func (o *oauth2Provider) Name() string { return o.p.Name }

// base lets the tests point the vendor at a local server. Empty means the real
// endpoints; nothing outside this file and its test reads it.
var oauth2BaseOverride string

func (o *oauth2Provider) endpoint(vendorURL string) string {
	if oauth2BaseOverride == "" {
		return vendorURL
	}
	u, err := url.Parse(vendorURL)
	if err != nil {
		return vendorURL
	}
	return strings.TrimRight(oauth2BaseOverride, "/") + u.Path
}

// AuthURL sends the browser to the vendor. There is no nonce and no PKCE here:
// GitHub's OAuth apps support neither, so `state` is the only guard against a
// forged callback — which is exactly why it is checked without mercy below.
func (o *oauth2Provider) AuthURL(req AuthRequest) (string, error) {
	q := url.Values{
		"client_id":     {o.cfg.ClientID},
		"redirect_uri":  {req.RedirectURI},
		"scope":         {strings.Join(o.scopes(), " ")},
		"state":         {req.State},
		"response_type": {"code"},
	}
	sep := "?"
	if strings.Contains(o.v.authURL, "?") {
		sep = "&"
	}
	return o.endpoint(o.v.authURL) + sep + q.Encode(), nil
}

func (o *oauth2Provider) Callback(ctx context.Context, r *http.Request, req AuthRequest) (Identity, error) {
	if e := r.URL.Query().Get("error"); e != "" {
		return Identity{}, fmt.Errorf("idp: %s refused the sign-in: %s %s",
			o.p.Name, e, r.URL.Query().Get("error_description"))
	}
	if got := r.URL.Query().Get("state"); got == "" || got != req.State {
		return Identity{}, fmt.Errorf("idp: state mismatch, the sign-in did not start here")
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		return Identity{}, fmt.Errorf("idp: %s returned no authorization code", o.p.Name)
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {req.RedirectURI},
		"client_id":     {o.cfg.ClientID},
		"client_secret": {o.cfg.ClientSecret},
	}
	post, err := http.NewRequestWithContext(ctx, http.MethodPost,
		o.endpoint(o.v.tokenURL), strings.NewReader(form.Encode()))
	if err != nil {
		return Identity{}, err
	}
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Without this GitHub answers form-encoded, which is the classic first-try
	// failure of every hand-rolled GitHub integration.
	post.Header.Set("Accept", "application/json")
	resp, err := o.client.Do(post)
	if err != nil {
		return Identity{}, fmt.Errorf("idp: token exchange with %s: %w", o.p.Name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return Identity{}, fmt.Errorf("idp: %s refused the code exchange (%d): %s",
			o.p.Name, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.Unmarshal(raw, &tok); err != nil {
		return Identity{}, fmt.Errorf("idp: %s returned a malformed token response: %w", o.p.Name, err)
	}
	// GitHub answers 200 with an error BODY on a bad secret: a status check
	// alone would take that for a success and fail later, obscurely.
	if tok.Error != "" {
		return Identity{}, fmt.Errorf("idp: %s refused the code exchange: %s %s",
			o.p.Name, tok.Error, tok.ErrorDesc)
	}
	if tok.AccessToken == "" {
		return Identity{}, fmt.Errorf("idp: %s returned no access token", o.p.Name)
	}

	var user map[string]any
	if err := o.get(ctx, o.v.userURL, tok.AccessToken, &user); err != nil {
		return Identity{}, err
	}
	id, err := o.v.identity(ctx, o, tok.AccessToken, user)
	if err != nil {
		return Identity{}, err
	}
	if id.Subject == "" {
		return Identity{}, fmt.Errorf("idp: %s returned no account id", o.p.Name)
	}
	if err := o.allowedOrg(id); err != nil {
		return Identity{}, err
	}
	return id, nil
}

// allowedOrg enforces the organisation allow-list. Without it, a GitHub
// provider with auto-create on would let ANY GitHub account open a pending
// account here.
func (o *oauth2Provider) allowedOrg(id Identity) error {
	if len(o.cfg.AllowedOrgs) == 0 {
		return nil
	}
	for _, want := range o.cfg.AllowedOrgs {
		for _, has := range id.Groups {
			// Groups carry "org" and "org/team": both belong to the org.
			if strings.EqualFold(has, want) || strings.HasPrefix(strings.ToLower(has), strings.ToLower(want)+"/") {
				return nil
			}
		}
	}
	return fmt.Errorf("idp: %s: this account belongs to none of the allowed organisations (%s)",
		o.p.Name, strings.Join(o.cfg.AllowedOrgs, ", "))
}

func (o *oauth2Provider) get(ctx context.Context, endpoint, token string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.endpoint(endpoint), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := o.client.Do(req)
	if err != nil {
		return fmt.Errorf("idp: %s: %w", o.p.Name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("idp: %s answered %d for %s: %s",
			o.p.Name, resp.StatusCode, endpoint, strings.TrimSpace(string(body)))
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

// ── GitHub ───────────────────────────────────────────────────────────────────

// githubIdentity assembles what GitHub scatters across three endpoints: the
// profile, the addresses, and the organisations and teams that stand in for
// groups here.
func githubIdentity(ctx context.Context, o *oauth2Provider, token string, user map[string]any) (Identity, error) {
	id := Identity{
		// The numeric id, never the login: a GitHub login can be renamed, and
		// can be taken over by someone else afterwards.
		Subject:  claimString(user, "id"),
		Username: claimString(user, "login"),
		Fullname: claimString(user, "name"),
		Email:    claimString(user, "email"),
		Raw:      user,
	}

	// /user hides a private address, and the one it does return says nothing
	// about being verified: the addresses endpoint is the only authority.
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := o.get(ctx, "https://api.github.com/user/emails", token, &emails); err == nil {
		for _, e := range emails {
			if e.Primary && e.Verified {
				id.Email, id.EmailVerified = e.Email, true
				break
			}
		}
		if !id.EmailVerified {
			for _, e := range emails {
				if e.Verified {
					id.Email, id.EmailVerified = e.Email, true
					break
				}
			}
		}
	}

	// Organisations and teams are GitHub's groups. Teams are reported as
	// "org/team", so a role mapping can key on either level. Only fetched
	// when the configuration uses them — the read:org scope is not asked for
	// otherwise, and calling these endpoints without it would fail anyway.
	if !o.wantsGroups() {
		return id, nil
	}
	var orgs []struct {
		Login string `json:"login"`
	}
	if err := o.get(ctx, "https://api.github.com/user/orgs", token, &orgs); err != nil {
		// "Could not ask" must not be reported as "belongs to nothing": the
		// allow-list below would refuse a legitimate member and blame them.
		// An organisation enforcing third-party application restrictions is
		// the usual cause, and it needs an owner's approval, not a retry.
		return id, fmt.Errorf("idp: %s: could not read this account's organisations "+
			"(an organisation restricting third-party applications must approve this OAuth app): %w",
			o.p.Name, err)
	}
	for _, org := range orgs {
		if org.Login != "" {
			id.Groups = append(id.Groups, org.Login)
		}
	}
	var teams []struct {
		Slug         string `json:"slug"`
		Organization struct {
			Login string `json:"login"`
		} `json:"organization"`
	}
	// Teams are a refinement, not a gate: the allow-list keys on the
	// organisation, which the call above already established.
	if err := o.get(ctx, "https://api.github.com/user/teams", token, &teams); err == nil {
		for _, t := range teams {
			if t.Slug != "" && t.Organization.Login != "" {
				id.Groups = append(id.Groups, t.Organization.Login+"/"+t.Slug)
			}
		}
	}
	return id, nil
}

// check confirms the credentials are usable without signing anyone in. GitHub
// has no endpoint that validates a client secret on its own, so this only
// reaches the authorization endpoint: it catches a network or proxy problem,
// not a typo in the secret, and says so rather than pretending otherwise.
func (o *oauth2Provider) check(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, o.endpoint(o.v.authURL), nil)
	if err != nil {
		return err
	}
	resp, err := o.client.Do(req)
	if err != nil {
		return fmt.Errorf("idp: %s is unreachable: %w", o.p.Name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("idp: %s answered %d", o.p.Name, resp.StatusCode)
	}
	return nil
}
