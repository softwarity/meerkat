package idp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/softwarity/meerkat/internal/store"
)

// A GitHub in a box. It answers the four endpoints a sign-in actually touches,
// each with GitHub's own quirks: a token error inside a 200, an address hidden
// from /user, and organisations and teams behind their own calls.
type fakeGitHub struct {
	*httptest.Server
	tokenBody string // overridden to rehearse a refusal
	emails    string
	orgs      string
	// orgsStatus rehearses the organisation that restricts third-party apps:
	// GitHub answers 403 until an owner approves this one.
	orgsStatus int
	teams      string
	lastForm   url.Values
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	t.Helper()
	g := &fakeGitHub{
		tokenBody: `{"access_token":"gho_test","token_type":"bearer"}`,
		emails:    `[{"email":"private@acme.io","primary":true,"verified":true}]`,
		orgs:      `[{"login":"softwarity"}]`,
		teams:     `[{"slug":"gateway","organization":{"login":"softwarity"}}]`,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		g.lastForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(g.tokenBody))
	})
	// /user reports NO address: GitHub hides a private one, which is the case
	// that breaks naive integrations.
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gho_test" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": 4242, "login": "jdoe", "name": "J. Doe", "email": nil,
		})
	})
	mux.HandleFunc("/user/emails", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(g.emails))
	})
	mux.HandleFunc("/user/orgs", func(w http.ResponseWriter, _ *http.Request) {
		if g.orgsStatus != 0 {
			w.WriteHeader(g.orgsStatus)
			return
		}
		_, _ = w.Write([]byte(g.orgs))
	})
	mux.HandleFunc("/user/teams", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(g.teams))
	})
	mux.HandleFunc("/login/oauth/authorize", func(http.ResponseWriter, *http.Request) {})
	g.Server = httptest.NewServer(mux)
	oauth2BaseOverride = g.URL
	t.Cleanup(func() { oauth2BaseOverride = ""; g.Close() })
	return g
}

func githubDriver(t *testing.T, cfg map[string]any) *oauth2Provider {
	t.Helper()
	base := map[string]any{"clientId": "cid", "clientSecret": "csecret"}
	for k, v := range cfg {
		base[k] = v
	}
	d, err := New(store.AuthProvider{ID: "gh", Kind: store.ProviderGitHub, Name: "GitHub", Config: base})
	if err != nil {
		t.Fatal(err)
	}
	return d.(*oauth2Provider)
}

func ghCallback(state string) *http.Request {
	return httptest.NewRequest("GET", "/login/gh/callback?code=abc&state="+url.QueryEscape(state), nil)
}

// TestGitHubSignIn: the whole exchange, and the three GitHub specifics that a
// generic OAuth2 form could never express - the address behind its own
// endpoint, the numeric id as the subject, and organisations as groups.
//
// With an allow-list configured, since that is what makes the organisations
// worth asking for at all (see TestGitHubAsksOnlyForWhatItUses).
func TestGitHubSignIn(t *testing.T) {
	g := newFakeGitHub(t)
	o := githubDriver(t, map[string]any{"allowedOrgs": []string{"softwarity"}})
	req := AuthRequest{State: "st", RedirectURI: "https://gw/login/gh/callback", ProviderID: "gh"}

	authURL, err := o.AuthURL(req)
	if err != nil {
		t.Fatal(err)
	}
	q, _ := url.Parse(authURL)
	if q.Query().Get("client_id") != "cid" || q.Query().Get("state") != "st" {
		t.Fatalf("authorization request: %s", authURL)
	}
	if !strings.Contains(q.Query().Get("scope"), "user:email") {
		t.Fatalf("the address scope must be asked for, got %q", q.Query().Get("scope"))
	}

	id, err := o.Callback(context.Background(), ghCallback("st"), req)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	// The NUMERIC id, never the login: a login can be renamed, and someone else
	// can then take it.
	if id.Subject != "4242" {
		t.Fatalf("subject must be the numeric id, got %q", id.Subject)
	}
	if id.Username != "jdoe" || id.Fullname != "J. Doe" {
		t.Fatalf("identity: %+v", id)
	}
	// /user returned no address; the addresses endpoint is what supplies it,
	// and it is the only one that says whether it is verified.
	if id.Email != "private@acme.io" || !id.EmailVerified {
		t.Fatalf("the private verified address was not picked up: %+v", id)
	}
	if len(id.Groups) != 2 || id.Groups[0] != "softwarity" || id.Groups[1] != "softwarity/gateway" {
		t.Fatalf("organisations and teams should both be groups, got %v", id.Groups)
	}
	if g.lastForm.Get("client_secret") != "csecret" {
		t.Fatalf("the exchange did not send the secret: %v", g.lastForm)
	}
}

// TestGitHubRefusals: GitHub answers 200 with an error BODY on a bad secret,
// and a forged callback carries the wrong state. Both must fail closed.
func TestGitHubRefusals(t *testing.T) {
	g := newFakeGitHub(t)
	o := githubDriver(t, nil)
	req := AuthRequest{State: "st", RedirectURI: "https://gw/cb"}

	if _, err := o.Callback(context.Background(), ghCallback("forged"), req); err == nil ||
		!strings.Contains(err.Error(), "state mismatch") {
		t.Fatalf("a forged state must be refused, got %v", err)
	}

	g.tokenBody = `{"error":"bad_verification_code","error_description":"The code passed is incorrect or expired."}`
	_, err := o.Callback(context.Background(), ghCallback("st"), req)
	if err == nil || !strings.Contains(err.Error(), "bad_verification_code") {
		t.Fatalf("an error inside a 200 must be caught, got %v", err)
	}
}

// TestGitHubOrganisationAllowList: without it, a GitHub provider with
// auto-create on lets ANY GitHub account open a pending account here. That is
// the whole internet.
func TestGitHubOrganisationAllowList(t *testing.T) {
	g := newFakeGitHub(t)
	req := AuthRequest{State: "st", RedirectURI: "https://gw/cb"}

	o := githubDriver(t, map[string]any{"allowedOrgs": []any{"softwarity"}})
	if _, err := o.Callback(context.Background(), ghCallback("st"), req); err != nil {
		t.Fatalf("a member of the allowed organisation must pass: %v", err)
	}

	// A team of that organisation counts as belonging to it.
	g.orgs = `[]`
	if _, err := o.Callback(context.Background(), ghCallback("st"), req); err != nil {
		t.Fatalf("a team membership must count as the organisation: %v", err)
	}

	// Someone else entirely: refused, and the message names what is expected.
	g.teams = `[]`
	_, err := o.Callback(context.Background(), ghCallback("st"), req)
	if err == nil || !strings.Contains(err.Error(), "softwarity") {
		t.Fatalf("an outsider must be refused with the expected orgs named, got %v", err)
	}
}

// TestGitHubNeedsCredentials: a half-filled provider is refused at save time,
// not discovered by the first person who clicks the button.
func TestGitHubNeedsCredentials(t *testing.T) {
	_, err := New(store.AuthProvider{
		ID: "gh", Kind: store.ProviderGitHub, Name: "GitHub",
		Config: map[string]any{"clientId": "cid"},
	})
	if err == nil || !strings.Contains(err.Error(), "clientSecret") {
		t.Fatalf("a missing secret must be named, got %v", err)
	}
}

// TestGitHubAsksOnlyForWhatItUses: reading someone's organisations is what
// makes GitHub's consent screen list their employers, so it is asked for only
// when the configuration cannot work without it - an organisation allow-list.
// Identity alone costs the address scope and nothing more.
func TestGitHubAsksOnlyForWhatItUses(t *testing.T) {
	g := newFakeGitHub(t)
	req := AuthRequest{State: "st", RedirectURI: "https://gw/login/gh/callback", ProviderID: "gh"}

	// No allow-list: the profile and the address, full stop.
	plain := githubDriver(t, nil)
	authURL, err := plain.AuthURL(req)
	if err != nil {
		t.Fatal(err)
	}
	scope := mustQuery(t, authURL).Get("scope")
	if !strings.Contains(scope, "user:email") {
		t.Fatalf("the address is always needed, got %q", scope)
	}
	if strings.Contains(scope, "read:org") {
		t.Fatalf("nothing uses the organisations here, they must not be asked for: %q", scope)
	}
	// And nothing is collected behind the person's back either.
	id, err := plain.Callback(context.Background(), ghCallback("st"), req)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if len(id.Groups) != 0 {
		t.Fatalf("groups gathered without the scope that pays for them: %v", id.Groups)
	}

	// An allow-list cannot be enforced without them: now it is asked.
	gated := githubDriver(t, map[string]any{"allowedOrgs": []string{"softwarity"}})
	authURL, err = gated.AuthURL(req)
	if err != nil {
		t.Fatal(err)
	}
	if scope := mustQuery(t, authURL).Get("scope"); !strings.Contains(scope, "read:org") {
		t.Fatalf("an allow-list needs the organisations, got %q", scope)
	}
	_ = g
}

// TestGitHubCannotReadTheOrganisations: "could not ask" is not "belongs to
// nothing". An organisation restricting third-party applications answers 403
// until an owner approves the app, and refusing its members with "you belong
// to none of the allowed organisations" sends them hunting for the wrong bug.
func TestGitHubCannotReadTheOrganisations(t *testing.T) {
	g := newFakeGitHub(t)
	g.orgsStatus = http.StatusForbidden
	o := githubDriver(t, map[string]any{"allowedOrgs": []string{"softwarity"}})
	req := AuthRequest{State: "st", RedirectURI: "https://gw/login/gh/callback", ProviderID: "gh"}

	_, err := o.Callback(context.Background(), ghCallback("st"), req)
	if err == nil {
		t.Fatal("an allow-list that cannot be evaluated must fail closed")
	}
	if !strings.Contains(err.Error(), "could not read") {
		t.Fatalf("the refusal must say what actually happened, got %v", err)
	}
}

func mustQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query()
}
