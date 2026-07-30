package admin

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/softwarity/meerkat/internal/vault"
)

// The literal every test below hunts for in a response body. It has to be
// recognisable and appear nowhere else.
const literalSecret = "s3cr3t-literal-never-returned"

func oidcBody(secret string) string {
	return `{"kind":"oidc","name":"Acme SSO","enabled":true,"config":{` +
		`"issuer":"https://sso.acme.io","clientId":"meerkat","clientSecret":"` + secret + `"}}`
}

// TestLiteralSecretNeverComesBack is the rule itself: a stored literal must not
// travel, on the save that set it or on any later read. What comes back is the
// fact that one is set, so the console can say "configured" instead of showing
// an empty field that invites a reset.
func TestLiteralSecretNeverComesBack(t *testing.T) {
	f := setup(t)
	code, body := f.call(t, "PUT", "/api/auth-providers/acme", oidcBody(literalSecret), f.rootC)
	if code != http.StatusOK {
		t.Fatalf("save: %d %s", code, body)
	}
	for _, res := range []string{body, get(t, f, "/api/auth-providers")} {
		if strings.Contains(res, literalSecret) {
			t.Fatalf("the literal secret came back: %s", res)
		}
		if !strings.Contains(res, `"secretsSet":["clientSecret"]`) {
			t.Fatalf("nothing says a secret is stored: %s", res)
		}
	}
	// It IS stored, though: withholding it must not mean dropping it.
	p, err := f.api.st.GetAuthProvider(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	if p.Config["clientSecret"] != literalSecret {
		t.Fatalf("the secret was not stored: %v", p.Config["clientSecret"])
	}
}

// TestReferenceComesBackVerbatim: the other half of the rule. A ${name} names
// an entry, not a value, and the screen cannot show WHICH entry without it.
func TestReferenceComesBackVerbatim(t *testing.T) {
	f := setup(t)
	code, body := f.call(t, "PUT", "/api/auth-providers/acme", oidcBody("${acme-client-secret}"), f.rootC)
	if code != http.StatusOK {
		t.Fatalf("save: %d %s", code, body)
	}
	if !strings.Contains(body, `"clientSecret":"${acme-client-secret}"`) {
		t.Fatalf("the reference did not come back: %s", body)
	}
	if strings.Contains(body, "secretsSet") {
		t.Fatalf("a reference is not a withheld literal: %s", body)
	}
}

// TestSavingWithoutTheSecretKeepsIt is the trap this whole shape creates: the
// console cannot resend what it never received, so an ordinary edit — renaming
// the authority — would erase the client secret if a blank meant "erase".
func TestSavingWithoutTheSecretKeepsIt(t *testing.T) {
	f := setup(t)
	if code, body := f.call(t, "PUT", "/api/auth-providers/acme", oidcBody(literalSecret), f.rootC); code != http.StatusOK {
		t.Fatalf("save: %d %s", code, body)
	}
	// Exactly what the console holds after a GET: no clientSecret at all.
	renamed := `{"kind":"oidc","name":"Acme SSO (renamed)","enabled":true,"config":{` +
		`"issuer":"https://sso.acme.io","clientId":"meerkat"}}`
	code, body := f.call(t, "PUT", "/api/auth-providers/acme", renamed, f.rootC)
	if code != http.StatusOK {
		t.Fatalf("rename: %d %s", code, body)
	}
	p, err := f.api.st.GetAuthProvider(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	if p.Config["clientSecret"] != literalSecret {
		t.Fatalf("renaming the authority lost its secret: %v", p.Config)
	}
	if p.Name != "Acme SSO (renamed)" {
		t.Fatalf("the rename itself did not take: %q", p.Name)
	}
}

// TestRelayIsServedUnresolved: the screen must see what is STORED. Serving the
// resolved value would make the next save write the secret back as a literal,
// so the form would silently eat the reference it was meant to show.
func TestRelayIsServedUnresolved(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if err := f.api.st.SaveVaultEntry(ctx, vaultSecret("smtp-password", "hunter2")); err != nil {
		t.Fatal(err)
	}
	relay := `{"host":"smtp.acme.io","port":587,"security":"starttls",` +
		`"username":"bot@acme.io","password":"${smtp-password}","from":"bot@acme.io"}`
	if code, body := f.call(t, "PUT", "/api/settings/mail-relay", relay, f.rootC); code != http.StatusOK {
		t.Fatalf("save relay: %d %s", code, body)
	}
	body := get(t, f, "/api/settings/mail-relay")
	if strings.Contains(body, "hunter2") {
		t.Fatalf("the resolved secret was served: %s", body)
	}
	if !strings.Contains(body, `"password":"${smtp-password}"`) {
		t.Fatalf("the reference did not come back: %s", body)
	}
	// And saving that payload again keeps the reference rather than freezing
	// the value it resolves to.
	if code, out := f.call(t, "PUT", "/api/settings/mail-relay", body, f.rootC); code != http.StatusOK {
		t.Fatalf("re-save: %d %s", code, out)
	}
	if got := f.api.st.RawSMTP(ctx).Password; got != "${smtp-password}" {
		t.Fatalf("re-saving the form replaced the reference with %q", got)
	}
}

// TestRelayLiteralPasswordNeverComesBack mirrors the authority case.
func TestRelayLiteralPasswordNeverComesBack(t *testing.T) {
	f := setup(t)
	relay := `{"host":"smtp.acme.io","port":587,"security":"starttls",` +
		`"username":"bot@acme.io","password":"` + literalSecret + `","from":"bot@acme.io"}`
	if code, body := f.call(t, "PUT", "/api/settings/mail-relay", relay, f.rootC); code != http.StatusOK {
		t.Fatalf("save relay: %d %s", code, body)
	}
	body := get(t, f, "/api/settings/mail-relay")
	if strings.Contains(body, literalSecret) {
		t.Fatalf("the literal password came back: %s", body)
	}
	if !strings.Contains(body, `"passwordSet":true`) {
		t.Fatalf("nothing says a password is stored: %s", body)
	}
	if got := f.api.st.RawSMTP(context.Background()).Password; got != literalSecret {
		t.Fatalf("the password was not stored: %q", got)
	}
}

// TestVaultUsageCoversEveryHolder: refusing to delete a live entry only works
// if every holder is scanned. An authority's secret deleted from under it fails
// at the next sign-in, far from the screen that caused it.
func TestVaultUsageCoversEveryHolder(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	for _, name := range []string{"acme-secret", "smtp-password"} {
		if err := f.api.st.SaveVaultEntry(ctx, vaultSecret(name, "x")); err != nil {
			t.Fatal(err)
		}
	}
	if code, body := f.call(t, "PUT", "/api/auth-providers/acme", oidcBody("${acme-secret}"), f.rootC); code != http.StatusOK {
		t.Fatalf("save authority: %d %s", code, body)
	}
	relay := `{"host":"smtp.acme.io","port":587,"username":"bot","password":"${smtp-password}"}`
	if code, body := f.call(t, "PUT", "/api/settings/mail-relay", relay, f.rootC); code != http.StatusOK {
		t.Fatalf("save relay: %d %s", code, body)
	}
	for name, want := range map[string]string{
		"acme-secret":   "authority: Acme SSO",
		"smtp-password": "mail relay",
	} {
		code, body := f.call(t, "DELETE", "/api/vault/infra/"+name, "", f.rootC)
		if code != http.StatusConflict {
			t.Fatalf("deleting %s: %d %s, want 409", name, code, body)
		}
		if !strings.Contains(body, want) {
			t.Fatalf("deleting %s should name %q, got %s", name, want, body)
		}
	}
}

// TestStashMovesTheSecretServerSide is the case the whole design turns on: a
// literal that arrived through the bootstrap file. The console never received
// it, so the only way to protect it is to have the server move it — the
// request below carries a NAME, never a value.
func TestStashMovesTheSecretServerSide(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if code, body := f.call(t, "PUT", "/api/auth-providers/acme", oidcBody(literalSecret), f.rootC); code != http.StatusOK {
		t.Fatalf("save: %d %s", code, body)
	}
	code, body := f.call(t, "POST", "/api/vault/stash",
		`{"holder":"authprovider","id":"acme","field":"clientSecret","name":"acme-client-secret"}`, f.rootC)
	if code != http.StatusOK {
		t.Fatalf("stash: %d %s", code, body)
	}
	if strings.Contains(body, literalSecret) {
		t.Fatalf("the answer carried the secret: %s", body)
	}
	if !strings.Contains(body, `"ref":"${acme-client-secret}"`) {
		t.Fatalf("the answer should hand back the reference: %s", body)
	}
	// The authority now points at the entry...
	p, err := f.api.st.GetAuthProvider(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if p.Config["clientSecret"] != "${acme-client-secret}" {
		t.Fatalf("the field was not rewritten: %v", p.Config["clientSecret"])
	}
	// ...and the entry holds what the field used to.
	e, err := f.api.st.GetVaultEntry(ctx, vault.ScopeInfra, "acme-client-secret")
	if err != nil {
		t.Fatal(err)
	}
	if e.Value != literalSecret {
		t.Fatalf("the entry does not hold the secret: %q", e.Value)
	}
	if e.Kind != vault.KindSecret {
		t.Fatalf("a moved secret must land as a secret, got %q", e.Kind)
	}
	// And the authority still signs in: what changed is where the secret
	// lives, not what it resolves to.
	resolved, missing, err := f.api.st.ResolvedAuthProvider(ctx, "acme")
	if err != nil || len(missing) > 0 {
		t.Fatalf("resolve: %v missing=%v", err, missing)
	}
	if resolved.Config["clientSecret"] != literalSecret {
		t.Fatalf("the moved secret no longer resolves: %v", resolved.Config["clientSecret"])
	}
}

// TestStashDerivesAName: with no name given, the entry lands under a
// deterministic one, so replaying a bootstrap cannot scatter near-duplicates.
func TestStashDerivesAName(t *testing.T) {
	f := setup(t)
	if code, body := f.call(t, "PUT", "/api/auth-providers/acme", oidcBody(literalSecret), f.rootC); code != http.StatusOK {
		t.Fatalf("save: %d %s", code, body)
	}
	code, body := f.call(t, "POST", "/api/vault/stash",
		`{"holder":"authprovider","id":"acme","field":"clientSecret"}`, f.rootC)
	if code != http.StatusOK || !strings.Contains(body, `"name":"acme-client-secret"`) {
		t.Fatalf("derived name: %d %s", code, body)
	}
}

// TestStashRefusals: every refusal names what is wrong, because these all
// arrive on a screen where the admin cannot see the value to reason about it.
func TestStashRefusals(t *testing.T) {
	f := setup(t)
	if code, body := f.call(t, "PUT", "/api/auth-providers/acme", oidcBody(literalSecret), f.rootC); code != http.StatusOK {
		t.Fatalf("save: %d %s", code, body)
	}
	for _, tc := range []struct {
		what, body string
		want       int
		says       string
	}{
		{"unknown holder", `{"holder":"nope","id":"acme","field":"clientSecret"}`,
			http.StatusUnprocessableEntity, "authprovider, mailrelay"},
		{"unknown object", `{"holder":"authprovider","id":"ghost","field":"clientSecret"}`,
			http.StatusNotFound, "ghost"},
		{"field that holds no secret", `{"holder":"authprovider","id":"acme","field":"clientId"}`,
			http.StatusUnprocessableEntity, "clientSecret"},
		{"bad name", `{"holder":"authprovider","id":"acme","field":"clientSecret","name":"1 bad name"}`,
			http.StatusUnprocessableEntity, "starts with a letter"},
	} {
		code, body := f.call(t, "POST", "/api/vault/stash", tc.body, f.rootC)
		if code != tc.want || !strings.Contains(body, tc.says) {
			t.Errorf("%s: %d %s, want %d mentioning %q", tc.what, code, body, tc.want, tc.says)
		}
	}
	// A name already taken is refused rather than overwritten: the entry there
	// may be what something else resolves.
	if err := f.api.st.SaveVaultEntry(context.Background(), vaultSecret("taken", "someone else's")); err != nil {
		t.Fatal(err)
	}
	code, body := f.call(t, "POST", "/api/vault/stash",
		`{"holder":"authprovider","id":"acme","field":"clientSecret","name":"taken"}`, f.rootC)
	if code != http.StatusConflict {
		t.Fatalf("taken name: %d %s, want 409", code, body)
	}
	if e, _ := f.api.st.GetVaultEntry(context.Background(), vault.ScopeInfra, "taken"); e.Value != "someone else's" {
		t.Fatalf("the existing entry was overwritten: %q", e.Value)
	}
	// Moving twice is refused, and says where it already is.
	if code, body := f.call(t, "POST", "/api/vault/stash",
		`{"holder":"authprovider","id":"acme","field":"clientSecret","name":"acme-secret"}`, f.rootC); code != http.StatusOK {
		t.Fatalf("first move: %d %s", code, body)
	}
	code, body = f.call(t, "POST", "/api/vault/stash",
		`{"holder":"authprovider","id":"acme","field":"clientSecret","name":"again"}`, f.rootC)
	if code != http.StatusUnprocessableEntity || !strings.Contains(body, "acme-secret") {
		t.Fatalf("second move: %d %s, want 422 naming the entry it is already in", code, body)
	}
}

// TestStashTheRelayPassword covers the other holder, and with it the registry:
// a screen gets this behaviour by being listed, not by wiring its own call.
func TestStashTheRelayPassword(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	relay := `{"host":"smtp.acme.io","port":587,"username":"bot","password":"` + literalSecret + `"}`
	if code, body := f.call(t, "PUT", "/api/settings/mail-relay", relay, f.rootC); code != http.StatusOK {
		t.Fatalf("save relay: %d %s", code, body)
	}
	code, body := f.call(t, "POST", "/api/vault/stash",
		`{"holder":"mailrelay","id":"","field":"password","name":"smtp-password"}`, f.rootC)
	if code != http.StatusOK {
		t.Fatalf("stash: %d %s", code, body)
	}
	if got := f.api.st.RawSMTP(ctx).Password; got != "${smtp-password}" {
		t.Fatalf("the relay was not rewritten: %q", got)
	}
	if got := f.api.st.GetSMTP(ctx).Password; got != literalSecret {
		t.Fatalf("the relay no longer resolves to its password: %q", got)
	}
}

func get(t *testing.T, f fixture, path string) string {
	t.Helper()
	code, body := f.call(t, "GET", path, "", f.rootC)
	if code != http.StatusOK {
		t.Fatalf("GET %s: %d %s", path, code, body)
	}
	return body
}

func vaultSecret(name, value string) vault.Entry {
	return vault.Entry{Name: name, Kind: vault.KindSecret, Scope: vault.ScopeInfra, Value: value}
}
