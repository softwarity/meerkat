package idp

import (
	"context"
	"net"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/softwarity/meerkat/internal/store"
)

// These run against the two servers of test/ldap/docker-compose.yml:
//
//	make ldap-up && go test ./internal/idp/ -run LDAP
//
// Without them the tests SKIP, so `make test` stays green on a machine with no
// Docker. They are worth the setup: a directory client is exactly the kind of
// code that passes every unit test and then meets a real directory.

const (
	openLDAPDefault = "ldap://localhost:3389"
	// LDAPS, because a domain controller refuses a simple bind in the clear
	// (ldap server require strong auth). That is the right default on its
	// side, so the test binds the way production does.
	adDefault  = "ldaps://localhost:3636"
	adPassword = "Passw0rd!2026"
)

func serverOrSkip(t *testing.T, env, def string) string {
	t.Helper()
	url := os.Getenv(env)
	if url == "" {
		url = def
	}
	host := strings.TrimPrefix(strings.TrimPrefix(url, "ldap://"), "ldaps://")
	conn, err := net.DialTimeout("tcp", host, 800*time.Millisecond)
	if err != nil {
		t.Skipf("no directory at %s (run `make ldap-up`): %v", url, err)
	}
	_ = conn.Close()
	return url
}

func ldapDriver(t *testing.T, cfg map[string]any) Credential {
	t.Helper()
	d, err := New(store.AuthProvider{ID: "l1", Kind: store.ProviderLDAP, Name: "Directory", Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	c, ok := d.(Credential)
	if !ok {
		t.Fatal("an LDAP driver must answer credentials")
	}
	return c
}

// TestLDAPDirectorySignIn: the OpenLDAP dialect, where membership lives on the
// GROUP and nesting has to be walked. developer holds frontend/backend/devops,
// so John must come out a developer without ever being listed as one.
func TestLDAPDirectorySignIn(t *testing.T) {
	url := serverOrSkip(t, "MEERKAT_TEST_LDAP_URL", openLDAPDefault)
	c := ldapDriver(t, map[string]any{
		"url":          url,
		"baseDn":       "dc=example,dc=com",
		"bindDn":       "cn=admin,dc=example,dc=com",
		"bindPassword": "adminpassword",
	})

	id, err := c.Authenticate(context.Background(), "johndoe", "password")
	if err != nil {
		t.Fatalf("sign-in: %v", err)
	}
	if id.Subject != "uid=johndoe,ou=users,dc=example,dc=com" {
		t.Fatalf("subject must be the DN, got %q", id.Subject)
	}
	if id.Username != "johndoe" || id.Email != "johndoe@example.com" || id.Fullname != "John Doe" {
		t.Fatalf("identity: %+v", id)
	}
	if !id.EmailVerified {
		t.Fatal("a directory is authoritative about its own people")
	}
	for _, want := range []string{"frontend", "backend", "operator", "developer"} {
		if !slices.Contains(id.Groups, want) {
			t.Fatalf("group %q missing from %v (nested membership not walked?)", want, id.Groups)
		}
	}
	if slices.Contains(id.Groups, "devops") {
		t.Fatalf("John is not in devops: %v", id.Groups)
	}
}

// TestLDAPRefusesBadCredentials: the empty password is the one that matters.
// An empty simple bind is ANONYMOUS in LDAP and succeeds, which would read as
// "the password is right".
func TestLDAPRefusesBadCredentials(t *testing.T) {
	url := serverOrSkip(t, "MEERKAT_TEST_LDAP_URL", openLDAPDefault)
	c := ldapDriver(t, map[string]any{
		"url":          url,
		"baseDn":       "dc=example,dc=com",
		"bindDn":       "cn=admin,dc=example,dc=com",
		"bindPassword": "adminpassword",
	})
	ctx := context.Background()

	if _, err := c.Authenticate(ctx, "johndoe", "not-the-password"); err == nil {
		t.Fatal("a wrong password must not sign in")
	}
	if _, err := c.Authenticate(ctx, "johndoe", ""); err == nil {
		t.Fatal("an empty password is an anonymous bind, it must be refused")
	}
	if _, err := c.Authenticate(ctx, "nobody", "password"); err == nil {
		t.Fatal("an unknown user must not sign in")
	}
	// And the refusal says the same thing either way: a directory must not
	// tell an attacker which usernames exist.
	_, e1 := c.Authenticate(ctx, "johndoe", "wrong")
	_, e2 := c.Authenticate(ctx, "nobody", "wrong")
	if e1.Error() != e2.Error() {
		t.Fatalf("user enumeration: %q vs %q", e1, e2)
	}
}

// TestLDAPActiveDirectorySignIn: the AD dialect. Different attribute names,
// membership exposed on the PERSON, and nesting resolved by the server through
// LDAP_MATCHING_RULE_IN_CHAIN. Same assertions as the directory above, which
// is the point: one contract, two very different servers.
func TestLDAPActiveDirectorySignIn(t *testing.T) {
	url := serverOrSkip(t, "MEERKAT_TEST_AD_URL", adDefault)
	c := ldapDriver(t, map[string]any{
		"url":     url,
		"dialect": "ad",
		"baseDn":  "DC=ad,DC=example,DC=com",
		"bindDn":  "Administrator@ad.example.com",
		// The controller signs its own certificate for dc1.ad.example.com and
		// the test reaches it as localhost: skipping verification is the
		// point of the flag, and it stays a deliberate, visible setting.
		"insecureSkipVerify": true,
		"bindPassword":       adPassword,
	})

	id, err := c.Authenticate(context.Background(), "johndoe", adPassword)
	if err != nil {
		t.Fatalf("sign-in: %v", err)
	}
	if !strings.HasPrefix(id.Subject, "CN=johndoe,") {
		t.Fatalf("subject must be the DN, got %q", id.Subject)
	}
	if id.Username != "johndoe" || id.Email != "johndoe@ad.example.com" {
		t.Fatalf("identity: %+v", id)
	}
	for _, want := range []string{"frontend", "backend", "operator", "developer"} {
		if !slices.Contains(id.Groups, want) {
			t.Fatalf("group %q missing from %v (matching rule in chain not used?)", want, id.Groups)
		}
	}
	if slices.Contains(id.Groups, "devops") {
		t.Fatalf("John is not in devops: %v", id.Groups)
	}

	if _, err := c.Authenticate(context.Background(), "johndoe", "wrong"); err == nil {
		t.Fatal("a wrong password must not sign in against AD either")
	}
}

// TestLDAPNestedGroupsCanBeTurnedOff: an installation that only grants on
// direct membership must be able to say so, on both dialects.
func TestLDAPNestedGroupsCanBeTurnedOff(t *testing.T) {
	url := serverOrSkip(t, "MEERKAT_TEST_LDAP_URL", openLDAPDefault)
	c := ldapDriver(t, map[string]any{
		"url":          url,
		"baseDn":       "dc=example,dc=com",
		"bindDn":       "cn=admin,dc=example,dc=com",
		"bindPassword": "adminpassword",
		"nestedGroups": false,
	})
	id, err := c.Authenticate(context.Background(), "johndoe", "password")
	if err != nil {
		t.Fatalf("sign-in: %v", err)
	}
	if slices.Contains(id.Groups, "developer") {
		t.Fatalf("nesting is off, developer should not appear: %v", id.Groups)
	}
	if !slices.Contains(id.Groups, "frontend") {
		t.Fatalf("direct membership must still be there: %v", id.Groups)
	}
}
