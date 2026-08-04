// Package idp drives the external authorities a person may sign in with
// (AUTH-19): OIDC today, LDAP and SAML behind the same contract.
//
// Two families, because the protocols really do differ:
//
//   - Redirect authorities (OIDC, SAML) send the browser away and answer on a
//     callback. Meerkat never sees the credentials.
//   - Credential authorities (LDAP) are asked directly, with the username and
//     password the person typed on our own form.
//
// Everything here is about ESTABLISHING who the person is. What happens next —
// linking to a local account, creating a pending one, granting roles — belongs
// to internal/auth, because it is the same story as self-registration.
package idp

import (
	"context"
	"fmt"
	"net/http"

	"github.com/softwarity/meerkat/internal/store"
)

// Identity is what an authority vouches for. Only Subject is guaranteed: it is
// the authority's own stable handle, and the only thing safe to key a link on.
// A username or an address can change upstream, and often does.
type Identity struct {
	// Subject is the authority's stable id for this person (OIDC "sub", an
	// LDAP entry's DN or objectGUID, a SAML NameID).
	Subject string
	// Username is the local login we would create; falls back to the address.
	Username string
	Email    string
	// EmailVerified says whether the AUTHORITY vouches for the address. When
	// it does, we do not send our own confirmation mail.
	EmailVerified bool
	Fullname      string
	// Groups are the authority's own groups or roles, kept for the mapping to
	// Meerkat roles (RBAC) — recorded now, acted on later.
	Groups []string
	// Raw keeps the claims/attributes as received, for the admin to see what
	// an authority actually sends when a mapping does not do what they expect.
	Raw map[string]any
}

// Redirect is an authority the browser is sent to (OIDC, SAML). The caller
// mints the per-attempt AuthRequest, keeps it in a signed cookie, and hands it
// back on the callback: nothing about a sign-in in flight is kept server-side.
type Redirect interface {
	AuthURL(req AuthRequest) (string, error)
	// Callback validates the authority's answer and returns the identity. It
	// must verify everything: signature, audience, issuer, nonce, expiry.
	Callback(ctx context.Context, r *http.Request, req AuthRequest) (Identity, error)
}

// Credential is an authority we ask ourselves, with what the person typed
// (LDAP). The password never leaves this call.
type Credential interface {
	Authenticate(ctx context.Context, username, password string) (Identity, error)
}

// Driver is the common surface: a configured authority, whatever its family.
type Driver interface {
	Kind() string
	// Name is what the login page shows.
	Name() string
}

// Revalidator is an authority that can be asked, with no credentials in hand,
// whether it still recognises someone.
//
// This is what turns a passkey into a SHORTCUT rather than a second front door.
// A passkey proves possession of a key tied to a LOCAL account; it says nothing
// about the directory that owns the person. Without this call, disabling
// someone in the annuaire would not stop them signing in here — they would keep
// a way in that the directory believes it has closed.
//
// Only a directory can answer. A redirect authority has no equivalent that
// works without sending the browser away (OIDC has prompt=none, which is a
// redirect and belongs elsewhere), so it simply does not implement this.
type Revalidator interface {
	// Recognises reports whether subject is still an active account. The
	// subject is what the identity was linked under — for LDAP, the entry's DN.
	//
	// An error means "could not ask", which is NOT the same as "no": a
	// directory that is down must not sign everybody out.
	Recognises(ctx context.Context, subject string) (bool, error)
}

// New builds the driver for one stored provider, with its config ALREADY
// resolved (see store.ResolvedAuthProvider): a driver never reaches into the
// vault itself.
func New(p store.AuthProvider) (Driver, error) {
	switch p.Kind {
	case store.ProviderOIDC:
		return newOIDC(p)
	case store.ProviderLDAP:
		return newLDAP(p)
	case store.ProviderGitHub:
		return newOAuth2(p)
	case store.ProviderSAML:
		return nil, fmt.Errorf("idp: SAML support is not wired yet (available: %s, %s, %s)",
			store.ProviderOIDC, store.ProviderLDAP, store.ProviderGitHub)
	default:
		return nil, fmt.Errorf("idp: unknown provider kind %q", p.Kind)
	}
}

// SecretFields names the config keys of one kind that hold a SECRET, and it is
// the only place that knowledge lives. Four behaviours read it: the admin API
// never returns such a field in clear, a save carries the stored value forward
// rather than blanking it, the audit trail redacts it, and the console offers
// to move it into the vault.
//
// Declared rather than guessed: the audit's isSensitiveKey heuristic matches
// "password" and "secret" but would miss an "apiKey" or a "privateKey", and a
// heuristic that misses once leaks once.
func SecretFields(kind string) []string {
	switch kind {
	case store.ProviderOIDC, store.ProviderGitHub:
		return []string{"clientSecret"}
	case store.ProviderLDAP:
		return []string{"bindPassword"}
	}
	return nil
}

// cfgString reads a string out of a provider's config.
func cfgString(cfg map[string]any, key string) string {
	s, _ := cfg[key].(string)
	return s
}

// cfgStrings reads a list of strings, tolerating a single string.
func cfgStrings(cfg map[string]any, key string) []string {
	switch v := cfg[key].(type) {
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return v
	}
	return nil
}

// cfgBool reads a boolean, defaulting to def when absent.
func cfgBool(cfg map[string]any, key string, def bool) bool {
	if b, ok := cfg[key].(bool); ok {
		return b
	}
	return def
}

// Check tries a configuration without signing anyone in: it is what the
// console's "test" button calls, and what turns "sign-in does not work" into
// "the issuer does not resolve" or "the service account cannot bind".
func Check(ctx context.Context, d Driver) error {
	type checker interface {
		check(ctx context.Context) error
	}
	c, ok := d.(checker)
	if !ok {
		return fmt.Errorf("idp: %s cannot be checked without a sign-in", d.Kind())
	}
	return c.check(ctx)
}
