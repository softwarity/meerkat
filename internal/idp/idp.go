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

// New builds the driver for one stored provider, with its config ALREADY
// resolved (see store.ResolvedAuthProvider): a driver never reaches into the
// vault itself.
func New(p store.AuthProvider) (Driver, error) {
	switch p.Kind {
	case store.ProviderOIDC:
		return newOIDC(p)
	case store.ProviderLDAP:
		return newLDAP(p)
	case store.ProviderSAML:
		return nil, fmt.Errorf("idp: SAML support is not wired yet (available: %s, %s)",
			store.ProviderOIDC, store.ProviderLDAP)
	default:
		return nil, fmt.Errorf("idp: unknown provider kind %q", p.Kind)
	}
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
