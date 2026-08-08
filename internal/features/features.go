// Package features is the runtime registry of Enterprise feature flags.
//
// Community features are unconditional and never appear here. Enterprise
// features stay dormant until enabled, normally by a valid license file
// (internal/license) at startup.
package features

import (
	"fmt"
	"slices"
	"sync"
)

// Enterprise feature keys. Also the values used in license files.
//
// The line they draw: what costs an organisation as it grows is paid for,
// what protects the user is not. So passkeys, TOTP, RBAC, the vault, the
// audit trail, per-endpoint security and OIDC/GitHub sign-in are community
// and always will be - making people pay for those pushes them to deploy
// less safely, and a gateway with no SSO is not adopted in the first place.
// What is sold is integration with an existing IT estate, scale, and the
// obligations that come with an audit.
//
// OIDC keeps a free path to every modern identity provider (Entra ID, Okta,
// Google Workspace, Keycloak), which is what makes Directories sellable
// without being a toll: what is bought there is plugging a directory in
// DIRECTLY rather than through a provider.
const (
	// MultiTenant unlocks more than one organisation. Every instance starts
	// single-tenant, where the notion never appears in the console at all.
	MultiTenant = "multi-tenant"
	// Directories covers LDAP, Active Directory and Kerberos - and with them
	// the group rules, which exist only to project what a directory declares.
	Directories = "directories"
	SAML        = "saml"
	// SCIM provisions accounts and, above all, DEPROVISIONS them: an audit
	// requirement, not a convenience.
	SCIM = "scim"
	// BusinessHours is internal control rather than security - no attacker is
	// stopped by opening hours - which is why it is sold while MFA is not.
	BusinessHours = "business-hours"
	Cluster       = "cluster"
	// AuditExport is the chain of custody: continuous export to a SIEM and
	// long retention. READING the trail stays community.
	AuditExport = "audit-export"
	// WhiteLabel removes the Meerkat mark from the sign-in pages.
	WhiteLabel = "white-label"
)

// All is every key, for the license payload and the console's roster.
var All = []string{
	MultiTenant, Directories, SAML, SCIM, BusinessHours, Cluster, AuditExport, WhiteLabel,
}

var (
	mu      sync.RWMutex
	enabled = map[string]bool{}
)

// Enable turns the given features on. Called once at startup after license
// validation.
func Enable(names ...string) {
	mu.Lock()
	defer mu.Unlock()
	for _, name := range names {
		enabled[name] = true
	}
}

// Has reports whether a feature is enabled.
func Has(name string) bool {
	mu.RLock()
	defer mu.RUnlock()
	return enabled[name]
}

// Require answers with an error naming what is missing, so a handler refuses
// with something the caller can act on rather than a bare 403.
func Require(name string) error {
	if Has(name) {
		return nil
	}
	return fmt.Errorf("%q is an Enterprise feature and this instance has no license covering it", name)
}

// Enabled returns a sorted snapshot of the enabled features.
func Enabled() []string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(enabled))
	for name := range enabled {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// Reset disables everything. Test helper.
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	enabled = map[string]bool{}
}
