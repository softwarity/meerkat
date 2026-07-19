// Package features is the runtime registry of Enterprise feature flags.
//
// Community features are unconditional and never appear here. Enterprise
// features (implemented under ee/) stay dormant until enabled, normally by a
// valid license file (internal/license) at startup.
package features

import (
	"slices"
	"sync"
)

// Enterprise feature keys. Also the values used in license files.
const (
	SSOOIDC        = "sso-oidc"
	SAML           = "saml"
	LDAP           = "ldap"
	Kerberos       = "kerberos"
	Cluster        = "cluster"
	AuditExport    = "audit-export"
	BusinessAccess = "business-access"
)

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
