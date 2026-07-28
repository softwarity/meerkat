// Package vault is Meerkat's value store (VAULT-01): named entries the rest of
// the configuration references by $name instead of carrying the value inline.
//
// Two kinds of entry share one namespace:
//
//   - secret: encrypted at rest (AES-256-GCM), never returned in plain by the
//     admin API, substituted only when the gateway loads the configuration;
//   - value: plain text, readable — a hostname, a header name, an account.
//
// Holding both in one place is the point: an admin has a single screen for
// everything the configuration refers to, and can see what is actually used.
// Only the encryption differs; the reference syntax is the same, so promoting a
// value to a secret never touches the objects that reference it.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// The entry kinds.
const (
	KindSecret = "secret"
	KindValue  = "value"
)

// ValidKind reports whether k is a known entry kind.
func ValidKind(k string) bool { return k == KindSecret || k == KindValue }

// The scopes an entry belongs to (RBAC-05), on the model of an organisation's
// variables and a repository's: several planes coexist, each administered by
// its own people, and a NAME IS UNIQUE PER SCOPE — so the same "db-password"
// can mean a different thing for two tenants.
//
// Resolution honours the same split, which is what stops an administrator of
// one plane from quietly changing what another plane resolves: a route only
// ever expands against gateway entries, the application settings against app
// ones. A TENANT resolves its own entries first and falls back to the
// application ones, so a tenant may USE a global value without being able to
// edit it, and may shadow it by declaring its own under the same name.
const (
	// ScopeInfra is the infrastructure plane: upstreams, filter arguments,
	// backend credentials. Administered by the infra-admin capability.
	ScopeInfra = "infra"
	// ScopeApp is the application plane: SMTP, identity providers… — app-admin.
	ScopeApp = "app"
	// ScopeTenantPrefix + <tenant id> is one organisation's own scope.
	ScopeTenantPrefix = "tenant:"
)

// TenantScope is the scope string of one organisation.
func TenantScope(tenantID string) string { return ScopeTenantPrefix + tenantID }

// TenantOf returns the organisation a scope belongs to, "" when it is global.
func TenantOf(scope string) string {
	if !IsTenantScope(scope) {
		return ""
	}
	return strings.TrimPrefix(scope, ScopeTenantPrefix)
}

// IsTenantScope reports whether the scope belongs to an organisation.
func IsTenantScope(s string) bool {
	return strings.HasPrefix(s, ScopeTenantPrefix) && len(s) > len(ScopeTenantPrefix)
}

// ValidScope reports whether s is a known scope.
func ValidScope(s string) bool {
	return s == ScopeInfra || s == ScopeApp || IsTenantScope(s)
}

// ResolutionOrder is the scopes a consumer of `scope` reads, most specific
// first. A tenant sees its own entries then the application ones (shadowing);
// the global planes resolve only themselves.
func ResolutionOrder(scope string) []string {
	if IsTenantScope(scope) {
		return []string{scope, ScopeApp}
	}
	return []string{scope}
}

// NameOK bounds an entry name: it must survive being written as $name inside a
// configuration, so no spaces and no punctuation that could end the reference.
var NameOK = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]*$`)

// Entry is one named value. Value is the CLEAR text; the store encrypts it on
// the way in for secrets, and the admin API blanks it on the way out.
type Entry struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	// Scope is the plane the entry serves (gateway|app): who may see and edit
	// it, and which configuration may resolve it.
	Scope       string   `json:"scope"`
	Value       string   `json:"value,omitempty"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	CreatedAt   int64    `json:"createdAt"`
	UpdatedAt   int64    `json:"updatedAt"`
}

// ── references ───────────────────────────────────────────────────────────────

// refRe matches $name and ${name} — the second form lets a reference sit flush
// against following text ("${host}:8080"). A doubled $$ escapes a literal $.
var refRe = regexp.MustCompile(`\$\$|\$\{([A-Za-z][A-Za-z0-9_.-]*)\}|\$([A-Za-z][A-Za-z0-9_.-]*)`)

// Refs returns the entry names s references, in order, without duplicates.
func Refs(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range refRe.FindAllStringSubmatch(s, -1) {
		name := m[1]
		if name == "" {
			name = m[2]
		}
		if name == "" || seen[name] { // $$ escape, or already collected
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

// Expand substitutes every $name / ${name} in s with what lookup returns. A
// name lookup cannot resolve is left VERBATIM and reported in missing, so a
// typo shows up as itself rather than silently becoming an empty string (an
// empty upstream or an empty secret fails in far more confusing ways).
func Expand(s string, lookup func(string) (string, bool)) (out string, missing []string) {
	out = refRe.ReplaceAllStringFunc(s, func(match string) string {
		if match == "$$" {
			return "$"
		}
		name := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(match, "$"), "{"), "}")
		if v, ok := lookup(name); ok {
			return v
		}
		missing = append(missing, name)
		return match
	})
	return out, missing
}

// ExpandAny walks a DECODED json structure (maps, slices, scalars) and expands
// every string leaf. Walking the decoded form rather than the raw json text is
// what keeps a value containing a quote or a backslash from breaking the
// document it lands in.
func ExpandAny(v any, lookup func(string) (string, bool)) (any, []string) {
	var missing []string
	var walk func(any) any
	walk = func(node any) any {
		switch n := node.(type) {
		case string:
			out, miss := Expand(n, lookup)
			missing = append(missing, miss...)
			return out
		case []any:
			for i, item := range n {
				n[i] = walk(item)
			}
			return n
		case map[string]any:
			for k, item := range n {
				n[k] = walk(item)
			}
			return n
		}
		return node
	}
	return walk(v), missing
}

// ── encryption at rest ───────────────────────────────────────────────────────

// Cipher seals secret values with AES-256-GCM. The nonce is random per seal and
// stored with the ciphertext, so re-sealing the same value never yields the
// same blob.
type Cipher struct{ aead cipher.AEAD }

// NewCipher builds a Cipher from a 32-byte key.
func NewCipher(key []byte) (*Cipher, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("vault: master key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("vault: cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("vault: gcm: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

// Seal encrypts a plain value into base64(nonce||ciphertext).
func (c *Cipher) Seal(plain string) (string, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("vault: nonce: %w", err)
	}
	sealed := c.aead.Seal(nonce, nonce, []byte(plain), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Open decrypts what Seal produced. It fails on a wrong key or tampered blob
// (GCM authenticates), which is exactly what we want a rotation mistake to do.
func (c *Cipher) Open(blob string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return "", fmt.Errorf("vault: bad ciphertext encoding: %w", err)
	}
	n := c.aead.NonceSize()
	if len(raw) < n {
		return "", errors.New("vault: ciphertext too short")
	}
	plain, err := c.aead.Open(nil, raw[:n], raw[n:], nil)
	if err != nil {
		return "", fmt.Errorf("vault: cannot decrypt (wrong master key?): %w", err)
	}
	return string(plain), nil
}

// KeyFileName is where the master key lands when none is supplied.
const KeyFileName = "vault.key"

// LoadOrCreateKey resolves the master key: the MEERKAT_VAULT_KEY environment
// value when set (64 hex chars or base64 of 32 bytes), otherwise a key file in
// the data directory, generated on first start with 0600 permissions.
//
// The generated file sits next to the database, so it protects a stolen or
// copied DATABASE (a backup, an export), not a stolen data directory. Supply
// the key by environment to keep it off the disk entirely.
func LoadOrCreateKey(dataDir, envValue string) ([]byte, error) {
	if envValue = strings.TrimSpace(envValue); envValue != "" {
		key, err := decodeKey(envValue)
		if err != nil {
			return nil, fmt.Errorf("vault: MEERKAT_VAULT_KEY: %w", err)
		}
		return key, nil
	}
	path := filepath.Join(dataDir, KeyFileName)
	switch raw, err := os.ReadFile(path); {
	case err == nil:
		key, derr := decodeKey(strings.TrimSpace(string(raw)))
		if derr != nil {
			return nil, fmt.Errorf("vault: %s: %w", path, derr)
		}
		return key, nil
	case !errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("vault: read master key: %w", err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("vault: generate master key: %w", err)
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)), 0o600); err != nil {
		return nil, fmt.Errorf("vault: write master key: %w", err)
	}
	return key, nil
}

func decodeKey(s string) ([]byte, error) {
	if key, err := hex.DecodeString(s); err == nil && len(key) == 32 {
		return key, nil
	}
	key, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(key) != 32 {
		return nil, errors.New("expected 32 bytes as 64 hex chars or base64")
	}
	return key, nil
}
