package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/softwarity/meerkat/internal/vault"
)

// External authentication (AUTH-19): the authorities a person may sign in
// with, besides the local password. One row per authority, one row per link
// between a local account and what that authority calls the person.

// Provider kinds. OIDC covers every OAuth2 authority worth the name (the
// discovery document and the ID token are what make the identity verifiable);
// plain OAuth2 without OIDC is a per-vendor affair and is not a kind of its own.
const (
	// ProviderLocal is the accounts held HERE, answering the sign-in form with
	// the password Meerkat itself stores (AUTH-24). It is an authority like the
	// others so that one list answers "by which door does one come in", and
	// closing that door is the same gesture as closing any other. It has no
	// configuration: there is no third party to reach.
	//
	// It never applies to the ADMIN plane. The console is what one repairs a
	// broken authority with, so it always keeps its password sign-in.
	ProviderLocal = "local"
	ProviderOIDC  = "oidc"
	ProviderLDAP  = "ldap"
	ProviderSAML  = "saml"
	// GitHub is its OWN kind, not a generic "oauth2" one. OAuth2 alone says how
	// to get a token, never who the person is, so every vendor invents its own
	// identity endpoint and its own field names. A generic form would ask an
	// admin to fill in three URLs and a field mapping they should never have to
	// know: the vendor is the setting, and the rest is ours to hold.
	ProviderGitHub = "github"
)

// Tri-state policies: "" inherits the application setting.
const (
	PolicyInherit = ""
	PolicyYes     = "yes"
	PolicyNo      = "no"
)

// AuthProvider is one configured authority.
type AuthProvider struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Order   int    `json:"order"`
	// Config is kind-specific (see internal/idp). It may hold $name vault
	// references: they are resolved when the provider is USED, never stored
	// expanded.
	Config map[string]any `json:"config"`
	// MFARequired / Passkeys override the application policy for people
	// arriving through this authority ("" inherits).
	MFARequired string `json:"mfaRequired"`
	Passkeys    string `json:"passkeys"`
	// AutoCreate lets a first sign-in create a PENDING local account, the way
	// self-registration does. Off means only linked accounts may come in.
	AutoCreate bool  `json:"autoCreate"`
	CreatedAt  int64 `json:"createdAt"`
	UpdatedAt  int64 `json:"updatedAt"`
}

// LocalProviderID is the fixed id of the local-accounts authority: exactly one
// exists, it is seeded at startup and it is never deleted - only turned off.
const LocalProviderID = "local"

// ValidProviderKind reports whether kind is one we know how to drive.
func ValidProviderKind(kind string) bool {
	switch kind {
	case ProviderLocal, ProviderOIDC, ProviderLDAP, ProviderSAML, ProviderGitHub:
		return true
	}
	return false
}

// LocalSignInEnabled reports whether the accounts held here may still answer
// the sign-in form on the DATA plane. A missing row (a database that predates
// the seed) reads as enabled: an installation that never touched the setting
// signs in exactly as before.
func (s *Store) LocalSignInEnabled(ctx context.Context) bool {
	p, err := s.GetAuthProvider(ctx, LocalProviderID)
	if err != nil {
		return true
	}
	return p.Enabled
}

// seedLocalProvider puts the local-accounts authority in the list, once. Only
// the ROW is seeded: an existing one keeps whatever state an admin gave it,
// including disabled.
func (s *Store) seedLocalProvider() error {
	ctx := context.Background()
	if _, err := s.GetAuthProvider(ctx, LocalProviderID); err == nil {
		return nil
	}
	return s.SaveAuthProvider(ctx, AuthProvider{
		ID:      LocalProviderID,
		Kind:    ProviderLocal,
		Name:    "Local accounts",
		Enabled: true,
		// First in the list: it is the door every installation starts with.
		Order: -1,
	})
}

// ValidPolicy reports whether p is one of the tri-state values.
func ValidPolicy(p string) bool {
	return p == PolicyInherit || p == PolicyYes || p == PolicyNo
}

// SaveAuthProvider inserts or updates one authority.
func (s *Store) SaveAuthProvider(ctx context.Context, p AuthProvider) error {
	p.Name = strings.TrimSpace(p.Name)
	if p.ID == "" || p.Name == "" {
		return fmt.Errorf("store: an auth provider needs an id and a name")
	}
	if !ValidProviderKind(p.Kind) {
		return fmt.Errorf("store: auth provider %q: unknown kind %q (allowed: %s, %s, %s)",
			p.Name, p.Kind, ProviderOIDC, ProviderLDAP, ProviderSAML)
	}
	if !ValidPolicy(p.MFARequired) || !ValidPolicy(p.Passkeys) {
		return fmt.Errorf("store: auth provider %q: a policy must be empty (inherit), %q or %q",
			p.Name, PolicyYes, PolicyNo)
	}
	cfg, err := json.Marshal(p.Config)
	if err != nil {
		return fmt.Errorf("store: auth provider %q config: %w", p.Name, err)
	}
	now := time.Now().Unix()
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO auth_providers (id, kind, name, enabled, ord, config, mfa_required, passkeys, auto_create, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		   kind = excluded.kind, name = excluded.name, enabled = excluded.enabled,
		   ord = excluded.ord, config = excluded.config, mfa_required = excluded.mfa_required,
		   passkeys = excluded.passkeys, auto_create = excluded.auto_create,
		   updated_at = excluded.updated_at`,
		p.ID, p.Kind, p.Name, p.Enabled, p.Order, string(cfg),
		p.MFARequired, p.Passkeys, p.AutoCreate, now, now)
	if err != nil {
		return fmt.Errorf("store: save auth provider %q: %w", p.Name, err)
	}
	return nil
}

const providerCols = `id, kind, name, enabled, ord, config, mfa_required, passkeys, auto_create, created_at, updated_at`

func scanProvider(sc scanner) (AuthProvider, error) {
	var p AuthProvider
	var cfg string
	if err := sc.Scan(&p.ID, &p.Kind, &p.Name, &p.Enabled, &p.Order, &cfg,
		&p.MFARequired, &p.Passkeys, &p.AutoCreate, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return p, err
	}
	if cfg != "" {
		if err := json.Unmarshal([]byte(cfg), &p.Config); err != nil {
			return p, fmt.Errorf("store: auth provider %q: bad config: %w", p.ID, err)
		}
	}
	return p, nil
}

// ListAuthProviders returns every authority in display order. Configs come
// back as STORED, references unresolved: listing is not using.
func (s *Store) ListAuthProviders(ctx context.Context) ([]AuthProvider, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+providerCols+` FROM auth_providers ORDER BY ord, name`)
	if err != nil {
		return nil, fmt.Errorf("store: list auth providers: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []AuthProvider
	for rows.Next() {
		p, err := scanProvider(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetAuthProvider returns one authority, config as stored.
func (s *Store) GetAuthProvider(ctx context.Context, id string) (AuthProvider, error) {
	p, err := scanProvider(s.db.QueryRowContext(ctx,
		`SELECT `+providerCols+` FROM auth_providers WHERE id = ?`, id))
	if err != nil {
		return p, fmt.Errorf("store: auth provider %q: %w", id, err)
	}
	return p, nil
}

// ResolvedAuthProvider returns one authority ready to USE: its $name
// references expanded in the INFRA scope, in memory only. Infra, because that
// is the plane an authority belongs to: it is a third-party service reached by
// URL with credentials, configured by an infra admin, who creates their
// secrets there. Resolving against the app scope meant an admin could never
// find the entry they had just created. The unresolved
// names come back so a misconfiguration names itself instead of failing as a
// bad client secret.
func (s *Store) ResolvedAuthProvider(ctx context.Context, id string) (AuthProvider, []string, error) {
	p, err := s.GetAuthProvider(ctx, id)
	if err != nil {
		return p, nil, err
	}
	values, err := s.VaultValues(ctx, vault.ScopeInfra)
	if err != nil {
		return p, nil, err
	}
	expanded, missing := vault.ExpandAny(p.Config, func(n string) (string, bool) {
		v, ok := values[n]
		return v, ok
	})
	if m, ok := expanded.(map[string]any); ok {
		p.Config = m
	}
	return p, missing, nil
}

// DeleteAuthProvider removes an authority; its identity links go with it, so
// the accounts stay but stop being reachable through it.
func (s *Store) DeleteAuthProvider(ctx context.Context, id string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM auth_providers WHERE id = ?`, id)
	if err != nil {
		return false, fmt.Errorf("store: delete auth provider %q: %w", id, err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ── identity links ───────────────────────────────────────────────────────────

// Identity links a local account to what one authority calls that person, plus
// what that authority last said about them.
type Identity struct {
	ProviderID string `json:"providerId"`
	ExternalID string `json:"externalId"`
	UserID     string `json:"userId"`
	// Groups is what the authority reported at the LAST sign-in: its own group
	// names, verbatim. Kept because an admin cannot map what they cannot see,
	// and because "which groups does upstream actually send" is the first
	// question every mapping raises.
	Groups     []string `json:"groups,omitempty"`
	CreatedAt  int64    `json:"createdAt"`
	LastSeenAt int64    `json:"lastSeenAt,omitempty"`
}

// LinkIdentity records that providerID's externalID is userID, and what the
// authority reported this time. Called on EVERY sign-in, not only the first:
// group membership changes upstream, and a snapshot from the day the account
// was created would describe someone who has since changed teams.
func (s *Store) LinkIdentity(ctx context.Context, providerID, externalID, userID string, groups []string) error {
	if providerID == "" || externalID == "" || userID == "" {
		return fmt.Errorf("store: an identity link needs a provider, an external id and a user")
	}
	raw, err := json.Marshal(groups)
	if err != nil {
		return fmt.Errorf("store: identity groups: %w", err)
	}
	if len(groups) == 0 {
		raw = nil // an authority that reports nothing stores nothing
	}
	now := time.Now().Unix()
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO user_identities (provider_id, external_id, user_id, groups, created_at, last_seen_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(provider_id, external_id) DO UPDATE SET
		   user_id = excluded.user_id, groups = excluded.groups,
		   last_seen_at = excluded.last_seen_at`,
		providerID, externalID, userID, string(raw), now, now)
	if err != nil {
		return fmt.Errorf("store: link identity %s/%s: %w", providerID, externalID, err)
	}
	return nil
}

// UserByIdentity resolves an authority's external id to a local account.
// sql.ErrNoRows means this person has never signed in here.
func (s *Store) UserByIdentity(ctx context.Context, providerID, externalID string) (User, error) {
	u, err := scanUser(s.db.QueryRowContext(ctx,
		`SELECT `+userCols+` FROM users
		 WHERE id = (SELECT user_id FROM user_identities WHERE provider_id = ? AND external_id = ?)`,
		providerID, externalID))
	if err != nil {
		if err == sql.ErrNoRows {
			return User{}, err
		}
		return User{}, fmt.Errorf("store: user by identity %s/%s: %w", providerID, externalID, err)
	}
	return u, nil
}

// IdentitiesOfUser lists the authorities one account can sign in through -
// what the profile and the admin's user drawer show.
func (s *Store) IdentitiesOfUser(ctx context.Context, userID string) ([]Identity, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT provider_id, external_id, user_id, groups, created_at, last_seen_at
		 FROM user_identities WHERE user_id = ? ORDER BY created_at`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: identities of %q: %w", userID, err)
	}
	defer func() { _ = rows.Close() }()
	var out []Identity
	for rows.Next() {
		var i Identity
		var groups string
		if err := rows.Scan(&i.ProviderID, &i.ExternalID, &i.UserID, &groups,
			&i.CreatedAt, &i.LastSeenAt); err != nil {
			return nil, fmt.Errorf("store: scan identity: %w", err)
		}
		if groups != "" {
			if err := json.Unmarshal([]byte(groups), &i.Groups); err != nil {
				return nil, fmt.Errorf("store: identity %s/%s groups: %w", i.ProviderID, i.ExternalID, err)
			}
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// UnlinkIdentity drops one link (the admin revoking an authority for one
// person, or a user detaching an account from their profile).
func (s *Store) UnlinkIdentity(ctx context.Context, providerID, externalID string) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM user_identities WHERE provider_id = ? AND external_id = ?`, providerID, externalID)
	if err != nil {
		return false, fmt.Errorf("store: unlink identity %s/%s: %w", providerID, externalID, err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
