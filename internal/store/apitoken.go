package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// API tokens (AUTH-16): a personal access token authenticates its owner on
// the DATA plane's API routes without a browser session. It CAPTURES the
// session context it was born in - the active tenant and (in exclusive mode)
// the active group - so an API call needs no interactive tenant/group choice.
// Only the token HASH is stored; the clear value is shown once at creation.

// APITokensAllowed reads the gateway-wide policy (SettingAPITokens): whether
// users may mint and use API tokens. Missing key = allowed (ships on).
func (s *Store) APITokensAllowed(ctx context.Context) bool {
	var allowed bool
	if err := s.GetSetting(ctx, SettingAPITokens, &allowed); err != nil {
		return true
	}
	return allowed
}

// APIToken is one token prepared for display (never carries the hash out).
type APIToken struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Prefix     string `json:"prefix"` // first clear chars, to recognise it
	Plane      string `json:"plane"`  // data | admin (control plane)
	TenantID   string `json:"tenantId"`
	TenantName string `json:"tenantName"`
	GroupID    string `json:"groupId"`
	GroupName  string `json:"groupName"`
	Enabled    bool   `json:"enabled"`
	CreatedAt  int64  `json:"createdAt"`
	ExpiresAt  int64  `json:"expiresAt"` // 0 = never
	LastUsedAt int64  `json:"lastUsedAt"`
}

// ResolvedToken is the context a valid token authenticates as.
type ResolvedToken struct {
	ID         string
	UserID     string
	Plane      string // the plane this token is valid on (data | admin)
	TenantID   string
	GroupID    string
	LastUsedAt int64
}

// AddAPIToken records a freshly minted token by its hash on the given plane
// (data|admin), capturing the caller's tenant and group (empty for admin).
func (s *Store) AddAPIToken(ctx context.Context, id, userID, name, tokenHash, prefix, plane, tenantID, groupID string, expiresAt int64) error {
	if plane == "" {
		plane = PlaneData
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO api_tokens (id, user_id, name, token_hash, prefix, plane, tenant_id, group_id, enabled, created_at, expires_at, last_used_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, 0)`,
		id, userID, name, tokenHash, prefix, plane, tenantID, groupID, time.Now().Unix(), expiresAt)
	if err != nil {
		return fmt.Errorf("store: add api token for %q: %w", userID, err)
	}
	return nil
}

// ResolveAPIToken maps a token hash to its live context (AUTH-16): present,
// enabled, unexpired. The caller still checks the user is enabled. Returns
// sql.ErrNoRows when absent/disabled/expired - all "no token".
func (s *Store) ResolveAPIToken(ctx context.Context, tokenHash string, now int64) (ResolvedToken, error) {
	var t ResolvedToken
	var enabled bool
	var expires int64
	err := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, plane, tenant_id, group_id, enabled, expires_at, last_used_at FROM api_tokens WHERE token_hash = ?`,
		tokenHash).Scan(&t.ID, &t.UserID, &t.Plane, &t.TenantID, &t.GroupID, &enabled, &expires, &t.LastUsedAt)
	if err != nil {
		return ResolvedToken{}, err // sql.ErrNoRows is the "no token" signal
	}
	if !enabled || (expires != 0 && now >= expires) {
		return ResolvedToken{}, sql.ErrNoRows
	}
	return t, nil
}

// TouchAPIToken stamps a token's last use (best-effort, throttled by caller).
func (s *Store) TouchAPIToken(ctx context.Context, id string, now int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE api_tokens SET last_used_at = ? WHERE id = ?`, now, id)
	return err
}

// ListAPITokens returns a user's tokens ON THE GIVEN PLANE (with tenant names),
// newest first. The two planes are listed separately (the profile page shows
// data tokens, the Gateway page shows admin tokens).
func (s *Store) ListAPITokens(ctx context.Context, userID, plane string) ([]APIToken, error) {
	if plane == "" {
		plane = PlaneData
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT a.id, a.name, a.prefix, a.plane, a.tenant_id, COALESCE(t.name, ''), a.group_id, COALESCE(g.name, ''),
		        a.enabled, a.created_at, a.expires_at, a.last_used_at
		 FROM api_tokens a
		 LEFT JOIN tenants t ON t.id = a.tenant_id
		 LEFT JOIN groups g ON g.id = a.group_id
		 WHERE a.user_id = ? AND a.plane = ? ORDER BY a.created_at DESC`, userID, plane)
	if err != nil {
		return nil, fmt.Errorf("store: list api tokens for %q: %w", userID, err)
	}
	defer func() { _ = rows.Close() }()
	var out []APIToken
	for rows.Next() {
		var a APIToken
		if err := rows.Scan(&a.ID, &a.Name, &a.Prefix, &a.Plane, &a.TenantID, &a.TenantName, &a.GroupID, &a.GroupName,
			&a.Enabled, &a.CreatedAt, &a.ExpiresAt, &a.LastUsedAt); err != nil {
			return nil, fmt.Errorf("store: scan api token: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// SetAPITokenEnabled toggles a token on/off (scoped by user), reporting
// whether it existed.
func (s *Store) SetAPITokenEnabled(ctx context.Context, userID, id string, enabled bool) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE api_tokens SET enabled = ? WHERE id = ? AND user_id = ?`, enabled, id, userID)
	if err != nil {
		return false, fmt.Errorf("store: set api token %q: %w", id, err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// RevokeAPIToken deletes one of the user's tokens (scoped by user), reporting
// whether it existed.
func (s *Store) RevokeAPIToken(ctx context.Context, userID, id string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM api_tokens WHERE id = ? AND user_id = ?`, id, userID)
	if err != nil {
		return false, fmt.Errorf("store: revoke api token %q: %w", id, err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// PurgeExpiredAPITokens drops lapsed tokens (periodic upkeep).
func (s *Store) PurgeExpiredAPITokens(ctx context.Context, now int64) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM api_tokens WHERE expires_at != 0 AND expires_at <= ?`, now)
	if err != nil {
		return 0, fmt.Errorf("store: purge api tokens: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
