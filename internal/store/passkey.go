package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// PasskeysAllowed reads the gateway-wide passkey policy (SettingPasskeys):
// whether users may register passkeys and sign in with them. A missing or
// unreadable key means allowed - the feature ships on; disabling is an
// explicit admin act.
func (s *Store) PasskeysAllowed(ctx context.Context) bool {
	var allowed bool
	if err := s.GetSetting(ctx, SettingPasskeys, &allowed); err != nil {
		return true
	}
	return allowed
}

// Passkey is a WebAuthn credential prepared for display (AUTH-15): the profile
// lists these so the user can name and revoke each device. The credential
// material itself never leaves the store as anything but an opaque blob.
type Passkey struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	CreatedAt  int64  `json:"createdAt"`
	LastUsedAt int64  `json:"lastUsedAt"`
}

// AddPasskey stores a freshly registered credential. data is the JSON of the
// go-webauthn Credential (opaque here); credID is its base64url raw ID.
func (s *Store) AddPasskey(ctx context.Context, id, userID, credID, data, label string) error {
	now := time.Now().Unix()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO webauthn_credentials (id, user_id, credential_id, data, label, created_at, last_used_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, userID, credID, data, label, now, now)
	if err != nil {
		return fmt.Errorf("store: add passkey for %q: %w", userID, err)
	}
	return nil
}

// ListPasskeys returns a user's credentials for display, newest first.
func (s *Store) ListPasskeys(ctx context.Context, userID string) ([]Passkey, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, label, created_at, last_used_at FROM webauthn_credentials
		 WHERE user_id = ? ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: list passkeys for %q: %w", userID, err)
	}
	defer func() { _ = rows.Close() }()
	var out []Passkey
	for rows.Next() {
		var p Passkey
		if err := rows.Scan(&p.ID, &p.Label, &p.CreatedAt, &p.LastUsedAt); err != nil {
			return nil, fmt.Errorf("store: scan passkey: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// PasskeyIDByCredential maps a raw credential id (base64url) back to the
// row id - the auth layer badges "this browser" through it.
func (s *Store) PasskeyIDByCredential(ctx context.Context, userID, credID string) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM webauthn_credentials WHERE user_id = ? AND credential_id = ?`,
		userID, credID).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("store: passkey lookup for %q: %w", userID, err)
	}
	return id, nil
}

// PasskeyBlobs returns the raw credential JSON blobs for a user - the auth layer
// decodes them into go-webauthn Credentials to build the WebAuthn user.
func (s *Store) PasskeyBlobs(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT data FROM webauthn_credentials WHERE user_id = ?`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: read passkeys for %q: %w", userID, err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, fmt.Errorf("store: scan passkey blob: %w", err)
		}
		out = append(out, data)
	}
	return out, rows.Err()
}

// HasPasskeys reports whether the user has at least one credential (drives the
// "Sign in with a passkey" affordance and whether the password may be replaced).
func (s *Store) HasPasskeys(ctx context.Context, userID string) (bool, error) {
	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ?`, userID).Scan(&n); err != nil {
		return false, fmt.Errorf("store: count passkeys for %q: %w", userID, err)
	}
	return n > 0, nil
}

// UpdatePasskeyData rewrites a credential's blob (e.g. the sign counter after a
// login) and stamps its last use, located by the base64url credential ID.
func (s *Store) UpdatePasskeyData(ctx context.Context, credID, data string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE webauthn_credentials SET data = ?, last_used_at = ? WHERE credential_id = ?`,
		data, time.Now().Unix(), credID)
	if err != nil {
		return fmt.Errorf("store: update passkey %q: %w", credID, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store: update passkey %q: %w", credID, sql.ErrNoRows)
	}
	return nil
}

// RevokePasskey deletes one of the user's credentials (scoped by user), reporting
// whether it existed.
func (s *Store) RevokePasskey(ctx context.Context, userID, id string) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?`, id, userID)
	if err != nil {
		return false, fmt.Errorf("store: revoke passkey %q: %w", id, err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// PutChallenge stores one-shot challenge state (WebAuthn SessionData, a
// captcha answer hash) under a random id.
func (s *Store) PutChallenge(ctx context.Context, id, data string, expiresAt int64) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO challenges (id, data, expires_at) VALUES (?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET data = excluded.data, expires_at = excluded.expires_at`,
		id, data, expiresAt)
	if err != nil {
		return fmt.Errorf("store: put challenge: %w", err)
	}
	return nil
}

// TakeChallenge returns and deletes the state for id - one shot, so a
// challenge can never be replayed. Returns sql.ErrNoRows if absent or
// already consumed.
func (s *Store) TakeChallenge(ctx context.Context, id string, now int64) (string, error) {
	var data string
	var expires int64
	err := s.db.QueryRowContext(ctx,
		`SELECT data, expires_at FROM challenges WHERE id = ?`, id).Scan(&data, &expires)
	if err != nil {
		return "", fmt.Errorf("store: take challenge: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM challenges WHERE id = ?`, id); err != nil {
		return "", fmt.Errorf("store: take challenge: %w", err)
	}
	if now >= expires {
		return "", sql.ErrNoRows
	}
	return data, nil
}

// PurgeExpiredChallenges drops lapsed challenge state (periodic upkeep).
func (s *Store) PurgeExpiredChallenges(ctx context.Context, now int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM challenges WHERE expires_at <= ?`, now)
	if err != nil {
		return 0, fmt.Errorf("store: purge challenges: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
