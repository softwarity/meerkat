package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/softwarity/meerkat/internal/mfa"
)

// TOTPState is a user's second-factor enrolment (MFA-01). It is read and
// written only here, never through the User struct, so a TOTP secret never
// rides along the identity path (/api/me, admin listings).
type TOTPState struct {
	Enrolled bool     // a confirmed secret exists
	Secret   string   // the confirmed base32 secret ("" when not enrolled)
	Pending  string   // a secret mid-enrolment, awaiting its first valid code
	Scratch  []string // SHA-256 hashes of the remaining single-use backup codes
}

// GetUserTOTP loads a user's second-factor state.
func (s *Store) GetUserTOTP(ctx context.Context, userID string) (TOTPState, error) {
	var st TOTPState
	var scratch string
	err := s.db.QueryRowContext(ctx,
		`SELECT totp_secret, totp_pending, totp_scratch FROM users WHERE id = ?`, userID).
		Scan(&st.Secret, &st.Pending, &scratch)
	if err != nil {
		return TOTPState{}, fmt.Errorf("store: get TOTP for user %q: %w", userID, err)
	}
	if scratch != "" {
		if err := json.Unmarshal([]byte(scratch), &st.Scratch); err != nil {
			return TOTPState{}, fmt.Errorf("store: user %q: bad scratch codes: %w", userID, err)
		}
	}
	st.Enrolled = st.Secret != ""
	return st, nil
}

// SetUserTOTPPending stores a secret mid-enrolment: the user has been shown the
// QR code but has not yet confirmed a valid TOTP. Overwrites any previous
// pending secret (starting enrolment over) but leaves an already-confirmed
// secret untouched until EnableUserTOTP commits.
func (s *Store) SetUserTOTPPending(ctx context.Context, userID, pending string) error {
	return s.execUser(ctx, userID,
		`UPDATE users SET totp_pending = ?, updated_at = ? WHERE id = ?`,
		pending, time.Now().Unix(), userID)
}

// EnableUserTOTP commits an enrolment: the pending secret becomes the confirmed
// one and the freshly generated scratch-code hashes replace any old ones. Call
// it only after a code validated against `secret`.
func (s *Store) EnableUserTOTP(ctx context.Context, userID, secret string, scratchHashes []string) error {
	scratch, err := json.Marshal(scratchHashes)
	if err != nil {
		return fmt.Errorf("store: user %q: encode scratch codes: %w", userID, err)
	}
	return s.execUser(ctx, userID,
		`UPDATE users SET totp_secret = ?, totp_pending = '', totp_scratch = ?, updated_at = ? WHERE id = ?`,
		secret, string(scratch), time.Now().Unix(), userID)
}

// DisableUserTOTP removes the second factor entirely (only allowed when MFA is
// not mandatory for the user — the handler enforces that).
func (s *Store) DisableUserTOTP(ctx context.Context, userID string) error {
	return s.execUser(ctx, userID,
		`UPDATE users SET totp_secret = '', totp_pending = '', totp_scratch = '[]', updated_at = ? WHERE id = ?`,
		time.Now().Unix(), userID)
}

// ConsumeScratch checks a backup code against the stored hashes and, on a
// match, burns it (single use — MFA-01). Reports whether the code was valid.
func (s *Store) ConsumeScratch(ctx context.Context, userID, code string) (bool, error) {
	st, err := s.GetUserTOTP(ctx, userID)
	if err != nil {
		return false, err
	}
	want := mfa.HashScratch(code)
	remaining := make([]string, 0, len(st.Scratch))
	matched := false
	for _, h := range st.Scratch {
		if !matched && h == want {
			matched = true
			continue
		}
		remaining = append(remaining, h)
	}
	if !matched {
		return false, nil
	}
	scratch, err := json.Marshal(remaining)
	if err != nil {
		return false, fmt.Errorf("store: user %q: encode scratch codes: %w", userID, err)
	}
	if err := s.execUser(ctx, userID,
		`UPDATE users SET totp_scratch = ?, updated_at = ? WHERE id = ?`,
		string(scratch), time.Now().Unix(), userID); err != nil {
		return false, err
	}
	return true, nil
}

// execUser runs an UPDATE that must hit exactly one user row.
func (s *Store) execUser(ctx context.Context, userID, query string, args ...any) error {
	res, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("store: update TOTP for user %q: %w", userID, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store: update TOTP for user %q: %w", userID, sql.ErrNoRows)
	}
	return nil
}

// MFARequiredForUser reports whether the user must have a second factor
// (MFA-04). The policy is resolvable BEFORE tenant selection — which the login
// flow needs (AUTH-05 runs MFA first) — so it walks only user → global: the
// per-user override ("true"/"false") wins, otherwise the gateway-wide setting.
// There is deliberately no tenant level: the tenant is unknown at the MFA step.
func (s *Store) MFARequiredForUser(ctx context.Context, userID string) (bool, error) {
	u, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return false, err
	}
	switch u.MFARequired {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return s.globalMFARequired(ctx)
}

// globalMFARequired reads the gateway-wide policy, treating a missing key as
// "not required" so an older database never hard-fails a login.
func (s *Store) globalMFARequired(ctx context.Context) (bool, error) {
	var required bool
	if err := s.GetSetting(ctx, SettingMFARequired, &required); err != nil {
		return false, nil
	}
	return required, nil
}

// ---- trusted browsers (MFA-03) ----

// TrustedBrowser is a browser the user marked as trusted after an MFA success:
// while it is unexpired the login skips the TOTP challenge. Only the token hash
// is persisted; this shape (no hash) is what the profile lists.
type TrustedBrowser struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	CreatedAt int64  `json:"createdAt"`
	ExpiresAt int64  `json:"expiresAt"`
}

// TrustedBrowserPolicy is the gateway-wide trusted-browser setting: whether
// users may skip the TOTP challenge on a remembered browser, and for how long
// (ISO-8601, e.g. "P7D"). Resolved globally because the MFA step runs before
// tenant selection (AUTH-05) — a per-tenant override would need a re-challenge.
type TrustedBrowserPolicy struct {
	Allowed bool   `json:"allowed"`
	TTL     string `json:"ttl"`
}

// GetTrustedBrowserPolicy reads the policy, defaulting to disabled with a 7-day
// TTL if unset (an older database never surprises with trust it never granted).
func (s *Store) GetTrustedBrowserPolicy(ctx context.Context) (TrustedBrowserPolicy, error) {
	var p TrustedBrowserPolicy
	if err := s.GetSetting(ctx, SettingTrustedBrowser, &p); err != nil {
		return TrustedBrowserPolicy{TTL: "P7D"}, nil
	}
	if p.TTL == "" {
		p.TTL = "P7D"
	}
	return p, nil
}

// AddTrustedBrowser records a trusted browser by its token hash and expiry.
func (s *Store) AddTrustedBrowser(ctx context.Context, id, userID, tokenHash, label string, expiresAt int64) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO trusted_browsers (id, user_id, token_hash, label, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		id, userID, tokenHash, label, time.Now().Unix(), expiresAt)
	if err != nil {
		return fmt.Errorf("store: add trusted browser for %q: %w", userID, err)
	}
	return nil
}

// IsBrowserTrusted reports whether the token hash names a live trusted browser
// for the user (present and unexpired at now).
func (s *Store) IsBrowserTrusted(ctx context.Context, userID, tokenHash string, now int64) (bool, error) {
	var expires int64
	switch err := s.db.QueryRowContext(ctx,
		`SELECT expires_at FROM trusted_browsers WHERE user_id = ? AND token_hash = ?`,
		userID, tokenHash).Scan(&expires); err {
	case nil:
		return now < expires, nil
	case sql.ErrNoRows:
		return false, nil
	default:
		return false, fmt.Errorf("store: check trusted browser: %w", err)
	}
}

// TrustedBrowserIDByHash maps a live trust-token hash to its row id — the
// profile badges "this browser" through it.
func (s *Store) TrustedBrowserIDByHash(ctx context.Context, userID, tokenHash string, now int64) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM trusted_browsers WHERE user_id = ? AND token_hash = ? AND expires_at > ?`,
		userID, tokenHash, now).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("store: trusted browser lookup for %q: %w", userID, err)
	}
	return id, nil
}

// ListTrustedBrowsers returns the user's trusted browsers, newest first.
func (s *Store) ListTrustedBrowsers(ctx context.Context, userID string) ([]TrustedBrowser, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, label, created_at, expires_at FROM trusted_browsers
		 WHERE user_id = ? ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: list trusted browsers for %q: %w", userID, err)
	}
	defer func() { _ = rows.Close() }()
	var out []TrustedBrowser
	for rows.Next() {
		var b TrustedBrowser
		if err := rows.Scan(&b.ID, &b.Label, &b.CreatedAt, &b.ExpiresAt); err != nil {
			return nil, fmt.Errorf("store: scan trusted browser: %w", err)
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// RevokeTrustedBrowser deletes one of the user's trusted browsers (scoped by
// user so nobody revokes another's), reporting whether it existed.
func (s *Store) RevokeTrustedBrowser(ctx context.Context, userID, id string) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM trusted_browsers WHERE id = ? AND user_id = ?`, id, userID)
	if err != nil {
		return false, fmt.Errorf("store: revoke trusted browser %q: %w", id, err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// RevokeAllTrustedBrowsers clears every trusted browser for a user — used when
// the second factor is replaced or removed, so old trust never skips a new one.
func (s *Store) RevokeAllTrustedBrowsers(ctx context.Context, userID string) error {
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM trusted_browsers WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("store: revoke trusted browsers for %q: %w", userID, err)
	}
	return nil
}

// PurgeExpiredTrustedBrowsers removes lapsed trusts (periodic upkeep).
func (s *Store) PurgeExpiredTrustedBrowsers(ctx context.Context, now int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM trusted_browsers WHERE expires_at <= ?`, now)
	if err != nil {
		return 0, fmt.Errorf("store: purge trusted browsers: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
