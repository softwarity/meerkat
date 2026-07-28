package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/softwarity/meerkat/internal/mail"
	"github.com/softwarity/meerkat/internal/vault"
)

// Outbound e-mail + self-registration (AUTH-20): the SMTP config is a
// gateway-wide setting; self-registration is a policy PER PROVIDER (local
// only today — external providers will carry their own knob).

// GetSMTP reads the SMTP config; an unset key means "not configured" (zero
// value), which mail.Send refuses explicitly. Vault references ($name) are
// expanded here, so the stored setting keeps the reference and the password
// never sits in the settings table.
//
// The two halves resolve in THEIR OWN scope, matching who owns them. The relay
// (host, credentials AND the sender address, which providers tie to the
// authenticated account) is infrastructure; only the display name is the
// application's. Resolving the relay's password against the app scope would let
// an app admin decide what the relay authenticates with.
func (s *Store) GetSMTP(ctx context.Context) mail.Config {
	var cfg mail.Config
	_ = s.GetSetting(ctx, SettingSMTP, &cfg)
	cfg.Host, cfg.Username, cfg.Password = s.expandRelay(ctx, cfg.Host, cfg.Username, cfg.Password)
	if values, err := s.VaultValues(ctx, vault.ScopeInfra); err == nil {
		cfg.From, _ = vault.Expand(cfg.From, func(n string) (string, bool) { v, ok := values[n]; return v, ok })
	}
	if values, err := s.VaultValues(ctx, vault.ScopeApp); err == nil {
		cfg.FromName, _ = vault.Expand(cfg.FromName, func(n string) (string, bool) { v, ok := values[n]; return v, ok })
	}
	return cfg
}

// ExpandRelay resolves the INFRA-scope references of a mail relay's transport
// fields. Exported so a relay can be TESTED before being saved: the form may
// carry "${smtp-password}", which has to become the real secret to connect.
func (s *Store) ExpandRelay(ctx context.Context, host, username, password string) (string, string, string) {
	return s.expandRelay(ctx, host, username, password)
}

// ExpandInfra resolves the INFRA-scope references of one value (the relay's
// sender address, tested before being saved like the rest of the transport).
func (s *Store) ExpandInfra(ctx context.Context, value string) string {
	values, err := s.VaultValues(ctx, vault.ScopeInfra)
	if err != nil {
		return value
	}
	out, _ := vault.Expand(value, func(n string) (string, bool) { v, ok := values[n]; return v, ok })
	return out
}

func (s *Store) expandRelay(ctx context.Context, host, username, password string) (string, string, string) {
	values, err := s.VaultValues(ctx, vault.ScopeInfra)
	if err != nil {
		return host, username, password
	}
	lookup := func(name string) (string, bool) {
		v, ok := values[name]
		return v, ok
	}
	host, _ = vault.Expand(host, lookup)
	username, _ = vault.Expand(username, lookup)
	password, _ = vault.Expand(password, lookup)
	return host, username, password
}

// RegistrationPolicy says who may create their own account (AUTH-20).
// Everything ships CLOSED: opening self-registration is an explicit admin act.
type RegistrationPolicy struct {
	// LocalEnabled opens the /register page (local accounts, e-mail confirmed).
	LocalEnabled bool `json:"localEnabled"`
	// CaptchaDisabled turns the home-grown captcha OFF (inverted so the safe
	// behaviour — captcha on — is the zero value of an older stored policy).
	CaptchaDisabled bool `json:"captchaDisabled"`
}

// GetRegistrationPolicy reads the policy; a missing key means all closed.
func (s *Store) GetRegistrationPolicy(ctx context.Context) RegistrationPolicy {
	var p RegistrationPolicy
	_ = s.GetSetting(ctx, SettingRegistration, &p)
	return p
}

// RateLimitPolicy throttles the unauthenticated credential endpoints
// (SEC-10): failed sign-ins per IP+account, wrong TOTP codes per account.
// Zero attempts disables a limiter (debug); missing fields take the defaults.
type RateLimitPolicy struct {
	// LoginAttempts: FAILED sign-ins tolerated per IP+username within
	// LoginWindow before /login answers 429. A success clears the counter.
	LoginAttempts int    `json:"loginAttempts"`
	LoginWindow   string `json:"loginWindow"` // ISO-8601 duration
	// TotpAttempts: wrong TOTP codes tolerated per account within the login
	// window before the challenge answers 429.
	TotpAttempts int `json:"totpAttempts"`
}

// GetRateLimitPolicy reads the policy, filling defaults for missing pieces.
func (s *Store) GetRateLimitPolicy(ctx context.Context) RateLimitPolicy {
	p := RateLimitPolicy{LoginAttempts: 10, LoginWindow: "PT15M", TotpAttempts: 5}
	var stored RateLimitPolicy
	if err := s.GetSetting(ctx, SettingRateLimit, &stored); err == nil {
		p = stored
		if p.LoginWindow == "" {
			p.LoginWindow = "PT15M"
		}
	}
	return p
}

// ---- one-shot e-mail tokens (confirmation now, password reset later) ----

// PutEmailToken stores a one-shot token by HASH for a user and purpose.
func (s *Store) PutEmailToken(ctx context.Context, tokenHash, userID, purpose string, expiresAt int64) error {
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO email_tokens (token_hash, user_id, purpose, expires_at) VALUES (?, ?, ?, ?)`,
		tokenHash, userID, purpose, expiresAt); err != nil {
		return fmt.Errorf("store: put email token for %q: %w", userID, err)
	}
	return nil
}

// PeekEmailToken checks a token WITHOUT consuming it — the reset link's GET
// must survive the mail scanners that prefetch URLs; only the POST consumes.
func (s *Store) PeekEmailToken(ctx context.Context, tokenHash, purpose string, now int64) (string, error) {
	var userID string
	var expires int64
	err := s.db.QueryRowContext(ctx,
		`SELECT user_id, expires_at FROM email_tokens WHERE token_hash = ? AND purpose = ?`,
		tokenHash, purpose).Scan(&userID, &expires)
	if err != nil {
		return "", fmt.Errorf("store: email token lookup: %w", err)
	}
	if now >= expires {
		return "", fmt.Errorf("store: email token expired")
	}
	return userID, nil
}

// TakeEmailToken consumes a live token (one shot), returning its user.
func (s *Store) TakeEmailToken(ctx context.Context, tokenHash, purpose string, now int64) (string, error) {
	var userID string
	var expires int64
	err := s.db.QueryRowContext(ctx,
		`SELECT user_id, expires_at FROM email_tokens WHERE token_hash = ? AND purpose = ?`,
		tokenHash, purpose).Scan(&userID, &expires)
	if err != nil {
		return "", fmt.Errorf("store: email token lookup: %w", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM email_tokens WHERE token_hash = ?`, tokenHash); err != nil {
		return "", fmt.Errorf("store: burn email token: %w", err)
	}
	if now >= expires {
		return "", fmt.Errorf("store: email token expired")
	}
	return userID, nil
}

// MarkEmailVerified flips the user's address to verified.
func (s *Store) MarkEmailVerified(ctx context.Context, userID string) error {
	return s.execUser(ctx, userID,
		`UPDATE users SET email_verified = 1, updated_at = ? WHERE id = ?`,
		time.Now().Unix(), userID)
}

// UserIDByEmail resolves an e-mail to its account, sql.ErrNoRows when free.
func (s *Store) UserIDByEmail(ctx context.Context, email string) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM users WHERE email = ? COLLATE NOCASE`, email).Scan(&id)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", err
		}
		return "", fmt.Errorf("store: user by email: %w", err)
	}
	return id, nil
}

// ListNotifiableAdmins lists who receives account-management notifications:
// the enabled root and app-admin users that carry an e-mail address (the
// application's identity is app-admin scope — RBAC-05).
func (s *Store) ListNotifiableAdmins(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+userCols+` FROM users
		 WHERE enabled = 1 AND email != '' AND (root = 1 OR app_admin = 1)
		 ORDER BY username`)
	if err != nil {
		return nil, fmt.Errorf("store: list notifiable admins: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scan admin: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// PurgeExpiredEmailTokens removes lapsed tokens (periodic upkeep).
func (s *Store) PurgeExpiredEmailTokens(ctx context.Context, now int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM email_tokens WHERE expires_at <= ?`, now)
	if err != nil {
		return 0, fmt.Errorf("store: purge email tokens: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// PurgeUnconfirmedSelfRegistrations drops self-registered accounts that never
// confirmed their address before the cutoff (abandoned sign-ups).
func (s *Store) PurgeUnconfirmedSelfRegistrations(ctx context.Context, cutoff int64) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM users WHERE self_registered = 1 AND email_verified = 0 AND created_at < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("store: purge unconfirmed sign-ups: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
