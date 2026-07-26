package store

import (
	"context"
	"fmt"
)

// LoginEvent is one COMPLETED sign-in (password, password+code, or passkey):
// the profile's sign-in history lists them. browser_hash identifies the
// browser that signed in (the hash of its durable MEERKAT_BROWSER token) so
// the history can badge "this browser"; country is best-effort, captured from
// a fronting CDN/LB geo header when one exists (the gateway is offline-first
// and never calls a GeoIP service itself).
type LoginEvent struct {
	ID          string `json:"id"`
	Method      string `json:"method"` // password | totp | passkey
	Label       string `json:"label"`  // "Chrome · macOS"
	IP          string `json:"ip"`
	Country     string `json:"country"` // ISO 3166-1 alpha-2, "" when unknown
	BrowserHash string `json:"-"`
	At          int64  `json:"at"`
}

// loginHistoryKeep bounds the history per user: adding an event prunes beyond
// this depth, so the table never grows with login traffic.
const loginHistoryKeep = 50

// AddLoginEvent records a completed sign-in and prunes the user's history to
// the retention depth.
func (s *Store) AddLoginEvent(ctx context.Context, e LoginEvent, userID string) error {
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO login_events (id, user_id, method, label, ip, country, browser_hash, at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, userID, e.Method, e.Label, e.IP, e.Country, e.BrowserHash, e.At); err != nil {
		return fmt.Errorf("store: add login event for %q: %w", userID, err)
	}
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM login_events WHERE user_id = ? AND id NOT IN (
		   SELECT id FROM login_events WHERE user_id = ? ORDER BY at DESC, rowid DESC LIMIT ?)`,
		userID, userID, loginHistoryKeep); err != nil {
		return fmt.Errorf("store: prune login events for %q: %w", userID, err)
	}
	return nil
}

// ListLoginEvents returns the user's sign-in history, newest first.
func (s *Store) ListLoginEvents(ctx context.Context, userID string) ([]LoginEvent, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, method, label, ip, country, browser_hash, at FROM login_events
		 WHERE user_id = ? ORDER BY at DESC, rowid DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: list login events for %q: %w", userID, err)
	}
	defer func() { _ = rows.Close() }()
	var out []LoginEvent
	for rows.Next() {
		var e LoginEvent
		if err := rows.Scan(&e.ID, &e.Method, &e.Label, &e.IP, &e.Country, &e.BrowserHash, &e.At); err != nil {
			return nil, fmt.Errorf("store: scan login event: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
