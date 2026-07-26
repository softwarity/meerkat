package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// newAuditID mints a random id for an event whose caller did not supply one
// (tests, or the emit helper leaving it to the store).
func newAuditID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// AuditEvent is one recorded administrative mutation (the audit trail). It
// captures WHO (actor), WHAT (action + target), and the exact field-level diff
// — only what changed, with before/after — so a group-mode edit reads as
// "groupMode: MULTIPLE → SINGLE", never "modified tenant X".
type AuditEvent struct {
	ID string `json:"id"`
	At int64  `json:"at"`
	// ActorID survives the actor's deletion (no FK); ActorName is joined on read.
	ActorID   string `json:"actorId"`
	ActorName string `json:"actorName,omitempty"`
	// Action is a dotted verb: "tenant.update", "member.remove", "settings.update"…
	Action string `json:"action"`
	// Target is the object kind ("tenant", "user", "membership", "role",
	// "group", "settings", "route"); TargetID/TargetName identify the instance
	// (TargetName captured at write time so it reads even after a delete).
	Target     string `json:"target"`
	TargetID   string `json:"targetId,omitempty"`
	TargetName string `json:"targetName,omitempty"`
	// TenantID scopes tenant-admin visibility ("" = a global/application event).
	TenantID string `json:"tenantId,omitempty"`
	// Changes is the field-level diff; Detail is a free note for create/delete
	// and events that have no meaningful before/after.
	Changes []FieldChange `json:"changes,omitempty"`
	Detail  string        `json:"detail,omitempty"`
}

// FieldChange is one field's before/after inside an AuditEvent. From/To are the
// decoded JSON values (string, number, bool, or a nested object/array).
type FieldChange struct {
	Field string `json:"field"`
	From  any    `json:"from"`
	To    any    `json:"to"`
}

// AuditScope is a visibility window: an event is visible when its target is in
// Targets (a whole domain, e.g. gateway = route/theme) OR its tenant_id is in
// TenantIDs (the tenants the caller administers). The two combine as OR, so a
// caller who is both app-admin and a tenant admin sees the union. Both empty
// means "nothing" (the caller administers no domain).
type AuditScope struct {
	Targets   []string
	TenantIDs []string
}

// AuditFilter narrows ListAuditEvents. All fields are optional; the zero value
// lists the most recent events across everything.
type AuditFilter struct {
	ActorID  string // exact actor
	Target   string // exact target kind
	TargetID string // exact target instance
	// Scope, when non-nil, restricts visibility (see AuditScope). Nil means no
	// restriction (root, or an internal caller).
	Scope *AuditScope
	Since int64 // at >= Since when > 0
	Until int64 // at <= Until when > 0
	Limit int   // capped result count (default 200)
}

// AddAuditEvent appends one event. It stamps ID (if empty) and At (if zero) so
// callers may pass a bare event.
func (s *Store) AddAuditEvent(ctx context.Context, ev AuditEvent) error {
	if ev.ID == "" {
		ev.ID = newAuditID()
	}
	if ev.At == 0 {
		ev.At = time.Now().Unix()
	}
	changes := "[]"
	if len(ev.Changes) > 0 {
		b, err := json.Marshal(ev.Changes)
		if err != nil {
			return fmt.Errorf("store: audit %q: encode changes: %w", ev.Action, err)
		}
		changes = string(b)
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_events (id, at, actor_id, action, target, target_id, target_name, tenant_id, changes, detail)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ev.ID, ev.At, ev.ActorID, ev.Action, ev.Target, ev.TargetID, ev.TargetName, ev.TenantID, changes, ev.Detail)
	if err != nil {
		return fmt.Errorf("store: add audit event %q: %w", ev.Action, err)
	}
	return nil
}

// ListAuditEvents returns matching events newest first, each enriched with the
// actor's current username (best-effort — "" if the actor is gone).
func (s *Store) ListAuditEvents(ctx context.Context, f AuditFilter) ([]AuditEvent, error) {
	var where []string
	var args []any
	if f.ActorID != "" {
		where = append(where, "e.actor_id = ?")
		args = append(args, f.ActorID)
	}
	if f.Target != "" {
		where = append(where, "e.target = ?")
		args = append(args, f.Target)
	}
	if f.TargetID != "" {
		where = append(where, "e.target_id = ?")
		args = append(args, f.TargetID)
	}
	if f.Scope != nil {
		if len(f.Scope.Targets) == 0 && len(f.Scope.TenantIDs) == 0 {
			return []AuditEvent{}, nil // no domain, no tenant → sees nothing
		}
		var ors []string
		if len(f.Scope.Targets) > 0 {
			ph := make([]string, len(f.Scope.Targets))
			for i, tgt := range f.Scope.Targets {
				ph[i] = "?"
				args = append(args, tgt)
			}
			ors = append(ors, "e.target IN ("+strings.Join(ph, ", ")+")")
		}
		if len(f.Scope.TenantIDs) > 0 {
			ph := make([]string, len(f.Scope.TenantIDs))
			for i, id := range f.Scope.TenantIDs {
				ph[i] = "?"
				args = append(args, id)
			}
			ors = append(ors, "e.tenant_id IN ("+strings.Join(ph, ", ")+")")
		}
		where = append(where, "("+strings.Join(ors, " OR ")+")")
	}
	if f.Since > 0 {
		where = append(where, "e.at >= ?")
		args = append(args, f.Since)
	}
	if f.Until > 0 {
		where = append(where, "e.at <= ?")
		args = append(args, f.Until)
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}
	q := `SELECT e.id, e.at, e.actor_id, COALESCE(u.username, ''), e.action, e.target,
	             e.target_id, e.target_name, e.tenant_id, e.changes, e.detail
	      FROM audit_events e
	      LEFT JOIN users u ON u.id = e.actor_id`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY e.at DESC, e.id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list audit events: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var events []AuditEvent
	for rows.Next() {
		var ev AuditEvent
		var changes string
		if err := rows.Scan(&ev.ID, &ev.At, &ev.ActorID, &ev.ActorName, &ev.Action, &ev.Target,
			&ev.TargetID, &ev.TargetName, &ev.TenantID, &changes, &ev.Detail); err != nil {
			return nil, fmt.Errorf("store: scan audit event: %w", err)
		}
		if changes != "" && changes != "[]" {
			if err := json.Unmarshal([]byte(changes), &ev.Changes); err != nil {
				return nil, fmt.Errorf("store: audit %q: bad changes: %w", ev.ID, err)
			}
		}
		events = append(events, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list audit events: %w", err)
	}
	return events, nil
}

// PurgeAuditEventsBefore drops events older than cutoff (retention upkeep) and
// reports how many were removed.
func (s *Store) PurgeAuditEventsBefore(ctx context.Context, cutoff int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM audit_events WHERE at < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("store: purge audit events: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
