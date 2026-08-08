package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Group rules (RBAC-10): turning what an authority SAYS into what someone may
// do here.
//
// The shape follows from one constraint. An authority belongs to the infra
// plane and only ever proves WHO someone is; tenants and groups belong to the
// application. So a rule is declared IN a tenant, by the people who administer
// it, and can only grant what is theirs. A directory reports one flat list of
// group names; each tenant confronts that list with its OWN rules, and nothing
// it declares can reach another tenant.
//
// That single shape covers both ways organisations map onto authorities:
//
//   - one directory, per-organisation groups: a rule per group name, e.g.
//     "cn=brest-agents" grants the Agents group of the Brest tenant;
//   - one directory PER organisation: a rule with an empty group name, which
//     reads "anyone who signs in through this authority is a member here".
//

// SourceRule marks a membership or a group that a RULE granted, as opposed to
// one an administrator placed (which carries no source). A synchronisation
// only ever adds or removes its own rows, so the two never fight.
const SourceRule = "rule"

// GroupRule is one such rule.
type GroupRule struct {
	ID       string `json:"id"`
	TenantID string `json:"tenantId"`
	// ProviderID restricts the rule to one authority; empty matches any.
	ProviderID string `json:"providerId,omitempty"`
	// External is the authority's own group name, VERBATIM (a DN, an
	// "org/team", a plain label). Empty matches anyone from the authority.
	External string `json:"external,omitempty"`
	// GroupID is the group of THIS tenant to grant. Empty grants the
	// membership alone, which is enough when the organisation has one group or
	// none.
	GroupID   string `json:"groupId,omitempty"`
	CreatedAt int64  `json:"createdAt"`
}

// SaveGroupRule inserts or updates one rule.
func (s *Store) SaveGroupRule(ctx context.Context, r GroupRule) error {
	r.ProviderID = strings.TrimSpace(r.ProviderID)
	r.External = strings.TrimSpace(r.External)
	if r.ID == "" || r.TenantID == "" {
		return fmt.Errorf("store: a group rule needs an id and a tenant")
	}
	// A rule matching every authority AND every group would hand this tenant to
	// anyone any authority authenticates - including one added later, for
	// something else entirely.
	if r.ProviderID == "" && r.External == "" {
		return fmt.Errorf("store: a group rule must name an authority, a group, or both: " +
			"one matching everything would admit anyone the gateway ever authenticates")
	}
	now := time.Now().Unix()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO group_rules (id, tenant_id, provider_id, external, group_id, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		   provider_id = excluded.provider_id, external = excluded.external,
		   group_id = excluded.group_id`,
		r.ID, r.TenantID, r.ProviderID, r.External, nullable(r.GroupID), now)
	if err != nil {
		return fmt.Errorf("store: save group rule: %w", err)
	}
	return nil
}

// ListGroupRules returns one tenant's rules.
func (s *Store) ListGroupRules(ctx context.Context, tenantID string) ([]GroupRule, error) {
	return s.scanRules(ctx,
		`SELECT id, tenant_id, provider_id, external, group_id, created_at
		 FROM group_rules WHERE tenant_id = ? ORDER BY external, created_at`, tenantID)
}

// AllGroupRules returns every rule, of every tenant: a sign-in is confronted
// with all of them at once, since one person may belong to several.
func (s *Store) AllGroupRules(ctx context.Context) ([]GroupRule, error) {
	return s.scanRules(ctx,
		`SELECT id, tenant_id, provider_id, external, group_id, created_at FROM group_rules`)
}

func (s *Store) scanRules(ctx context.Context, query string, args ...any) ([]GroupRule, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list group rules: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []GroupRule
	for rows.Next() {
		var r GroupRule
		var group sql.NullString
		if err := rows.Scan(&r.ID, &r.TenantID, &r.ProviderID, &r.External, &group, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: scan group rule: %w", err)
		}
		r.GroupID = group.String
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteGroupRule removes one rule from one tenant. What it granted is undone
// at the next sign-in, like any other change of the rules.
func (s *Store) DeleteGroupRule(ctx context.Context, tenantID, id string) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM group_rules WHERE tenant_id = ? AND id = ?`, tenantID, id)
	if err != nil {
		return false, fmt.Errorf("store: delete group rule: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ReportedGroups lists every group name the authorities have been heard to
// say, across all the identity links, sorted and without duplicates. It is
// what the rule editor offers instead of asking someone to retype a DN: a
// rule written against a remembered name matches nothing, silently, and
// "cn=Developers,OU=Groups" and "cn=developers,ou=groups" look identical to
// the person writing them.
func (s *Store) ReportedGroups(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT groups FROM user_identities WHERE groups != ''`)
	if err != nil {
		return nil, fmt.Errorf("store: reported groups: %w", err)
	}
	defer func() { _ = rows.Close() }()
	seen := map[string]bool{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("store: scan reported groups: %w", err)
		}
		var names []string
		if err := json.Unmarshal([]byte(raw), &names); err != nil {
			continue // a row we cannot read must not hide the others
		}
		for _, n := range names {
			seen[n] = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

// matches reports whether a rule applies to this authority and these reported
// group names.
func (r GroupRule) matches(providerID string, reported map[string]bool) bool {
	if r.ProviderID != "" && r.ProviderID != providerID {
		return false
	}
	return r.External == "" || reported[r.External]
}

// SyncMappedGroups applies every tenant's rules to one person, given what the
// authority just reported, and returns the tenants they now belong to through
// a rule.
//
// It is a SYNCHRONISATION, not an accumulation: memberships and groups that a
// rule granted before and no longer grants are taken back, because someone who
// left a team upstream must lose what that team gave them. Rows an
// administrator placed by hand carry no source and are never touched - neither
// added to nor removed - which is what lets the two coexist.
func (s *Store) SyncMappedGroups(ctx context.Context, userID, providerID string, reported []string) ([]string, error) {
	rules, err := s.AllGroupRules(ctx)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(reported))
	for _, g := range reported {
		seen[g] = true
	}
	// What the rules say this person should have, right now.
	tenants := map[string]bool{}
	groups := map[[2]string]bool{} // tenant -> group
	for _, r := range rules {
		if !r.matches(providerID, seen) {
			continue
		}
		tenants[r.TenantID] = true
		if r.GroupID != "" {
			groups[[2]string{r.TenantID, r.GroupID}] = true
		}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: sync mapped groups: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Grant what is missing. An existing row keeps ITS source: a membership an
	// admin placed stays theirs even when a rule would also grant it, so
	// removing the rule cannot revoke what they decided.
	now := time.Now().Unix()
	for tenantID := range tenants {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO memberships (user_id, tenant_id, type, enabled, source, created_at, updated_at)
			 VALUES (?, ?, 'USER', 1, ?, ?, ?)
			 ON CONFLICT(user_id, tenant_id) DO NOTHING`,
			userID, tenantID, SourceRule, now, now); err != nil {
			return nil, fmt.Errorf("store: grant membership of %q: %w", tenantID, err)
		}
	}
	for key := range groups {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO member_groups (tenant_id, user_id, group_id, source)
			 VALUES (?, ?, ?, ?)
			 ON CONFLICT(tenant_id, user_id, group_id) DO NOTHING`,
			key[0], userID, key[1], SourceRule); err != nil {
			return nil, fmt.Errorf("store: grant group %q: %w", key[1], err)
		}
	}

	// Take back what the rules no longer grant - and only that.
	rows, err := tx.QueryContext(ctx,
		`SELECT tenant_id, group_id FROM member_groups WHERE user_id = ? AND source = ?`,
		userID, SourceRule)
	if err != nil {
		return nil, fmt.Errorf("store: read mapped groups: %w", err)
	}
	var stale [][2]string
	for rows.Next() {
		var key [2]string
		if err := rows.Scan(&key[0], &key[1]); err != nil {
			_ = rows.Close()
			return nil, err
		}
		if !groups[key] {
			stale = append(stale, key)
		}
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, key := range stale {
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM member_groups WHERE tenant_id = ? AND user_id = ? AND group_id = ? AND source = ?`,
			key[0], userID, key[1], SourceRule); err != nil {
			return nil, err
		}
	}

	mrows, err := tx.QueryContext(ctx,
		`SELECT tenant_id FROM memberships WHERE user_id = ? AND source = ?`, userID, SourceRule)
	if err != nil {
		return nil, fmt.Errorf("store: read mapped memberships: %w", err)
	}
	var dropped []string
	for mrows.Next() {
		var tenantID string
		if err := mrows.Scan(&tenantID); err != nil {
			_ = mrows.Close()
			return nil, err
		}
		if !tenants[tenantID] {
			dropped = append(dropped, tenantID)
		}
	}
	_ = mrows.Close()
	if err := mrows.Err(); err != nil {
		return nil, err
	}
	for _, tenantID := range dropped {
		// The groups go with the membership: leaving them behind would let a
		// re-admission silently restore rights nobody granted again.
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM member_groups WHERE tenant_id = ? AND user_id = ? AND source = ?`,
			tenantID, userID, SourceRule); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM memberships WHERE tenant_id = ? AND user_id = ? AND source = ?`,
			tenantID, userID, SourceRule); err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: sync mapped groups: %w", err)
	}
	out := make([]string, 0, len(tenants))
	for tenantID := range tenants {
		out = append(out, tenantID)
	}
	return out, nil
}

// nullable turns "" into a NULL, so an empty group id does not have to satisfy
// the foreign key on groups.
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
