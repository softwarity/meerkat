package admin

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/softwarity/meerkat/internal/store"
)

// The audit trail (phase 2). Every administrative mutation records WHO changed
// WHAT, and — for updates — the exact field-level diff (before/after). The diff
// is computed generically by JSON-marshaling the old and new value and
// comparing top-level keys, so it works for tenants, users, memberships, roles,
// groups and the settings payload without per-type code.

// AuditRetention is how long events are kept; older ones are purged by the
// periodic ticker (called from main). A year is plenty for an admin trail and
// bounds the table.
const AuditRetention = 365 * 24 * time.Hour

// auditIgnore are keys never worth recording as a change: identifiers, server
// timestamps, and the GET-only display fields that ride along on a round-trip.
var auditIgnore = map[string]bool{
	"id": true, "createdAt": true, "updatedAt": true, "lastConnectionAt": true,
	"createdByName": true, "ownerName": true, "tenantName": true,
}

// The audit domains (RBAC-05): each administrative capability sees its own
// slice of the trail. infra-admin runs the routing plane (routes, themes);
// app-admin runs the application's identity (users, roles, settings); a tenant
// admin sees their tenants' events (scoped by tenant_id, not by target). Root
// sees everything. A user who administers nothing sees nothing.
var (
	infraTargets = []string{"route", "theme", "token"}
	appTargets   = []string{"user", "role", "settings"}
)

// auditRegisterViewer mounts the read-only audit endpoint. It is a section of
// its own (not under Application): the handler scopes each caller to the
// domains their capabilities cover, so routes show to infra admins and
// identity changes to app admins.
func (a *API) auditRegisterViewer(mux *http.ServeMux) {
	mux.Handle("GET /api/audit", a.authed(a.listAudit))
}

// audit records one event, best-effort: an audit write must never fail the
// mutation it trails, so an error is logged, not propagated.
func (a *API) audit(ctx context.Context, ev store.AuditEvent) {
	if err := a.st.AddAuditEvent(ctx, ev); err != nil {
		slog.Error("audit write failed", "action", ev.Action, "target", ev.Target, "err", err)
	}
}

// auditUpdate records an update only when something actually changed — an empty
// diff writes nothing (no noise for a no-op save).
func (a *API) auditUpdate(ctx context.Context, actor store.User, action, target, targetID, targetName, tenantID string, oldV, newV any) {
	changes := diffFields(oldV, newV)
	if len(changes) == 0 {
		return
	}
	a.audit(ctx, store.AuditEvent{
		At: time.Now().Unix(), ActorID: actor.ID, Action: action,
		Target: target, TargetID: targetID, TargetName: targetName,
		TenantID: tenantID, Changes: changes,
	})
}

// auditEvent records a create/delete/action event (no diff, an optional note).
func (a *API) auditEvent(ctx context.Context, actor store.User, action, target, targetID, targetName, tenantID, detail string) {
	a.audit(ctx, store.AuditEvent{
		At: time.Now().Unix(), ActorID: actor.ID, Action: action,
		Target: target, TargetID: targetID, TargetName: targetName,
		TenantID: tenantID, Detail: detail,
	})
}

// diffFields returns the top-level fields that differ between oldV and newV,
// keyed by JSON field name, each carrying the before/after value. Nested
// objects/arrays compare by their JSON encoding (a change anywhere inside
// surfaces the whole field). Ignored keys are skipped; sensitive leaf values
// (passwords, secrets, tokens, hashes) are redacted in place.
func diffFields(oldV, newV any) []store.FieldChange {
	om := toMap(oldV)
	nm := toMap(newV)
	seen := map[string]bool{}
	var keys []string
	for k := range om {
		if !auditIgnore[k] {
			keys = append(keys, k)
			seen[k] = true
		}
	}
	for k := range nm {
		if !auditIgnore[k] && !seen[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var changes []store.FieldChange
	for _, k := range keys {
		ov, nv := om[k], nm[k]
		if jsonEqual(ov, nv) {
			continue
		}
		changes = append(changes, store.FieldChange{Field: k, From: redact(k, ov), To: redact(k, nv)})
	}
	return changes
}

// toMap renders any struct/map to a map[string]any via JSON (honours json tags,
// drops json:"-" fields). A non-object marshals to an empty map — the diff then
// treats it as "no fields", which is the safe default.
func toMap(v any) map[string]any {
	if v == nil {
		return map[string]any{}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return map[string]any{}
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return map[string]any{}
	}
	return m
}

// jsonEqual compares two decoded JSON values by their canonical encoding (Go
// sorts map keys, so re-marshaling is order-stable).
func jsonEqual(a, b any) bool {
	ab, err1 := json.Marshal(a)
	bb, err2 := json.Marshal(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return string(ab) == string(bb)
}

// redact replaces sensitive values with "***" so a secret never lands in the
// trail — either because the key itself is sensitive, or because it hides
// inside a nested object (walked recursively).
func redact(key string, v any) any {
	if isSensitiveKey(key) {
		return "***"
	}
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = redact(k, val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = redact(key, val)
		}
		return out
	default:
		return v
	}
}

func isSensitiveKey(k string) bool {
	k = strings.ToLower(k)
	return strings.Contains(k, "password") || strings.Contains(k, "secret") ||
		strings.Contains(k, "token") || strings.Contains(k, "hash")
}

// listAudit serves the audit trail, scoped to the caller. Query params:
// actor, target, targetId, since, until (unix seconds), limit.
func (a *API) listAudit(w http.ResponseWriter, r *http.Request, actor store.User) {
	f := store.AuditFilter{
		ActorID:  strings.TrimSpace(r.URL.Query().Get("actor")),
		Target:   strings.TrimSpace(r.URL.Query().Get("target")),
		TargetID: strings.TrimSpace(r.URL.Query().Get("targetId")),
		Since:    atoi64(r.URL.Query().Get("since")),
		Until:    atoi64(r.URL.Query().Get("until")),
		Limit:    int(atoi64(r.URL.Query().Get("limit"))),
	}
	// Scope by capability (RBAC-05): root sees all; otherwise the union of the
	// domains the caller administers. infra-admin → routing plane targets,
	// app-admin → identity targets, tenant admin → their tenants (by tenant_id).
	// Administering nothing → 403 (the trail is an administrative view, not an
	// empty page).
	if !actor.Root {
		scope := &store.AuditScope{}
		if actor.InfraAdmin {
			scope.Targets = append(scope.Targets, infraTargets...)
		}
		if actor.AppAdmin {
			scope.Targets = append(scope.Targets, appTargets...)
		}
		administered, err := a.st.ListTenantsAdministeredBy(r.Context(), actor.ID)
		if err != nil {
			a.internal(w, err)
			return
		}
		for _, t := range administered {
			scope.TenantIDs = append(scope.TenantIDs, t.ID)
		}
		if len(scope.Targets) == 0 && len(scope.TenantIDs) == 0 {
			writeErr(w, http.StatusForbidden,
				"the audit trail requires root, a gateway/app-admin capability, or a tenant administration")
			return
		}
		f.Scope = scope
	}
	events, err := a.st.ListAuditEvents(r.Context(), f)
	if err != nil {
		a.internal(w, err)
		return
	}
	if events == nil {
		events = []store.AuditEvent{}
	}
	writeJSON(w, http.StatusOK, events)
}

func atoi64(s string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n
}
