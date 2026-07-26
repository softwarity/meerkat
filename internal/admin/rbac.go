package admin

import (
	"context"
	"net/http"
	"time"

	"github.com/softwarity/meerkat/internal/store"
)

// RBAC admin API (RBAC-01/02/03): the GLOBAL role catalogue (root only) and the
// per-tenant groups + member↔group assignments (root or the tenant's
// OWNER/ADMIN, via tenantScoped). Roles are created at the application level;
// groups are the tenant admin's responsibility within their org.
func (a *API) registerRBAC(mux *http.ServeMux) {
	mux.Handle("GET /api/roles", a.appAdmin(a.listRoles))
	mux.Handle("POST /api/roles", a.appAdmin(a.createRole))
	mux.Handle("PUT /api/roles/{id}", a.appAdmin(a.updateRole))
	mux.Handle("DELETE /api/roles/{id}", a.appAdmin(a.deleteRole))

	mux.Handle("GET /api/tenants/{id}/groups", a.tenantScoped(a.listGroups))
	mux.Handle("POST /api/tenants/{id}/groups", a.tenantScoped(a.createGroup))
	mux.Handle("PUT /api/tenants/{id}/groups/{groupId}", a.tenantScoped(a.updateGroup))
	mux.Handle("DELETE /api/tenants/{id}/groups/{groupId}", a.tenantScoped(a.deleteGroup))

	mux.Handle("GET /api/tenants/{id}/members/{userId}/groups", a.tenantScoped(a.getMemberGroups))
	mux.Handle("PUT /api/tenants/{id}/members/{userId}/groups", a.tenantScoped(a.putMemberGroups))
}

// ── Roles (global catalogue, root) ───────────────────────────────────────────

func (a *API) listRoles(w http.ResponseWriter, r *http.Request, _ store.User) {
	roles, err := a.st.ListRoles(r.Context())
	if err != nil {
		a.internal(w, err)
		return
	}
	if roles == nil {
		roles = []store.Role{}
	}
	writeJSON(w, http.StatusOK, roles)
}

func (a *API) createRole(w http.ResponseWriter, r *http.Request, actor store.User) {
	var role store.Role
	if err := decodeStrict(r, &role); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed role: "+err.Error())
		return
	}
	role.ID = newID()
	if err := a.st.SaveRole(r.Context(), role); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	a.auditEvent(r.Context(), actor, "role.create", "role", role.ID, role.Name, "", "")
	a.writeRole(w, r, role.ID)
}

func (a *API) updateRole(w http.ResponseWriter, r *http.Request, actor store.User) {
	var role store.Role
	if err := decodeStrict(r, &role); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed role: "+err.Error())
		return
	}
	role.ID = r.PathValue("id")
	old, err := a.st.GetRole(r.Context(), role.ID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "role not found")
		return
	}
	if err := a.st.SaveRole(r.Context(), role); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if saved, err := a.st.GetRole(r.Context(), role.ID); err == nil {
		a.auditUpdate(r.Context(), actor, "role.update", "role", saved.ID, saved.Name, "", old, saved)
	}
	a.writeRole(w, r, role.ID)
}

func (a *API) deleteRole(w http.ResponseWriter, r *http.Request, actor store.User) {
	id := r.PathValue("id")
	role, _ := a.st.GetRole(r.Context(), id) // capture the name before it is gone
	ok, err := a.st.DeleteRole(r.Context(), id)
	if err != nil {
		// A system role is protected — the store reports why.
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "role not found")
		return
	}
	a.auditEvent(r.Context(), actor, "role.delete", "role", id, role.Name, "", "")
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) writeRole(w http.ResponseWriter, r *http.Request, id string) {
	saved, err := a.st.GetRole(r.Context(), id)
	if err != nil {
		a.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

// ── Groups (per tenant, tenantScoped) ────────────────────────────────────────

func (a *API) listGroups(w http.ResponseWriter, r *http.Request, _ store.User) {
	groups, err := a.st.ListGroups(r.Context(), r.PathValue("id"))
	if err != nil {
		a.internal(w, err)
		return
	}
	if groups == nil {
		groups = []store.Group{}
	}
	writeJSON(w, http.StatusOK, groups)
}

func (a *API) createGroup(w http.ResponseWriter, r *http.Request, actor store.User) {
	var g store.Group
	if err := decodeStrict(r, &g); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed group: "+err.Error())
		return
	}
	g.ID = newID()
	g.TenantID = r.PathValue("id")
	if err := a.st.SaveGroup(r.Context(), g); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	a.auditEvent(r.Context(), actor, "group.create", "group", g.ID, g.Name, g.TenantID, "")
	a.writeGroup(w, r, g.ID)
}

func (a *API) updateGroup(w http.ResponseWriter, r *http.Request, actor store.User) {
	var g store.Group
	if err := decodeStrict(r, &g); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed group: "+err.Error())
		return
	}
	g.ID = r.PathValue("groupId")
	g.TenantID = r.PathValue("id")
	existing, err := a.st.GetGroup(r.Context(), g.ID)
	if err != nil || existing.TenantID != g.TenantID {
		writeErr(w, http.StatusNotFound, "group not found")
		return
	}
	if err := a.st.SaveGroup(r.Context(), g); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if saved, err := a.st.GetGroup(r.Context(), g.ID); err == nil {
		a.auditUpdate(r.Context(), actor, "group.update", "group", saved.ID, saved.Name, saved.TenantID, existing, saved)
	}
	a.writeGroup(w, r, g.ID)
}

func (a *API) deleteGroup(w http.ResponseWriter, r *http.Request, actor store.User) {
	// Confirm the group belongs to this tenant before deleting (path scoping).
	g, err := a.st.GetGroup(r.Context(), r.PathValue("groupId"))
	if err != nil || g.TenantID != r.PathValue("id") {
		writeErr(w, http.StatusNotFound, "group not found")
		return
	}
	if _, err := a.st.DeleteGroup(r.Context(), g.ID); err != nil {
		a.internal(w, err)
		return
	}
	a.auditEvent(r.Context(), actor, "group.delete", "group", g.ID, g.Name, g.TenantID, "")
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) writeGroup(w http.ResponseWriter, r *http.Request, id string) {
	saved, err := a.st.GetGroup(r.Context(), id)
	if err != nil {
		a.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

// ── Member ↔ groups (per tenant, tenantScoped) ───────────────────────────────

func (a *API) getMemberGroups(w http.ResponseWriter, r *http.Request, _ store.User) {
	ids, err := a.st.MemberGroupIDs(r.Context(), r.PathValue("id"), r.PathValue("userId"))
	if err != nil {
		a.internal(w, err)
		return
	}
	if ids == nil {
		ids = []string{}
	}
	writeJSON(w, http.StatusOK, ids)
}

func (a *API) putMemberGroups(w http.ResponseWriter, r *http.Request, actor store.User) {
	tenantID, userID := r.PathValue("id"), r.PathValue("userId")
	var ids []string
	if err := decodeStrict(r, &ids); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed group list: expected a JSON array of group ids")
		return
	}
	old, _ := a.st.MemberGroupIDs(r.Context(), tenantID, userID)
	if err := a.st.SetMemberGroups(r.Context(), tenantID, userID, ids); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	// Audit the assignment as a diff of group NAMES (ids mean nothing in a log).
	if !sameStringSet(old, ids) {
		name := userID
		if u, err := a.st.GetUserByID(r.Context(), userID); err == nil {
			name = u.Username
		}
		a.audit(r.Context(), store.AuditEvent{
			At: time.Now().Unix(), ActorID: actor.ID, Action: "member.groups", Target: "membership",
			TargetID: userID, TargetName: name, TenantID: tenantID,
			Changes: []store.FieldChange{{
				Field: "groups",
				From:  a.groupNames(r.Context(), old),
				To:    a.groupNames(r.Context(), ids),
			}},
		})
	}
	writeJSON(w, http.StatusOK, ids)
}

// groupNames resolves group ids to their names for a readable audit entry
// (unknown ids fall back to the raw id).
func (a *API) groupNames(ctx context.Context, ids []string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if g, err := a.st.GetGroup(ctx, id); err == nil {
			out = append(out, g.Name)
		} else {
			out = append(out, id)
		}
	}
	return out
}

// sameStringSet reports whether two id lists hold the same elements (order and
// duplicates ignored).
func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, s := range a {
		seen[s]++
	}
	for _, s := range b {
		seen[s]--
		if seen[s] < 0 {
			return false
		}
	}
	return true
}
