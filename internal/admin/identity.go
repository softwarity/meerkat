package admin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"golang.org/x/text/language"

	"github.com/softwarity/meerkat/internal/store"
)

// Identity endpoints (users, tenants, memberships, global settings).
//
// Authorization model: superpowers (root/dev/tester/tenantCreator) are global
// user flags; tenant administration is the OWNER/ADMIN membership on that
// tenant (TENANT-02). Every handler receives the resolved session user and
// enforces its own scope — the role-CSS gating in the console is comfort, the
// contract is here.

type userHandler func(w http.ResponseWriter, r *http.Request, actor store.User)

// authed resolves the session into a user and hands it to the handler.
func (a *API) authed(next userHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, err := a.sm.Resolve(r.Context(), r)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if sess.Pending != "" {
			// AUTH-05: the login flow is not complete — nothing else answers.
			writeErr(w, http.StatusUnauthorized, "login flow incomplete: finish the "+sess.Pending+" step first")
			return
		}
		actor, err := a.st.GetUserByID(r.Context(), sess.UserID)
		if err != nil || !actor.Enabled {
			writeErr(w, http.StatusUnauthorized, "authentication required")
			return
		}
		next(w, r, actor)
	})
}

// rootOnly restricts a handler to root users.
func (a *API) rootOnly(next userHandler) http.Handler {
	return a.authed(func(w http.ResponseWriter, r *http.Request, actor store.User) {
		if !actor.Root {
			writeErr(w, http.StatusForbidden, "root privilege required")
			return
		}
		next(w, r, actor)
	})
}

// infraAdmin restricts a handler to root or infra-admin users (RBAC-05):
// the routing plane — routes, catalog, reload, built-in pages.
func (a *API) infraAdmin(next userHandler) http.Handler {
	return a.authed(func(w http.ResponseWriter, r *http.Request, actor store.User) {
		if !actor.Root && !actor.InfraAdmin {
			writeErr(w, http.StatusForbidden, "infrastructure administration requires root or the infra-admin capability")
			return
		}
		next(w, r, actor)
	})
}

// appAdmin restricts a handler to root or app-admin users (RBAC-05): the
// application's identity — users, roles, global settings.
func (a *API) appAdmin(next userHandler) http.Handler {
	return a.authed(func(w http.ResponseWriter, r *http.Request, actor store.User) {
		if !actor.Root && !actor.AppAdmin {
			writeErr(w, http.StatusForbidden, "application administration requires root or the app-admin capability")
			return
		}
		next(w, r, actor)
	})
}

// tenantScoped restricts a handler to root, the tenant's OWNER (Tenant.OwnerID
// — ownership is decoupled from membership), or an ADMIN member of the tenant
// named by the {id} path value.
func (a *API) tenantScoped(next userHandler) http.Handler {
	return a.authed(func(w http.ResponseWriter, r *http.Request, actor store.User) {
		if actor.Root || a.administersTenant(r.Context(), actor.ID, r.PathValue("id")) {
			next(w, r, actor)
			return
		}
		writeErr(w, http.StatusForbidden, "tenant administration requires root, tenant ownership, or an ADMIN membership on this tenant")
	})
}

// administersTenant reports whether the user administers the tenant: its OWNER
// (owner_id, member or not) or an enabled ADMIN member. Root bypasses this.
func (a *API) administersTenant(ctx context.Context, userID, tenantID string) bool {
	if t, err := a.st.GetTenant(ctx, tenantID); err == nil && t.OwnerID == userID {
		return true
	}
	m, err := a.st.GetMembership(ctx, userID, tenantID)
	return err == nil && m.Enabled && m.Type == store.MemberAdmin
}

// registerIdentity mounts the identity endpoints on mux.
func (a *API) registerIdentity(mux *http.ServeMux) {
	mux.Handle("GET /api/me", a.authed(a.me))

	// Users are the APPLICATION's identity (RBAC-05): app-admin scope. Granting
	// or revoking root itself still requires root (privilege escalation guard).
	mux.Handle("GET /api/users", a.appAdmin(a.listUsers))
	mux.Handle("GET /api/users/lookup", a.authed(a.lookupUser))
	mux.Handle("POST /api/users", a.appAdmin(a.createUser))
	mux.Handle("PUT /api/users/{id}", a.appAdmin(a.updateUser))
	mux.Handle("POST /api/users/{id}/reset-password", a.appAdmin(a.resetPassword))
	mux.Handle("GET /api/users/{id}/logins", a.appAdmin(a.userLogins))
	mux.Handle("DELETE /api/users/{id}", a.appAdmin(a.deleteUser))

	mux.Handle("GET /api/tenants", a.authed(a.listTenants))
	mux.Handle("POST /api/tenants", a.authed(a.createTenant))
	mux.Handle("GET /api/tenants/{id}", a.tenantScoped(a.getTenant))
	mux.Handle("PUT /api/tenants/{id}", a.tenantScoped(a.updateTenant))
	mux.Handle("DELETE /api/tenants/{id}", a.tenantScoped(a.deleteTenant))
	mux.Handle("GET /api/tenants/{id}/members", a.tenantScoped(a.listMembers))
	mux.Handle("PUT /api/tenants/{id}/members/{userId}", a.tenantScoped(a.putMember))
	mux.Handle("DELETE /api/tenants/{id}/members/{userId}", a.tenantScoped(a.deleteMember))
	// Ownership transfer (TENANT-02): a tenant mutation, not a membership one —
	// tenantScoped lets ADMINs reach it, the handler narrows to root/owner.
	mux.Handle("POST /api/tenants/{id}/owner", a.tenantScoped(a.transferOwner))
	mux.Handle("POST /api/tenants/{id}/members/{userId}/reset-password", a.tenantScoped(a.resetMemberPassword))
	mux.Handle("GET /api/tenants/{id}/members/{userId}/logins", a.tenantScoped(a.memberLogins))

	mux.Handle("GET /api/settings", a.authed(a.getSettings))
	mux.Handle("PUT /api/settings", a.appAdmin(a.putSettings))
}

// ── me ───────────────────────────────────────────────────────────────────────

func (a *API) me(w http.ResponseWriter, r *http.Request, actor store.User) {
	tenants, err := a.st.ListUserTenants(r.Context(), actor.ID)
	if err != nil {
		a.internal(w, err)
		return
	}
	if tenants == nil {
		tenants = []store.UserTenant{}
	}
	// The session's active tenant (TENANT-03) — "" when none is selected.
	activeTenant := ""
	if sess, err := a.sm.Resolve(r.Context(), r); err == nil {
		activeTenant = sess.TenantID
	}
	// tenantAdmin drives the console's role-CSS: true when the user administers
	// at least one tenant — as its OWNER (even without a membership) or an ADMIN
	// member. Ownership is decoupled from membership, so the tenants list above
	// (memberships) is not enough to decide this.
	tenantAdmin := false
	if administered, err := a.st.ListTenantsAdministeredBy(r.Context(), actor.ID); err == nil {
		tenantAdmin = len(administered) > 0
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user": actor, "tenants": tenants, "activeTenant": activeTenant, "tenantAdmin": tenantAdmin,
	})
}

// ── users (root scope) ───────────────────────────────────────────────────────

func (a *API) listUsers(w http.ResponseWriter, r *http.Request, _ store.User) {
	users, err := a.st.ListUsers(r.Context())
	if err != nil {
		a.internal(w, err)
		return
	}
	if users == nil {
		users = []store.User{}
	}
	writeJSON(w, http.StatusOK, users)
}

func (a *API) createUser(w http.ResponseWriter, r *http.Request, actor store.User) {
	var u store.User
	if err := decodeStrict(r, &u); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed user: "+err.Error())
		return
	}
	u.Username = strings.TrimSpace(u.Username)
	if u.Username == "" {
		writeErr(w, http.StatusUnprocessableEntity, "username is required")
		return
	}
	// Privilege escalation guard (RBAC-05): an app-admin manages users but
	// never mints a root.
	if u.Root && !actor.Root {
		writeErr(w, http.StatusForbidden, "granting root requires root")
		return
	}
	u.ID = newID()
	// A generated one-time password, shown once in the response — the archway
	// pattern; temporary-password expiry arrives with the password policy.
	password, err := randomSecret()
	if err != nil {
		a.internal(w, err)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		a.internal(w, err)
		return
	}
	u.PasswordHash = string(hash)
	u.MustChangePassword = true // generated password → forced update at first login
	u.EmailVerified = true      // an admin answers for the address they type
	u.SelfRegistered = false
	if err := a.st.CreateUser(r.Context(), u); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	created, err := a.st.GetUserByID(r.Context(), u.ID)
	if err != nil {
		a.internal(w, err)
		return
	}
	a.auditEvent(r.Context(), actor, "user.create", "user", created.ID, created.Username, "", "")
	writeJSON(w, http.StatusCreated, map[string]any{"user": created, "password": password})
}

func (a *API) updateUser(w http.ResponseWriter, r *http.Request, actor store.User) {
	var u store.User
	if err := decodeStrict(r, &u); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed user: "+err.Error())
		return
	}
	u.ID = r.PathValue("id")
	current, err := a.st.GetUserByID(r.Context(), u.ID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	// Privilege escalation guard (RBAC-05): only root grants or revokes root.
	if u.Root != current.Root && !actor.Root {
		writeErr(w, http.StatusForbidden, "granting or revoking root requires root")
		return
	}
	// Self-lockout guard: whatever other roots exist, you never disable your
	// own account nor drop your own root — nothing proves you control the
	// other root account (learned the hard way).
	if u.ID == actor.ID && ((current.Enabled && !u.Enabled) || (current.Root && !u.Root)) {
		writeErr(w, http.StatusUnprocessableEntity, "refusing: you cannot disable your own account or drop your own root — have another root do it")
		return
	}
	// Lockout guard: the gateway must always keep one enabled root.
	losesRoot := current.Root && current.Enabled && (!u.Root || !u.Enabled)
	if losesRoot {
		if err := a.ensureAnotherRoot(r, current.ID); err != nil {
			writeErr(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
	}
	if err := a.st.UpdateUser(r.Context(), u); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	updated, err := a.st.GetUserByID(r.Context(), u.ID)
	if err != nil {
		a.internal(w, err)
		return
	}
	a.auditUpdate(r.Context(), actor, "user.update", "user", updated.ID, updated.Username, "", current, updated)
	writeJSON(w, http.StatusOK, updated)
}

func (a *API) resetPassword(w http.ResponseWriter, r *http.Request, actor store.User) {
	a.writeResetPassword(w, r, actor, r.PathValue("id"), "")
}

// resetMemberPassword lets a tenant's OWNER/ADMIN reset one of THEIR members'
// passwords without needing root. The target must be a member of the tenant,
// and resetting a root account still requires root (no privilege escalation
// through a tenant).
func (a *API) resetMemberPassword(w http.ResponseWriter, r *http.Request, actor store.User) {
	tenantID, userID := r.PathValue("id"), r.PathValue("userId")
	if _, err := a.st.GetMembership(r.Context(), userID, tenantID); err != nil {
		writeErr(w, http.StatusNotFound, "member not found")
		return
	}
	target, err := a.st.GetUserByID(r.Context(), userID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	if target.Root && !actor.Root {
		writeErr(w, http.StatusForbidden, "resetting a root account requires root")
		return
	}
	a.writeResetPassword(w, r, actor, userID, tenantID)
}

// userLogins returns a user's sign-in history (root scope) — same data the
// user sees on /profile/history, newest first.
func (a *API) userLogins(w http.ResponseWriter, r *http.Request, _ store.User) {
	if _, err := a.st.GetUserByID(r.Context(), r.PathValue("id")); err != nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	a.writeLogins(w, r, r.PathValue("id"))
}

// memberLogins is the tenant-scoped view of the same history: an OWNER/ADMIN
// of the tenant may consult the sign-ins of its members.
func (a *API) memberLogins(w http.ResponseWriter, r *http.Request, _ store.User) {
	tenantID, userID := r.PathValue("id"), r.PathValue("userId")
	if _, err := a.st.GetMembership(r.Context(), userID, tenantID); err != nil {
		writeErr(w, http.StatusNotFound, "member not found")
		return
	}
	a.writeLogins(w, r, userID)
}

func (a *API) writeLogins(w http.ResponseWriter, r *http.Request, userID string) {
	events, err := a.st.ListLoginEvents(r.Context(), userID)
	if err != nil {
		a.internal(w, err)
		return
	}
	if events == nil {
		events = []store.LoginEvent{}
	}
	writeJSON(w, http.StatusOK, events)
}

// writeResetPassword generates a temporary password, stores its hash with the
// must-change flag, returns it once, and records the reset (a security event —
// never the password itself). tenantID scopes a tenant-admin's member reset.
func (a *API) writeResetPassword(w http.ResponseWriter, r *http.Request, actor store.User, id, tenantID string) {
	password, err := randomSecret()
	if err != nil {
		a.internal(w, err)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		a.internal(w, err)
		return
	}
	if err := a.st.SetUserPassword(r.Context(), id, string(hash), true); err != nil {
		if errors.Is(err, store.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "user not found")
			return
		}
		a.internal(w, err)
		return
	}
	name := ""
	if u, err := a.st.GetUserByID(r.Context(), id); err == nil {
		name = u.Username
	}
	a.auditEvent(r.Context(), actor, "user.reset-password", "user", id, name, tenantID, "temporary password issued")
	writeJSON(w, http.StatusOK, map[string]string{"password": password})
}

func (a *API) deleteUser(w http.ResponseWriter, r *http.Request, actor store.User) {
	id := r.PathValue("id")
	target, err := a.st.GetUserByID(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	if target.Root && target.Enabled {
		if err := a.ensureAnotherRoot(r, id); err != nil {
			writeErr(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
	}
	if id == actor.ID {
		writeErr(w, http.StatusUnprocessableEntity, "you cannot delete your own account from here")
		return
	}
	existed, err := a.st.DeleteUser(r.Context(), id)
	if err != nil {
		a.internal(w, err)
		return
	}
	if !existed {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	a.auditEvent(r.Context(), actor, "user.delete", "user", id, target.Username, "", "")
	w.WriteHeader(http.StatusNoContent)
}

// ensureAnotherRoot fails when no OTHER enabled root would remain.
func (a *API) ensureAnotherRoot(r *http.Request, excludeID string) error {
	users, err := a.st.ListUsers(r.Context())
	if err != nil {
		return err
	}
	for _, u := range users {
		if u.ID != excludeID && u.Root && u.Enabled {
			return nil
		}
	}
	return fmt.Errorf("refusing: %q is the last enabled root — promote another root first", excludeID)
}

// lookupUser resolves a username to a minimal identity (never the flags, never
// anything sensitive) so a tenant admin can add an existing user as a member.
// Restricted to root or someone administering at least one tenant — a plain
// user cannot probe usernames.
func (a *API) lookupUser(w http.ResponseWriter, r *http.Request, actor store.User) {
	if !actor.Root {
		administered, err := a.st.ListTenantsAdministeredBy(r.Context(), actor.ID)
		if err != nil {
			a.internal(w, err)
			return
		}
		if len(administered) == 0 {
			writeErr(w, http.StatusForbidden, "user lookup requires root or a tenant OWNER/ADMIN membership")
			return
		}
	}
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	if username == "" {
		writeErr(w, http.StatusBadRequest, "username query parameter is required")
		return
	}
	u, err := a.st.GetUserByUsername(r.Context(), username)
	if err != nil || !u.Enabled {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": u.ID, "username": u.Username, "fullname": u.Fullname})
}

// ── tenants ──────────────────────────────────────────────────────────────────

func (a *API) listTenants(w http.ResponseWriter, r *http.Request, actor store.User) {
	var (
		tenants []store.Tenant
		err     error
	)
	if actor.Root {
		tenants, err = a.st.ListTenants(r.Context())
	} else {
		// A tenant admin sees exactly the tenants they administer.
		tenants, err = a.st.ListTenantsAdministeredBy(r.Context(), actor.ID)
	}
	if err != nil {
		a.internal(w, err)
		return
	}
	if tenants == nil {
		tenants = []store.Tenant{}
	}
	writeJSON(w, http.StatusOK, tenants)
}

func (a *API) createTenant(w http.ResponseWriter, r *http.Request, actor store.User) {
	if !actor.Root && !actor.TenantCreator {
		writeErr(w, http.StatusForbidden, "creating tenants requires root or the tenant-creator superpower")
		return
	}
	var t store.Tenant
	if err := decodeStrict(r, &t); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed tenant: "+err.Error())
		return
	}
	t.Name = strings.TrimSpace(t.Name)
	if t.Name == "" {
		writeErr(w, http.StatusUnprocessableEntity, "tenant name is required")
		return
	}
	if t.GroupMode != "" && t.GroupMode != store.GroupModeMultiple && t.GroupMode != store.GroupModeSingle {
		writeErr(w, http.StatusUnprocessableEntity,
			"group mode must be MULTIPLE, SINGLE, or empty (default cumulative)")
		return
	}
	t.ID = newID()
	t.CreatedBy = actor.ID // audit: stamped once, never changed
	// Every tenant has an owner from birth (the creator, root included) —
	// ownership is a tenant field now, so no tenant is ever ownerless.
	t.OwnerID = actor.ID
	// A tenant is born enabled — disabling is a later, deliberate act (PUT).
	t.Enabled = true
	if !t.BusinessAccess.Inherited && len(t.BusinessAccess.Days) == 0 {
		// No override provided → inherit the global setting.
		t.BusinessAccess = store.BusinessAccess{Inherited: true}
	}
	if err := a.st.SaveTenant(r.Context(), t); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	// A non-root creator also joins their tenant as an ADMIN member (they work
	// in it). Root owns it from the outside without becoming a member.
	if !actor.Root {
		if err := a.st.SaveMembership(r.Context(), store.Membership{
			UserID: actor.ID, TenantID: t.ID, Type: store.MemberAdmin, Enabled: true,
			BusinessAccess: store.BusinessAccess{Inherited: true},
		}); err != nil {
			a.internal(w, err)
			return
		}
	}
	created, err := a.st.GetTenant(r.Context(), t.ID)
	if err != nil {
		a.internal(w, err)
		return
	}
	a.auditEvent(r.Context(), actor, "tenant.create", "tenant", created.ID, created.Name, created.ID, "")
	writeJSON(w, http.StatusCreated, created)
}

func (a *API) getTenant(w http.ResponseWriter, r *http.Request, _ store.User) {
	t, err := a.st.GetTenant(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "tenant not found")
		return
	}
	// Enrich (display-only): the creator's username and the current owner's.
	if t.CreatedBy != "" {
		if u, err := a.st.GetUserByID(r.Context(), t.CreatedBy); err == nil {
			t.CreatedByName = u.Username
		}
	}
	if t.OwnerID != "" {
		if u, err := a.st.GetUserByID(r.Context(), t.OwnerID); err == nil {
			t.OwnerName = u.Username
		}
	}
	writeJSON(w, http.StatusOK, t)
}

func (a *API) updateTenant(w http.ResponseWriter, r *http.Request, actor store.User) {
	var t store.Tenant
	if err := decodeStrict(r, &t); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed tenant: "+err.Error())
		return
	}
	t.ID = r.PathValue("id")
	existing, err := a.st.GetTenant(r.Context(), t.ID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "tenant not found")
		return
	}
	// Ownership is NOT changed by the general update — it is transferred in the
	// Danger zone (POST .../owner). Carry the stored owner forward whatever the
	// payload says, so a round-trip cannot silently reassign it.
	t.OwnerID = existing.OwnerID
	t.Name = strings.TrimSpace(t.Name)
	if t.Name == "" {
		writeErr(w, http.StatusUnprocessableEntity, "tenant name is required")
		return
	}
	if t.GroupMode != "" && t.GroupMode != store.GroupModeMultiple && t.GroupMode != store.GroupModeSingle {
		writeErr(w, http.StatusUnprocessableEntity,
			"group mode must be MULTIPLE, SINGLE, or empty (default cumulative)")
		return
	}
	if err := a.st.SaveTenant(r.Context(), t); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	saved, err := a.st.GetTenant(r.Context(), t.ID)
	if err != nil {
		a.internal(w, err)
		return
	}
	// Audit the field-level diff (name, hours, group mode…) — not "tenant saved".
	a.auditUpdate(r.Context(), actor, "tenant.update", "tenant", saved.ID, saved.Name, saved.ID, existing, saved)
	writeJSON(w, http.StatusOK, saved)
}

func (a *API) deleteTenant(w http.ResponseWriter, r *http.Request, actor store.User) {
	id := r.PathValue("id")
	// Load it once: to check ownership (non-root) and to capture the name for
	// the audit trail before it is gone.
	t, err := a.st.GetTenant(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "tenant not found")
		return
	}
	// Destroying a tenant is for root or its owner — an ADMIN configures, the
	// owner (or root) disposes.
	if !actor.Root && t.OwnerID != actor.ID {
		writeErr(w, http.StatusForbidden, "deleting a tenant requires root or its owner")
		return
	}
	existed, err := a.st.DeleteTenant(r.Context(), id)
	if err != nil {
		a.internal(w, err)
		return
	}
	if !existed {
		writeErr(w, http.StatusNotFound, "tenant not found")
		return
	}
	a.auditEvent(r.Context(), actor, "tenant.delete", "tenant", id, t.Name, id, "")
	w.WriteHeader(http.StatusNoContent)
}

// ── members ──────────────────────────────────────────────────────────────────

func (a *API) listMembers(w http.ResponseWriter, r *http.Request, _ store.User) {
	members, err := a.st.ListMembers(r.Context(), r.PathValue("id"))
	if err != nil {
		a.internal(w, err)
		return
	}
	if members == nil {
		members = []store.Member{}
	}
	writeJSON(w, http.StatusOK, members)
}

func (a *API) putMember(w http.ResponseWriter, r *http.Request, actor store.User) {
	tenantID, userID := r.PathValue("id"), r.PathValue("userId")
	var m store.Membership
	if err := decodeStrict(r, &m); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed membership: "+err.Error())
		return
	}
	m.TenantID, m.UserID = tenantID, userID
	u, err := a.st.GetUserByID(r.Context(), userID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	// Capture the prior membership (if any) so the audit can tell a grant from a
	// change (USER ↔ ADMIN, enable/disable).
	old, hadMembership := store.Membership{}, false
	if prev, err := a.st.GetMembership(r.Context(), userID, tenantID); err == nil {
		old, hadMembership = prev, true
	}
	// Ownership is not a membership type — SaveMembership rejects OWNER (422).
	// Ownership is transferred through POST .../owner (TENANT-02).
	if err := a.st.SaveMembership(r.Context(), m); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	saved, err := a.st.GetMembership(r.Context(), userID, tenantID)
	if err != nil {
		a.internal(w, err)
		return
	}
	if hadMembership {
		a.auditUpdate(r.Context(), actor, "member.update", "membership", userID, u.Username, tenantID, old, saved)
	} else {
		a.auditEvent(r.Context(), actor, "member.add", "membership", userID, u.Username, tenantID, "type "+saved.Type)
	}
	writeJSON(w, http.StatusOK, saved)
}

// transferOwner reassigns the tenant's owner (TENANT-02). Reachable by tenant
// admins (tenantScoped), but only root or the CURRENT owner may actually
// transfer — an ADMIN cannot hand the tenant away. The new owner need not be a
// member; the previous owner keeps their membership (if any).
func (a *API) transferOwner(w http.ResponseWriter, r *http.Request, actor store.User) {
	tenantID := r.PathValue("id")
	var body struct {
		UserID string `json:"userId"`
	}
	if err := decodeStrict(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request: expected {\"userId\": \"...\"}")
		return
	}
	t, err := a.st.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "tenant not found")
		return
	}
	if !actor.Root && t.OwnerID != actor.ID {
		writeErr(w, http.StatusForbidden, "transferring ownership requires root or the current owner")
		return
	}
	if _, err := a.st.GetUserByID(r.Context(), body.UserID); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "new owner: user not found")
		return
	}
	// Capture the outgoing owner's name for the audit before reassigning.
	oldOwnerName := ""
	if u, err := a.st.GetUserByID(r.Context(), t.OwnerID); err == nil {
		oldOwnerName = u.Username
	}
	if _, err := a.st.SetTenantOwner(r.Context(), tenantID, body.UserID); err != nil {
		a.internal(w, err)
		return
	}
	saved, err := a.st.GetTenant(r.Context(), tenantID)
	if err != nil {
		a.internal(w, err)
		return
	}
	// Enrich the same display fields as getTenant so the console can drop the
	// fresh tenant straight into its scope (creator + owner names).
	if u, err := a.st.GetUserByID(r.Context(), saved.CreatedBy); err == nil {
		saved.CreatedByName = u.Username
	}
	if u, err := a.st.GetUserByID(r.Context(), saved.OwnerID); err == nil {
		saved.OwnerName = u.Username
	}
	a.audit(r.Context(), store.AuditEvent{
		At: time.Now().Unix(), ActorID: actor.ID, Action: "tenant.transfer-owner",
		Target: "tenant", TargetID: tenantID, TargetName: saved.Name, TenantID: tenantID,
		Changes: []store.FieldChange{{Field: "owner", From: oldOwnerName, To: saved.OwnerName}},
	})
	writeJSON(w, http.StatusOK, saved)
}

func (a *API) deleteMember(w http.ResponseWriter, r *http.Request, actor store.User) {
	tenantID, userID := r.PathValue("id"), r.PathValue("userId")
	if _, err := a.st.GetMembership(r.Context(), userID, tenantID); err != nil {
		writeErr(w, http.StatusNotFound, "membership not found")
		return
	}
	// Removing a membership never touches ownership (Tenant.OwnerID) — an owner
	// who was also a member simply becomes a non-member owner.
	if _, err := a.st.DeleteMembership(r.Context(), userID, tenantID); err != nil {
		a.internal(w, err)
		return
	}
	name := ""
	if u, err := a.st.GetUserByID(r.Context(), userID); err == nil {
		name = u.Username
	}
	a.auditEvent(r.Context(), actor, "member.remove", "membership", userID, name, tenantID, "")
	w.WriteHeader(http.StatusNoContent)
}

// ── global settings ──────────────────────────────────────────────────────────

// settingsPayload is the global level of the inheritable options — what tenant
// and membership overrides fall back to (TENANT-04/05). The "/" trap is NOT a
// setting: it is an ordinary catch-all route ordered last (ROUTE-10).
type settingsPayload struct {
	BusinessAccess   store.BusinessAccess       `json:"businessAccess"`
	SessionTTL       string                     `json:"sessionTTL"`
	MFARequired      bool                       `json:"mfaRequired"`      // gateway-wide second-factor policy (MFA-04)
	PasskeysAllowed  bool                       `json:"passkeysAllowed"`  // gateway-wide passkey policy (AUTH-15)
	APITokens        bool                       `json:"apiTokens"`        // personal API tokens allowed (AUTH-16)
	TrustedBrowser   store.TrustedBrowserPolicy `json:"trustedBrowser"`   // remember-this-browser policy (MFA-03)
	SMTP             smtpPayload                `json:"smtp"`             // outbound e-mail (AUTH-20)
	SelfRegistration bool                       `json:"selfRegistration"` // /register open (local accounts)
	// SelfRegisterCaptcha: the home-grown anti-robot check on /register
	// (default on whenever registration opens).
	SelfRegisterCaptcha bool `json:"selfRegisterCaptcha"`
	// RateLimit throttles the credential endpoints (SEC-10).
	RateLimit store.RateLimitPolicy `json:"rateLimit"`
	// Languages is the APPLICATION's locale pool (free BCP 47). The flow pages
	// speak its intersection with Meerkat's embedded languages (fallback en).
	Languages []string `json:"languages"`
}

// smtpPayload is the APPLICATION's side of outbound e-mail: the sender the
// recipient sees. The RELAY (host, credentials) is infrastructure and lives
// behind /api/settings/mail-relay — an app admin should not hold a third
// party's credentials to change a From address. The relay fields here are
// read-only context, so this page can say whether mail can go out at all.
type smtpPayload struct {
	From string `json:"from"`
	// Read-only mirrors of the relay, for context.
	RelayHost       string `json:"relayHost,omitempty"`
	RelayConfigured bool   `json:"relayConfigured"`
}

// loadSettingsPayload assembles the current global settings as the console sees
// them (SMTP password write-only). Shared by the GET handler and the audit's
// before-image on PUT.
func (a *API) loadSettingsPayload(ctx context.Context) (settingsPayload, error) {
	var p settingsPayload
	if err := a.st.GetSetting(ctx, store.SettingBusinessAccess, &p.BusinessAccess); err != nil {
		return p, err
	}
	if err := a.st.GetSetting(ctx, store.SettingSessionTTL, &p.SessionTTL); err != nil {
		return p, err
	}
	if err := a.st.GetSetting(ctx, store.SettingMFARequired, &p.MFARequired); err != nil {
		return p, err
	}
	tb, err := a.st.GetTrustedBrowserPolicy(ctx)
	if err != nil {
		return p, err
	}
	p.TrustedBrowser = tb
	p.PasskeysAllowed = a.st.PasskeysAllowed(ctx)
	p.APITokens = a.st.APITokensAllowed(ctx)
	// The application locale pool may legitimately be empty.
	_ = a.st.GetSetting(ctx, store.SettingLanguages, &p.Languages)
	smtp := a.st.GetSMTP(ctx)
	p.SMTP = smtpPayload{
		From: smtp.From, RelayHost: smtp.Host, RelayConfigured: smtp.Configured(),
	}
	reg := a.st.GetRegistrationPolicy(ctx)
	p.SelfRegistration = reg.LocalEnabled
	p.SelfRegisterCaptcha = !reg.CaptchaDisabled
	p.RateLimit = a.st.GetRateLimitPolicy(ctx)
	return p, nil
}

func (a *API) getSettings(w http.ResponseWriter, r *http.Request, _ store.User) {
	p, err := a.loadSettingsPayload(r.Context())
	if err != nil {
		a.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (a *API) putSettings(w http.ResponseWriter, r *http.Request, actor store.User) {
	// Snapshot the current settings for the audit before-image (best-effort).
	before, _ := a.loadSettingsPayload(r.Context())
	var p settingsPayload
	if err := decodeStrict(r, &p); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed settings: "+err.Error())
		return
	}
	// A trusted-browser TTL, when set, must be a valid ISO-8601 duration.
	if p.TrustedBrowser.TTL != "" {
		if _, err := store.ParseISODuration(p.TrustedBrowser.TTL); err != nil {
			writeErr(w, http.StatusUnprocessableEntity, "trusted-browser duration: "+err.Error())
			return
		}
	} else if p.TrustedBrowser.Allowed {
		writeErr(w, http.StatusUnprocessableEntity, "trusted-browser duration is required when trusted browsers are allowed")
		return
	}
	// The application locale pool: free BCP 47 tags (fr, fr-FR, pt-BR…),
	// canonicalized here. It may be empty. The flow pages will speak the
	// subset Meerkat embeds; the rest still feed the user button and the
	// upstream forwarding.
	for i, l := range p.Languages {
		tag, err := language.Parse(l)
		if err != nil {
			writeErr(w, http.StatusUnprocessableEntity,
				"language "+l+" is not a valid ISO code (like fr or fr-FR)")
			return
		}
		p.Languages[i] = tag.String()
	}
	if err := a.st.SetSetting(r.Context(), store.SettingBusinessAccess, p.BusinessAccess); err != nil {
		a.internal(w, err)
		return
	}
	if err := a.st.SetSetting(r.Context(), store.SettingSessionTTL, p.SessionTTL); err != nil {
		a.internal(w, err)
		return
	}
	if err := a.st.SetSetting(r.Context(), store.SettingMFARequired, p.MFARequired); err != nil {
		a.internal(w, err)
		return
	}
	if err := a.st.SetSetting(r.Context(), store.SettingTrustedBrowser, p.TrustedBrowser); err != nil {
		a.internal(w, err)
		return
	}
	if err := a.st.SetSetting(r.Context(), store.SettingPasskeys, p.PasskeysAllowed); err != nil {
		a.internal(w, err)
		return
	}
	if err := a.st.SetSetting(r.Context(), store.SettingAPITokens, p.APITokens); err != nil {
		a.internal(w, err)
		return
	}
	// Outbound e-mail (AUTH-20). An empty password keeps the stored one — the
	// console never sees or resends it.
	// Only the SENDER is this plane's to change: the relay is kept verbatim.
	smtp := a.st.GetSMTP(r.Context())
	smtp.From = strings.TrimSpace(p.SMTP.From)
	if p.SelfRegistration && !smtp.Configured() {
		writeErr(w, http.StatusUnprocessableEntity,
			"self-registration needs outbound e-mail: set a sender here, and ask an infra admin to configure the mail relay")
		return
	}
	if err := a.st.SetSetting(r.Context(), store.SettingSMTP, smtp); err != nil {
		a.internal(w, err)
		return
	}
	if err := a.st.SetSetting(r.Context(), store.SettingRegistration,
		store.RegistrationPolicy{LocalEnabled: p.SelfRegistration, CaptchaDisabled: !p.SelfRegisterCaptcha}); err != nil {
		a.internal(w, err)
		return
	}
	// Rate limiting (SEC-10): sane bounds; 0 attempts disables a limiter.
	if p.RateLimit.LoginAttempts < 0 || p.RateLimit.LoginAttempts > 1000 ||
		p.RateLimit.TotpAttempts < 0 || p.RateLimit.TotpAttempts > 100 {
		writeErr(w, http.StatusUnprocessableEntity, "rate limit attempts out of range (login 0-1000, totp 0-100; 0 disables)")
		return
	}
	if p.RateLimit.LoginWindow == "" {
		p.RateLimit.LoginWindow = "PT15M"
	}
	if _, err := store.ParseISODuration(p.RateLimit.LoginWindow); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "rate limit window: "+err.Error())
		return
	}
	if err := a.st.SetSetting(r.Context(), store.SettingRateLimit, p.RateLimit); err != nil {
		a.internal(w, err)
		return
	}
	p.SMTP = smtpPayload{From: smtp.From, RelayHost: smtp.Host, RelayConfigured: smtp.Configured()}
	if err := a.st.SetSetting(r.Context(), store.SettingLanguages, p.Languages); err != nil {
		a.internal(w, err)
		return
	}
	// The default route lives in the data plane's snapshot — apply on save.
	if err := a.router.Reload(r.Context()); err != nil {
		a.internal(w, fmt.Errorf("saved, but reload failed: %w", err))
		return
	}
	// Audit the changed knobs only (SMTP secrets redacted by the differ).
	a.auditUpdate(r.Context(), actor, "settings.update", "settings", "", "", "", before, p)
	writeJSON(w, http.StatusOK, p)
}

// ── helpers ──────────────────────────────────────────────────────────────────

func decodeStrict(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func newID() string {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		panic(fmt.Sprintf("admin: id entropy unavailable: %v", err))
	}
	return hex.EncodeToString(raw)
}

func randomSecret() (string, error) {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("admin: secret entropy unavailable: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
