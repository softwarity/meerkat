package admin

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/softwarity/meerkat/internal/store"
)

// registerIssues mounts the embedded issue tracker's management side
// (ISSUE-03): the console lists, reads, moves and comments the reports filed
// from the injected user-button panel on the data plane. The GET/PUT settings
// pair is the Others-screen switch that turns the whole feature on (ISSUE-04).
func (a *API) registerIssues(mux *http.ServeMux) {
	mux.Handle("GET /api/settings/issues", a.infraAdmin(a.getIssuesSetting))
	mux.Handle("PUT /api/settings/issues", a.infraAdmin(a.putIssuesSetting))
	mux.Handle("GET /api/issues", a.authed(a.listIssues))
	mux.Handle("GET /api/issues/{id}", a.authed(a.getIssue))
	mux.Handle("GET /api/issues/{id}/screenshot", a.authed(a.issueScreenshot))
	mux.Handle("PUT /api/issues/{id}/status", a.authed(a.putIssueStatus))
	mux.Handle("POST /api/issues/{id}/comments", a.authed(a.postIssueComment))
	mux.Handle("DELETE /api/issues/{id}", a.authed(a.deleteIssue))
}

// issuesSetting is the Others screen's payload: whether the issue tracker is
// enabled on the data plane.
type issuesSetting struct {
	Enabled bool `json:"enabled"`
}

func (a *API) issuesEnabledOn(r *http.Request) bool {
	var enabled bool
	_ = a.st.GetSetting(r.Context(), store.SettingIssuesEnabled, &enabled)
	return enabled
}

func (a *API) getIssuesSetting(w http.ResponseWriter, r *http.Request, _ store.User) {
	writeJSON(w, http.StatusOK, issuesSetting{Enabled: a.issuesEnabledOn(r)})
}

func (a *API) putIssuesSetting(w http.ResponseWriter, r *http.Request, actor store.User) {
	var body issuesSetting
	if err := decodeStrict(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed setting: "+err.Error())
		return
	}
	before := issuesSetting{Enabled: a.issuesEnabledOn(r)}
	if err := a.st.SetSetting(r.Context(), store.SettingIssuesEnabled, body.Enabled); err != nil {
		a.internal(w, err)
		return
	}
	a.auditUpdate(r.Context(), actor, "issues.expose", "settings", "", "", "", before, body)
	writeJSON(w, http.StatusOK, body)
}

// issueScope computes the actor's visibility window: nil = everything (root,
// infra-admin or app-admin - the application's administrators), otherwise the
// tenants they administer. ok is false when they administer nothing.
func (a *API) issueScope(r *http.Request, actor store.User) (ids []string, ok bool, err error) {
	if actor.Root || actor.InfraAdmin || actor.AppAdmin {
		return nil, true, nil
	}
	administered, err := a.st.ListTenantsAdministeredBy(r.Context(), actor.ID)
	if err != nil {
		return nil, false, err
	}
	for _, t := range administered {
		ids = append(ids, t.ID)
	}
	return ids, len(ids) > 0, nil
}

// issueInScope tells whether one report is visible inside a scope (nil = all).
func issueInScope(is store.Issue, scope []string) bool {
	if scope == nil {
		return true
	}
	for _, id := range scope {
		if is.TenantID == id {
			return true
		}
	}
	return false
}

// scopedIssue resolves {id} and enforces the actor's scope; a report outside
// it answers 404 - its existence is not revealed.
func (a *API) scopedIssue(w http.ResponseWriter, r *http.Request, actor store.User) (store.Issue, bool) {
	scope, ok, err := a.issueScope(r, actor)
	if err != nil {
		a.internal(w, err)
		return store.Issue{}, false
	}
	if !ok {
		writeErr(w, http.StatusForbidden,
			"issues require root, an infra/app-admin capability, or a tenant administration")
		return store.Issue{}, false
	}
	is, err := a.st.GetIssue(r.Context(), r.PathValue("id"))
	if err != nil || !issueInScope(is, scope) {
		writeErr(w, http.StatusNotFound, "unknown issue")
		return store.Issue{}, false
	}
	return is, true
}

func (a *API) listIssues(w http.ResponseWriter, r *http.Request, actor store.User) {
	scope, ok, err := a.issueScope(r, actor)
	if err != nil {
		a.internal(w, err)
		return
	}
	if !ok {
		writeErr(w, http.StatusForbidden,
			"issues require root, an infra/app-admin capability, or a tenant administration")
		return
	}
	f := store.IssueFilter{Status: r.URL.Query().Get("status"), TenantIDs: scope}
	if f.Status != "" && !store.ValidIssueStatus(f.Status) {
		writeErr(w, http.StatusUnprocessableEntity,
			"unknown status "+f.Status+": use open, in-progress or closed")
		return
	}
	issues, err := a.st.ListIssues(r.Context(), f)
	if err != nil {
		a.internal(w, err)
		return
	}
	if issues == nil {
		issues = []store.Issue{}
	}
	writeJSON(w, http.StatusOK, issues)
}

func (a *API) getIssue(w http.ResponseWriter, r *http.Request, actor store.User) {
	if is, ok := a.scopedIssue(w, r, actor); ok {
		writeJSON(w, http.StatusOK, is)
	}
}

// issueScreenshot serves the snapshot as a real image (decoded from its data
// URI): the console binds it straight into an img tag, cookies do the auth.
func (a *API) issueScreenshot(w http.ResponseWriter, r *http.Request, actor store.User) {
	is, ok := a.scopedIssue(w, r, actor)
	if !ok {
		return
	}
	uri, err := a.st.GetIssueScreenshot(r.Context(), is.ID)
	if err != nil {
		a.internal(w, err)
		return
	}
	meta, data, found := strings.Cut(uri, ";base64,")
	if !found {
		writeErr(w, http.StatusNotFound, "this issue carries no screenshot")
		return
	}
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		a.internal(w, err)
		return
	}
	w.Header().Set("Content-Type", strings.TrimPrefix(meta, "data:"))
	w.Header().Set("Cache-Control", "private, no-store")
	_, _ = w.Write(raw)
}

// issueLabel names a report in the audit trail: its description, shortened.
func issueLabel(is store.Issue) string {
	label := strings.Join(strings.Fields(is.Description), " ")
	if len(label) > 60 {
		label = label[:60]
	}
	return label
}

func (a *API) putIssueStatus(w http.ResponseWriter, r *http.Request, actor store.User) {
	is, ok := a.scopedIssue(w, r, actor)
	if !ok {
		return
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := decodeStrict(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed status: "+err.Error())
		return
	}
	if !store.ValidIssueStatus(body.Status) {
		writeErr(w, http.StatusUnprocessableEntity,
			"unknown status "+body.Status+": use open, in-progress or closed")
		return
	}
	if _, err := a.st.SetIssueStatus(r.Context(), is.ID, body.Status); err != nil {
		a.internal(w, err)
		return
	}
	a.auditUpdate(r.Context(), actor, "issue.status", "issue", is.ID, issueLabel(is), is.TenantID,
		map[string]string{"status": is.Status}, map[string]string{"status": body.Status})
	updated, err := a.st.GetIssue(r.Context(), is.ID)
	if err != nil {
		a.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (a *API) postIssueComment(w http.ResponseWriter, r *http.Request, actor store.User) {
	is, ok := a.scopedIssue(w, r, actor)
	if !ok {
		return
	}
	var body struct {
		Text string `json:"text"`
	}
	if err := decodeStrict(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed comment: "+err.Error())
		return
	}
	text := strings.TrimSpace(body.Text)
	if text == "" {
		writeErr(w, http.StatusUnprocessableEntity, "a comment needs some text")
		return
	}
	if len(text) > 2000 {
		writeErr(w, http.StatusUnprocessableEntity, "comment is too long: keep it under 2000 characters")
		return
	}
	if _, err := a.st.AddIssueComment(r.Context(), is.ID,
		store.IssueComment{AuthorID: actor.ID, Author: actor.Username, Text: text}); err != nil {
		a.internal(w, err)
		return
	}
	a.auditEvent(r.Context(), actor, "issue.comment", "issue", is.ID, issueLabel(is), is.TenantID, "comment added")
	updated, err := a.st.GetIssue(r.Context(), is.ID)
	if err != nil {
		a.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (a *API) deleteIssue(w http.ResponseWriter, r *http.Request, actor store.User) {
	is, ok := a.scopedIssue(w, r, actor)
	if !ok {
		return
	}
	if _, err := a.st.DeleteIssue(r.Context(), is.ID); err != nil {
		a.internal(w, err)
		return
	}
	a.auditEvent(r.Context(), actor, "issue.delete", "issue", is.ID, issueLabel(is), is.TenantID, "report deleted")
	w.WriteHeader(http.StatusNoContent)
}
