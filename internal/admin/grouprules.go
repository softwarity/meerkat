package admin

import (
	"net/http"
	"strings"

	"github.com/softwarity/meerkat/internal/features"
	"github.com/softwarity/meerkat/internal/store"
)

// Group rules (RBAC-10), scoped to the tenant that owns them. tenantScoped is
// the right guard for exactly the reason the rules are shaped this way: what a
// rule grants belongs to one organisation, so its administrator is the one who
// writes it. An infra admin configures the authority; they do not decide who
// it lets into whose organisation.

func (a *API) registerGroupRules(mux *http.ServeMux) {
	mux.Handle("GET /api/tenants/{id}/group-rules", a.tenantScoped(a.listGroupRules))
	mux.Handle("POST /api/tenants/{id}/group-rules", a.tenantScoped(a.createGroupRule))
	mux.Handle("PUT /api/tenants/{id}/group-rules/{ruleId}", a.tenantScoped(a.updateGroupRule))
	mux.Handle("DELETE /api/tenants/{id}/group-rules/{ruleId}", a.tenantScoped(a.deleteGroupRule))
	// What the authorities have actually been heard to say, so a rule is
	// picked from real names instead of retyped from memory.
	mux.Handle("GET /api/tenants/{id}/group-rules/reported", a.tenantScoped(a.reportedGroups))
}

// ruleView carries the names the console needs to render a rule as a sentence:
// an id says nothing to the person reading the table.
type ruleView struct {
	store.GroupRule
	ProviderName string `json:"providerName,omitempty"`
	GroupName    string `json:"groupName,omitempty"`
}

func (a *API) ruleViews(r *http.Request, rules []store.GroupRule) ([]ruleView, error) {
	ctx := r.Context()
	providers, err := a.st.ListAuthProviders(ctx)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]string, len(providers))
	for _, p := range providers {
		byID[p.ID] = p.Name
	}
	groups, err := a.st.ListGroups(ctx, r.PathValue("id"))
	if err != nil {
		return nil, err
	}
	groupName := make(map[string]string, len(groups))
	for _, g := range groups {
		groupName[g.ID] = g.Name
	}
	out := make([]ruleView, 0, len(rules))
	for _, rule := range rules {
		out = append(out, ruleView{
			GroupRule: rule, ProviderName: byID[rule.ProviderID], GroupName: groupName[rule.GroupID],
		})
	}
	return out, nil
}

func (a *API) listGroupRules(w http.ResponseWriter, r *http.Request, _ store.User) {
	rules, err := a.st.ListGroupRules(r.Context(), r.PathValue("id"))
	if err != nil {
		a.internal(w, err)
		return
	}
	views, err := a.ruleViews(r, rules)
	if err != nil {
		a.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, views)
}

// saveRule is the shared body of create and update: same validation, same
// answer, only the id differs.
func (a *API) saveRule(w http.ResponseWriter, r *http.Request, actor store.User, rule store.GroupRule, action string) {
	rule.TenantID = r.PathValue("id")
	rule.External = strings.TrimSpace(rule.External)
	rule.ProviderID = strings.TrimSpace(rule.ProviderID)
	// A group has to belong to THIS tenant. Without the check, a rule could
	// name another organisation's group by id and grant it from here.
	if rule.GroupID != "" {
		g, err := a.st.GetGroup(r.Context(), rule.GroupID)
		if err != nil || g.TenantID != rule.TenantID {
			writeErr(w, http.StatusUnprocessableEntity, "unknown group in this organization")
			return
		}
	}
	if rule.ProviderID != "" {
		if _, err := a.st.GetAuthProvider(r.Context(), rule.ProviderID); err != nil {
			writeErr(w, http.StatusUnprocessableEntity, "unknown authority "+rule.ProviderID)
			return
		}
	}
	if err := a.st.SaveGroupRule(r.Context(), rule); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	label := rule.External
	if label == "" {
		label = "everyone from " + rule.ProviderID
	}
	a.auditEvent(r.Context(), actor, action, "grouprule", rule.ID, label, rule.TenantID, "")
	// Answer with what was STORED, not with what was sent: the timestamp is
	// the server's, and a console echoing its own payload back would show a
	// rule created "at zero".
	stored, err := a.st.ListGroupRules(r.Context(), rule.TenantID)
	if err != nil {
		a.internal(w, err)
		return
	}
	for _, s := range stored {
		if s.ID == rule.ID {
			rule = s
			break
		}
	}
	views, err := a.ruleViews(r, []store.GroupRule{rule})
	if err != nil {
		a.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, views[0])
}

func (a *API) createGroupRule(w http.ResponseWriter, r *http.Request, actor store.User) {
	// A rule exists only to project what a DIRECTORY declares, so it belongs to
	// the same feature. Reading and applying existing rules is untouched: what
	// a licence gates is writing.
	if err := features.Require(features.Directories); err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	var rule store.GroupRule
	if err := decodeStrict(r, &rule); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed rule: "+err.Error())
		return
	}
	rule.ID = newID()
	a.saveRule(w, r, actor, rule, "grouprule.create")
}

func (a *API) updateGroupRule(w http.ResponseWriter, r *http.Request, actor store.User) {
	if err := features.Require(features.Directories); err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	var rule store.GroupRule
	if err := decodeStrict(r, &rule); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed rule: "+err.Error())
		return
	}
	rule.ID = r.PathValue("ruleId")
	existing, err := a.st.ListGroupRules(r.Context(), r.PathValue("id"))
	if err != nil {
		a.internal(w, err)
		return
	}
	found := false
	for _, e := range existing {
		if e.ID == rule.ID {
			found = true
			break
		}
	}
	if !found {
		writeErr(w, http.StatusNotFound, "rule not found in this organization")
		return
	}
	a.saveRule(w, r, actor, rule, "grouprule.update")
}

func (a *API) deleteGroupRule(w http.ResponseWriter, r *http.Request, actor store.User) {
	tenantID, id := r.PathValue("id"), r.PathValue("ruleId")
	ok, err := a.st.DeleteGroupRule(r.Context(), tenantID, id)
	if err != nil {
		a.internal(w, err)
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "rule not found in this organization")
		return
	}
	a.auditEvent(r.Context(), actor, "grouprule.delete", "grouprule", id, id, tenantID, "")
	w.WriteHeader(http.StatusNoContent)
}

// reportedGroups lists the group names the authorities have actually been
// heard to say, across everyone who has signed in. Writing a rule against a
// remembered name is how a mapping silently matches nothing:
// "cn=Developers,OU=Groups" and "cn=developers,ou=groups" look the same to a
// human and are two different strings here.
func (a *API) reportedGroups(w http.ResponseWriter, r *http.Request, _ store.User) {
	names, err := a.st.ReportedGroups(r.Context())
	if err != nil {
		a.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, names)
}
