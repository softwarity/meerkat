package gateway

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// UI test mode (DEV-10): a developer browses a UI route AS a simulated
// identity, driven by the user-button's developer bar. The simulation is
// attached to the developer's REAL session and scoped to ONE route, with a
// TTL: every request that session sends through that route carries the
// simulated identity (simKey), so access gates, endpoint security, page
// stamps, identity forwarding and the X-Meerkat-Test upstream markers all
// behave as if that user browsed - the whole point is SEEING what a role
// sees (role-CSS). State is per process, like the ephemeral swagger tokens:
// a restart or the TTL simply ends the test.

// uiSimTTL bounds a forgotten test: past it the route serves normally again.
const uiSimTTL = time.Hour

type uiSimKey struct {
	session string // the dev session's token hash
	route   string
}

type uiSimEntry struct {
	user    string
	roles   []string
	by      string // the real developer, for the X-Meerkat-Test-By marker
	expires time.Time
}

// RegisterUISim mounts the developer-bar endpoints on the data-plane mux,
// next to the developer docs. Same double gate as those: the Others-screen
// switch exposes the surface, the dev capability authorizes the caller.
func (rt *Router) RegisterUISim(mux *http.ServeMux) {
	mux.HandleFunc("GET /meerkat/dev-sim", rt.uiSimState)
	mux.HandleFunc("POST /meerkat/dev-sim", rt.uiSimSet)
	mux.HandleFunc("DELETE /meerkat/dev-sim", rt.uiSimClear)
}

// uiSimGate resolves the calling developer, or answers the refusal. The
// switch off plays dead (404), a non-dev session gets an explicit 401.
func (rt *Router) uiSimGate(w http.ResponseWriter, r *http.Request) (sessionKey, username string, ok bool) {
	if !rt.devDocsOn(r.Context()) {
		http.NotFound(w, r)
		return "", "", false
	}
	sess, err := rt.sm.Resolve(r.Context(), r)
	if err != nil || sess.Pending != "" {
		uiSimErr(w, http.StatusUnauthorized, "sign in with a developer account to use the UI test mode")
		return "", "", false
	}
	u, err := rt.st.GetUserByID(r.Context(), sess.UserID)
	if err != nil || !u.Enabled || !u.Dev {
		uiSimErr(w, http.StatusUnauthorized, "the UI test mode requires the dev capability")
		return "", "", false
	}
	return sess.TokenHash, u.Username, true
}

func uiSimErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

type uiSimView struct {
	Active bool     `json:"active"`
	User   string   `json:"user,omitempty"`
	Roles  []string `json:"roles,omitempty"`
}

func writeUISim(w http.ResponseWriter, v uiSimView) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

// uiSimState answers the developer bar's load question: is THIS route
// simulated for MY session, and as whom?
func (rt *Router) uiSimState(w http.ResponseWriter, r *http.Request) {
	key, _, ok := rt.uiSimGate(w, r)
	if !ok {
		return
	}
	e, active := rt.uiSimFor(key, r.URL.Query().Get("route"))
	if !active {
		writeUISim(w, uiSimView{})
		return
	}
	writeUISim(w, uiSimView{Active: true, User: e.user, Roles: e.roles})
}

type uiSimRequest struct {
	Route string   `json:"route"`
	User  string   `json:"user"`
	Roles []string `json:"roles"`
}

// uiSimSet starts (or edits) the simulation for the caller's session on one
// route. The identity is validated the same way the swagger headers are.
func (rt *Router) uiSimSet(w http.ResponseWriter, r *http.Request) {
	key, by, ok := rt.uiSimGate(w, r)
	if !ok {
		return
	}
	var body uiSimRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil {
		uiSimErr(w, http.StatusBadRequest, "malformed request: "+err.Error())
		return
	}
	body.Route = strings.TrimSpace(body.Route)
	body.User = strings.TrimSpace(body.User)
	if body.Route == "" || !rt.routeLive(body.Route) {
		uiSimErr(w, http.StatusUnprocessableEntity, "route: name a route of the live snapshot")
		return
	}
	if body.User == "" {
		uiSimErr(w, http.StatusUnprocessableEntity, "user: a simulated username is required")
		return
	}
	e := uiSimEntry{user: body.User, by: by, expires: time.Now().Add(uiSimTTL)}
	for _, role := range body.Roles {
		if role = strings.TrimSpace(role); role != "" && schemeTokenOK.MatchString(role) {
			e.roles = append(e.roles, role)
		}
	}
	// Expanded AT SET TIME so the developer bar shows the implication: check
	// a parent role, reload, and its descendants come back checked.
	e.roles = rt.expandSimRoles(r.Context(), e.roles)
	rt.uiSimMu.Lock()
	if rt.uiSims == nil {
		rt.uiSims = map[uiSimKey]uiSimEntry{}
	}
	for k, old := range rt.uiSims { // sweep expired leftovers while we hold the lock
		if time.Now().After(old.expires) {
			delete(rt.uiSims, k)
		}
	}
	rt.uiSims[uiSimKey{session: key, route: body.Route}] = e
	rt.uiSimMu.Unlock()
	slog.Info("ui test mode on", "by", by, "route", body.Route, "as", e.user, "roles", e.roles)
	writeUISim(w, uiSimView{Active: true, User: e.user, Roles: e.roles})
}

// uiSimClear ends the simulation for the caller's session on one route.
func (rt *Router) uiSimClear(w http.ResponseWriter, r *http.Request) {
	key, by, ok := rt.uiSimGate(w, r)
	if !ok {
		return
	}
	route := r.URL.Query().Get("route")
	rt.uiSimMu.Lock()
	delete(rt.uiSims, uiSimKey{session: key, route: route})
	rt.uiSimMu.Unlock()
	slog.Info("ui test mode off", "by", by, "route", route)
	writeUISim(w, uiSimView{})
}

// routeLive reports whether the id is in the live snapshot (a disabled route
// is not - simulating it would silently do nothing).
func (rt *Router) routeLive(id string) bool {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	for i := range rt.routes {
		if rt.routes[i].id == id {
			return true
		}
	}
	return false
}

// uiSimFor looks the simulation up; expired entries answer false (the sweep
// happens on writes, reads just ignore leftovers).
func (rt *Router) uiSimFor(sessionKey, routeID string) (uiSimEntry, bool) {
	rt.uiSimMu.RLock()
	defer rt.uiSimMu.RUnlock()
	e, ok := rt.uiSims[uiSimKey{session: sessionKey, route: routeID}]
	if !ok || time.Now().After(e.expires) {
		return uiSimEntry{}, false
	}
	return e, true
}

// applyUISim stamps the simulated identity on a matched request when the
// caller's session runs a UI test on this route. Zero cost while no test
// runs; a header/token simulation (swagger) always wins over it.
func (rt *Router) applyUISim(req *http.Request, routeID string) *http.Request {
	rt.uiSimMu.RLock()
	empty := len(rt.uiSims) == 0
	rt.uiSimMu.RUnlock()
	if empty {
		return req
	}
	if _, ok := simulatedIdentity(req.Context()); ok {
		return req
	}
	sess, err := rt.sm.Resolve(req.Context(), req)
	if err != nil || sess.Pending != "" {
		return req
	}
	e, ok := rt.uiSimFor(sess.TokenHash, routeID)
	if !ok {
		return req
	}
	d := identityData{UserID: "simulated", Username: e.user, Fullname: "Simulated identity", Roles: e.roles}
	ctx := req.Context()
	ctx = withSimMeta(ctx, simMeta{By: e.by, Via: "ui-test", Route: routeID})
	return req.WithContext(withSimulatedIdentity(ctx, d))
}

// uiSimRefusalPage keeps the developer out of a lockout: when the SIMULATED
// identity is refused by an access gate, a bare 403 would also take the
// developer bar away - and with it the way out of the test. This small page
// says what happened and offers the exit.
func uiSimRefusalPage(w http.ResponseWriter, req *http.Request) {
	m, _ := simulationMeta(req.Context())
	d, _ := simulatedIdentity(req.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`<!doctype html><meta charset="utf-8"><title>UI test - refused</title>` +
		`<body style="font-family:system-ui;background:#1c1c22;color:#e8e8ee;display:grid;place-items:center;min-height:100vh;margin:0">` +
		`<div style="max-width:34em;padding:2em;border:3px solid #f59e0b;border-radius:12px">` +
		`<h1 style="font-size:1.2em;margin:0 0 .6em">Simulated identity refused</h1>` +
		`<p style="margin:0 0 1.2em;line-height:1.5">This route refuses "` + htmlEscape(d.Username) +
		`" (roles: ` + htmlEscape(strings.Join(d.Roles, ", ")) + `). That IS what such a user would ` +
		`experience here. Adjust the roles from the developer bar after exiting, or end the test.</p>` +
		`<button style="font:inherit;padding:.5em 1.2em;border-radius:8px;border:0;background:#f59e0b;color:#1c1c22;cursor:pointer" ` +
		`onclick="fetch('/meerkat/dev-sim?route=` + htmlEscape(m.Route) + `',{method:'DELETE'}).then(()=>location.reload())">` +
		`Exit UI test mode</button></div>`))
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
	return r.Replace(s)
}
