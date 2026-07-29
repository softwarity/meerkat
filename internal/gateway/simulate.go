package gateway

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
)

// Identity simulation (Try it out): the API-docs page lets a privileged tester
// call a route AS an arbitrary user with arbitrary roles — no account, no
// session to prepare. The two headers are honored only when the request ALSO
// carries an admin session (the admin cookie rides along on a same-host
// deployment) whose user is root, infra-admin, dev or tester; anyone else gets
// an explicit 403. The simulated identity then replaces the data-plane session
// everywhere it counts — access gates, endpoint security (RBAC-07), page stamp,
// identity forwarding — so the route and the upstream behave exactly as they
// would for a real user shaped like that.
const (
	SimulateUserHeader  = "X-Meerkat-Simulate-User"
	SimulateRolesHeader = "X-Meerkat-Simulate-Roles"
)

var errSimulationRefused = errors.New(
	"identity simulation requires a signed-in admin session with the root, infra-admin, dev or tester capability")

type simKey struct{}

// simulatedIdentity returns the identity posed by validated simulate headers.
func simulatedIdentity(ctx context.Context) (identityData, bool) {
	d, ok := ctx.Value(simKey{}).(identityData)
	return d, ok
}

// applySimulation validates the simulate headers and stashes the simulated
// identity in the request context. Requests without the headers pass through
// untouched; requests with them and no privileged admin session are refused.
func (rt *Router) applySimulation(req *http.Request) (*http.Request, error) {
	user := strings.TrimSpace(req.Header.Get(SimulateUserHeader))
	rolesRaw := strings.TrimSpace(req.Header.Get(SimulateRolesHeader))
	if user == "" && rolesRaw == "" {
		return req, nil
	}
	if rt.AdminSessions == nil {
		return nil, errSimulationRefused
	}
	sess, err := rt.AdminSessions.Resolve(req.Context(), req)
	if err != nil || sess.Pending != "" {
		return nil, errSimulationRefused
	}
	actor, err := rt.st.GetUserByID(req.Context(), sess.UserID)
	maySimulate := actor.Root || actor.InfraAdmin || actor.Dev || actor.Tester
	if err != nil || !actor.Enabled || !maySimulate {
		return nil, errSimulationRefused
	}
	d := identityData{UserID: "simulated", Username: user, Fullname: "Simulated identity"}
	for role := range strings.SplitSeq(rolesRaw, ",") {
		if role = strings.TrimSpace(role); role != "" && schemeTokenOK.MatchString(role) {
			d.Roles = append(d.Roles, role)
		}
	}
	slog.Info("identity simulation", "by", actor.Username, "as", user, "roles", d.Roles,
		"method", req.Method, "path", req.URL.Path)
	return req.WithContext(context.WithValue(req.Context(), simKey{}, d)), nil
}
