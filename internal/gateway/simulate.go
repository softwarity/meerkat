package gateway

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/softwarity/meerkat/internal/store"
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
	"identity simulation requires a signed-in admin session (root, infra-admin, dev or tester) or a data session with the dev capability")

// simulationActor decides WHO may simulate: a privileged admin session (the
// console's swagger and test tools) or a data-plane session whose user holds
// the dev capability (the developer docs simulate on their own plane). via
// names the tool for the audit trail.
func (rt *Router) simulationActor(req *http.Request) (actor store.User, via string, ok bool) {
	if rt.AdminSessions != nil {
		if sess, err := rt.AdminSessions.Resolve(req.Context(), req); err == nil && sess.Pending == "" {
			if u, err := rt.st.GetUserByID(req.Context(), sess.UserID); err == nil && u.Enabled &&
				(u.Root || u.InfraAdmin || u.Dev || u.Tester) {
				return u, "console-swagger", true
			}
		}
	}
	if rt.sm != nil {
		if sess, err := rt.sm.Resolve(req.Context(), req); err == nil && sess.Pending == "" {
			if u, err := rt.st.GetUserByID(req.Context(), sess.UserID); err == nil && u.Enabled && u.Dev {
				return u, "dev-swagger", true
			}
		}
	}
	return store.User{}, "", false
}

type simKey struct{}

// simMeta records that THIS request is a simulated (test) call, not a genuine
// user action: who is really behind it and through which tool. It becomes a
// log line on the gateway and marker headers on the upstream request, so the
// backend's own action log can tell a swagger test from real traffic.
type simMeta struct {
	By  string // the real signed-in user driving the test ("" for a bare token)
	Via string // dev-swagger | console-swagger | test-token
}

type simMetaKey struct{}

func withSimMeta(ctx context.Context, m simMeta) context.Context {
	return context.WithValue(ctx, simMetaKey{}, m)
}

func simulationMeta(ctx context.Context) (simMeta, bool) {
	m, ok := ctx.Value(simMetaKey{}).(simMeta)
	return m, ok
}

// specReadKey marks an IN-PROCESS spec read (admin API docs): the caller was
// already verified root/infra-admin on the control plane, and reading a
// route's OpenAPI contract must not additionally require a data session —
// actual calls stay gated. Never set on a network request.
type specReadKey struct{}

// WithSpecRead marks ctx as an internal spec read that access gates let through.
func WithSpecRead(ctx context.Context) context.Context {
	return context.WithValue(ctx, specReadKey{}, true)
}

func isSpecRead(ctx context.Context) bool {
	ok, _ := ctx.Value(specReadKey{}).(bool)
	return ok
}

// simulatedIdentity returns the identity posed by validated simulate headers.
func simulatedIdentity(ctx context.Context) (identityData, bool) {
	d, ok := ctx.Value(simKey{}).(identityData)
	return d, ok
}

// applySimulation validates the simulate headers and stashes the simulated
// identity in the request context. Requests without the headers pass through
// untouched; requests with them and no privileged admin session are refused.
func (rt *Router) applySimulation(req *http.Request) (*http.Request, error) {
	// An ephemeral test token IS the authorization: minted by a privileged
	// admin, TTL-bounded, self-contained — no session needed alongside.
	if auth := req.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer "+SimTokenPrefix) {
		d, ok := rt.verifySimulationToken(strings.TrimPrefix(auth, "Bearer "))
		if !ok {
			return nil, errSimTokenInvalid
		}
		slog.Info("simulated request (swagger test)", "via", "test-token", "as", d.Username,
			"roles", d.Roles, "method", req.Method, "path", req.URL.Path)
		ctx := context.WithValue(req.Context(), simKey{}, d)
		ctx = withSimMeta(ctx, simMeta{Via: "test-token"})
		return req.WithContext(ctx), nil
	}
	user := strings.TrimSpace(req.Header.Get(SimulateUserHeader))
	rolesRaw := strings.TrimSpace(req.Header.Get(SimulateRolesHeader))
	if user == "" && rolesRaw == "" {
		return req, nil
	}
	actor, via, ok := rt.simulationActor(req)
	if !ok {
		return nil, errSimulationRefused
	}
	d := identityData{UserID: "simulated", Username: user, Fullname: "Simulated identity"}
	for role := range strings.SplitSeq(rolesRaw, ",") {
		if role = strings.TrimSpace(role); role != "" && schemeTokenOK.MatchString(role) {
			d.Roles = append(d.Roles, role)
		}
	}
	slog.Info("simulated request (swagger test)", "via", via, "by", actor.Username, "as", user,
		"roles", d.Roles, "method", req.Method, "path", req.URL.Path)
	ctx := context.WithValue(req.Context(), simKey{}, d)
	ctx = withSimMeta(ctx, simMeta{By: actor.Username, Via: via})
	return req.WithContext(ctx), nil
}

// ── Ephemeral test tokens ────────────────────────────────────────────────────
//
// The API screen mints a short-lived token carrying an arbitrary identity
// (user + roles), pasted into swagger's Authorize: the whole authorization
// travels IN the token, so Try it out works without cookies or sessions. The
// HMAC key is drawn per boot and never leaves the process — tokens die with
// it, which is exactly the lifespan a test artifact deserves.

// SimTokenPrefix marks an ephemeral test token in an Authorization header.
const SimTokenPrefix = "mksim_"

var errSimTokenInvalid = errors.New("invalid or expired test token — mint a fresh one on the API screen")

type simTokenClaims struct {
	User  string   `json:"u"`
	Roles []string `json:"r"`
	Exp   int64    `json:"e"`
}

// MintSimulationToken issues a test token for the given identity; the admin
// API gates WHO may call this (root, infra-admin, dev or tester).
func (rt *Router) MintSimulationToken(user string, roles []string, ttl time.Duration) (string, time.Time) {
	exp := time.Now().Add(ttl)
	payload, _ := json.Marshal(simTokenClaims{User: user, Roles: roles, Exp: exp.Unix()})
	mac := hmac.New(sha256.New, rt.simTokenKey)
	mac.Write(payload)
	return SimTokenPrefix + base64.RawURLEncoding.EncodeToString(payload) +
		"." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), exp
}

// verifySimulationToken authenticates a minted token and yields its identity.
func (rt *Router) verifySimulationToken(token string) (identityData, bool) {
	payloadB64, macB64, ok := strings.Cut(strings.TrimPrefix(token, SimTokenPrefix), ".")
	if !ok {
		return identityData{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return identityData{}, false
	}
	sig, err := base64.RawURLEncoding.DecodeString(macB64)
	if err != nil {
		return identityData{}, false
	}
	mac := hmac.New(sha256.New, rt.simTokenKey)
	mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return identityData{}, false
	}
	var claims simTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil || time.Now().Unix() > claims.Exp {
		return identityData{}, false
	}
	d := identityData{UserID: "simulated", Username: claims.User, Fullname: "Simulated identity"}
	for _, role := range claims.Roles {
		if role != "" && schemeTokenOK.MatchString(role) {
			d.Roles = append(d.Roles, role)
		}
	}
	return d, true
}
