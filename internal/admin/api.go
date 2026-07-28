// Package admin is Meerkat's control plane: the API served on the dedicated
// admin port (CONSOLE-11), consumed by the console. It is strictly separated
// from the data plane — nothing here is ever routable from the application
// port.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/softwarity/meerkat/internal/gateway"
	"github.com/softwarity/meerkat/internal/mail"
	"github.com/softwarity/meerkat/internal/routing"
	"github.com/softwarity/meerkat/internal/session"
	"github.com/softwarity/meerkat/internal/store"
	"github.com/softwarity/meerkat/internal/vault"
)

// API serves the admin endpoints. Every endpoint requires a session whose
// user is root.
type API struct {
	// Mailer sends outbound e-mail through the STORED config; nil answers "not
	// configured". Wired by main, faked in tests.
	Mailer func(ctx context.Context, msg mail.Message) error
	// MailerWith sends through an EXPLICIT config — the relay test tries what is
	// on screen, not what is stored. Defaults to mail.Send; faked in tests.
	MailerWith func(ctx context.Context, cfg mail.Config, msg mail.Message) error

	// DataAddr is the data plane's listen address (main's -addr): the API-docs
	// page derives from it the origin Try it out must target, since the routes
	// answer there and not on this admin port. Empty keeps the admin hostname.
	DataAddr string

	st     *store.Store
	sm     *session.Manager
	router *gateway.Router
}

// New builds the admin API. router receives a hot reload after every
// mutation — saving IS applying.
func New(st *store.Store, sm *session.Manager, router *gateway.Router) *API {
	return &API{st: st, sm: sm, router: router}
}

// Register mounts the API on mux. The routing plane is GATEWAY scope
// (RBAC-05): root or the infra-admin capability.
func (a *API) Register(mux *http.ServeMux) {
	mux.Handle("GET /api/catalog", a.gw(a.catalog))
	mux.Handle("GET /api/routes", a.gw(a.listRoutes))
	mux.Handle("POST /api/routes/reorder", a.infraAdmin(a.reorderRoutes))
	mux.Handle("GET /api/routes/{id}", a.gw(a.getRoute))
	mux.Handle("PUT /api/routes/{id}", a.infraAdmin(a.putRoute))
	mux.Handle("DELETE /api/routes/{id}", a.infraAdmin(a.deleteRoute))
	a.registerOpenAPI(mux)
	a.registerSigning(mux)
	a.registerVault(mux)
	a.registerMailRelay(mux)
	a.registerIdentity(mux)
	a.registerThemes(mux)
	a.registerRBAC(mux)
	a.registerAdminTokens(mux)
	a.registerAPIDocs(mux)
	a.auditRegisterViewer(mux)
}

// gw adapts a plain handler to the infra-admin guard (the routing-plane
// handlers predate the userHandler signature and never need the actor).
func (a *API) gw(next http.HandlerFunc) http.Handler {
	return a.infraAdmin(func(w http.ResponseWriter, r *http.Request, _ store.User) { next(w, r) })
}

func (a *API) catalog(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, routing.Catalog())
}

func (a *API) listRoutes(w http.ResponseWriter, r *http.Request) {
	routes, err := a.st.ListRoutes(r.Context())
	if err != nil {
		a.internal(w, err)
		return
	}
	if routes == nil {
		routes = []store.Route{}
	}
	writeJSON(w, http.StatusOK, routes)
}

func (a *API) getRoute(w http.ResponseWriter, r *http.Request) {
	route, err := a.st.GetRoute(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "route not found")
		return
	}
	writeJSON(w, http.StatusOK, route)
}

// reorderRoutes persists a new route order (first-match-wins, so order matters)
// from a JSON array of route ids, then reloads the data-plane snapshot.
func (a *API) reorderRoutes(w http.ResponseWriter, r *http.Request, actor store.User) {
	var ids []string
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ids); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed order: expected a JSON array of route ids")
		return
	}
	if err := a.st.ReorderRoutes(r.Context(), ids); err != nil {
		a.internal(w, err)
		return
	}
	if err := a.router.Reload(r.Context()); err != nil {
		a.internal(w, fmt.Errorf("reordered, but reload failed: %w", err))
		return
	}
	a.auditEvent(r.Context(), actor, "route.reorder", "route", "", "", "", fmt.Sprintf("%d routes reordered", len(ids)))
	writeJSON(w, http.StatusOK, map[string]int{"reordered": len(ids)})
}

// putRoute upserts a route: the body is validated by COMPILING it — the
// exact same code path the engine uses — so an invalid route is refused with
// the engine's precise error and never persisted.
func (a *API) putRoute(w http.ResponseWriter, r *http.Request, actor store.User) {
	var route store.Route
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&route); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed route: "+err.Error())
		return
	}
	route.ID = r.PathValue("id")
	if strings.TrimSpace(route.Name) == "" {
		writeErr(w, http.StatusUnprocessableEntity, "route name is required")
		return
	}
	if len(route.Predicates) == 0 {
		writeErr(w, http.StatusUnprocessableEntity, "a route needs at least one predicate")
		return
	}
	if err := a.validateRoute(r.Context(), route); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	// The prior route (if any) so the audit tells a create from an update diff.
	old, hadRoute := store.Route{}, false
	if prev, err := a.st.GetRoute(r.Context(), route.ID); err == nil {
		old, hadRoute = prev, true
	}
	if err := a.st.SaveRoute(r.Context(), route); err != nil {
		a.internal(w, err)
		return
	}
	if err := a.router.Reload(r.Context()); err != nil {
		// This route is valid, so a reload failure means another stored route
		// is broken — surface it instead of pretending everything applied.
		a.internal(w, fmt.Errorf("saved, but reload failed: %w", err))
		return
	}
	if hadRoute {
		a.auditUpdate(r.Context(), actor, "route.update", "route", route.ID, route.Name, "", old, route)
	} else {
		a.auditEvent(r.Context(), actor, "route.create", "route", route.ID, route.Name, "", "")
	}
	writeJSON(w, http.StatusOK, route)
}

// validateRoute compiles the route the ENGINE will run: the stored route with
// its $name references expanded (VAULT-01). Validating the raw form would
// reject a perfectly good "upstream: $api-host"; validating the expansion also
// catches a typo in a reference at save time rather than at reload time.
func (a *API) validateRoute(ctx context.Context, route store.Route) error {
	values, err := a.st.VaultValues(ctx, vault.ScopeInfra)
	if err != nil {
		return fmt.Errorf("vault unavailable: %w", err)
	}
	expanded, missing, err := gateway.ExpandRoute(route, values)
	if err != nil {
		return err
	}
	if len(missing) > 0 {
		return fmt.Errorf("unknown vault entries: %s", strings.Join(missing, ", "))
	}
	return gateway.Validate(expanded)
}

func (a *API) deleteRoute(w http.ResponseWriter, r *http.Request, actor store.User) {
	id := r.PathValue("id")
	route, _ := a.st.GetRoute(r.Context(), id) // capture the name before deletion
	existed, err := a.st.DeleteRoute(r.Context(), id)
	if err != nil {
		a.internal(w, err)
		return
	}
	if !existed {
		writeErr(w, http.StatusNotFound, "route not found")
		return
	}
	if err := a.router.Reload(r.Context()); err != nil {
		a.internal(w, fmt.Errorf("deleted, but reload failed: %w", err))
		return
	}
	a.auditEvent(r.Context(), actor, "route.delete", "route", id, route.Name, "", "")
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) internal(w http.ResponseWriter, err error) {
	slog.Error("admin api error", "err", err)
	writeErr(w, http.StatusInternalServerError, "internal error")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil && !errors.Is(err, http.ErrHandlerTimeout) {
		slog.Error("admin api encode", "err", err)
	}
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
