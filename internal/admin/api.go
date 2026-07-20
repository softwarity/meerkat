// Package admin is Meerkat's control plane: the API served on the dedicated
// admin port (CONSOLE-11), consumed by the console. It is strictly separated
// from the data plane — nothing here is ever routable from the application
// port.
package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/softwarity/meerkat/internal/gateway"
	"github.com/softwarity/meerkat/internal/routing"
	"github.com/softwarity/meerkat/internal/session"
	"github.com/softwarity/meerkat/internal/store"
)

// API serves the admin endpoints. Every endpoint requires a session whose
// user is root.
type API struct {
	st     *store.Store
	sm     *session.Manager
	router *gateway.Router
}

// New builds the admin API. router receives a hot reload after every
// mutation — saving IS applying.
func New(st *store.Store, sm *session.Manager, router *gateway.Router) *API {
	return &API{st: st, sm: sm, router: router}
}

// Register mounts the API on mux.
func (a *API) Register(mux *http.ServeMux) {
	mux.Handle("GET /api/catalog", a.root(a.catalog))
	mux.Handle("GET /api/routes", a.root(a.listRoutes))
	mux.Handle("GET /api/routes/{id}", a.root(a.getRoute))
	mux.Handle("PUT /api/routes/{id}", a.root(a.putRoute))
	mux.Handle("DELETE /api/routes/{id}", a.root(a.deleteRoute))
}

// root gates a handler behind an authenticated root user.
func (a *API) root(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, err := a.sm.Resolve(r.Context(), r)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "authentication required")
			return
		}
		user, err := a.st.GetUserByID(r.Context(), sess.UserID)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if !user.Root {
			writeErr(w, http.StatusForbidden, "root privilege required")
			return
		}
		next(w, r)
	})
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

// putRoute upserts a route: the body is validated by COMPILING it — the
// exact same code path the engine uses — so an invalid route is refused with
// the engine's precise error and never persisted.
func (a *API) putRoute(w http.ResponseWriter, r *http.Request) {
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
	if err := gateway.Validate(route); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
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
	writeJSON(w, http.StatusOK, route)
}

func (a *API) deleteRoute(w http.ResponseWriter, r *http.Request) {
	existed, err := a.st.DeleteRoute(r.Context(), r.PathValue("id"))
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
