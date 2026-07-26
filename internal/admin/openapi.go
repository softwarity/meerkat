package admin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/softwarity/meerkat/internal/gateway"
	"github.com/softwarity/meerkat/internal/openapi"
	"github.com/softwarity/meerkat/internal/store"
)

// specClient fetches OpenAPI specs from upstreams server-side. The per-request
// context carries the real deadline; the client Timeout is a backstop.
var specClient = &http.Client{Timeout: 20 * time.Second}

// registerOpenAPI mounts the endpoint-security surface (RBAC-07): read the
// route's OpenAPI operations, and pose per-endpoint access rules. Routing plane
// (GATEWAY scope): root or gateway-admin.
func (a *API) registerOpenAPI(mux *http.ServeMux) {
	mux.Handle("GET /api/routes/{id}/operations", a.gw(a.getRouteOperations))
	mux.Handle("PUT /api/routes/{id}/security", a.gatewayAdmin(a.putRouteSecurity))
}

// routeOperations is what the console consumes to draw the swagger-like editor:
// the API metadata, the flat operation list fetched live from the upstream, and
// the currently saved per-endpoint security to overlay onto it.
type routeOperations struct {
	Title      string                  `json:"title,omitempty"`
	Version    string                  `json:"version,omitempty"`
	Format     string                  `json:"format"`
	Operations []openapi.Operation     `json:"operations"`
	Security   *store.EndpointSecurity `json:"security,omitempty"`
}

// getRouteOperations fetches the route's OpenAPI spec, parses it (Swagger 2.0 or
// OpenAPI 3.x) and returns the operation projection plus the saved security.
func (a *API) getRouteOperations(w http.ResponseWriter, r *http.Request) {
	route, err := a.st.GetRoute(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "route not found")
		return
	}
	specURL, err := resolveSpecURL(route)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	spec, _, err := openapi.Fetch(ctx, specClient, specURL)
	if err != nil {
		// The upstream or its spec is the problem, not this request: 502.
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, routeOperations{
		Title: spec.Title, Version: spec.Version, Format: spec.Format,
		Operations: spec.Operations, Security: securityOf(route),
	})
}

// putRouteSecurity replaces the route's endpoint-security block, validating it
// through the same engine path the router uses, then reloading. An empty block
// (no endpoints, no deny-by-default) clears security entirely.
func (a *API) putRouteSecurity(w http.ResponseWriter, r *http.Request, actor store.User) {
	route, err := a.st.GetRoute(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "route not found")
		return
	}
	var sec store.EndpointSecurity
	if err := decodeStrict(r, &sec); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed security: "+err.Error())
		return
	}
	if err := sec.Validate(); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	oldSec := securityOf(route)

	api := store.RouteAPI{}
	if route.API != nil {
		api = *route.API // keep swaggerUrl and any future API options
	}
	if len(sec.Endpoints) == 0 && !sec.DenyByDefault {
		api.Security = nil
	} else {
		api.Security = &sec
	}
	route.API = &api

	// Compile the whole route (predicates, filters, endpoint security) before
	// persisting, so a bad policy is refused with the engine's precise error.
	if err := gateway.Validate(route); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err := a.st.SaveRoute(r.Context(), route); err != nil {
		a.internal(w, err)
		return
	}
	if err := a.router.Reload(r.Context()); err != nil {
		a.internal(w, fmt.Errorf("saved, but reload failed: %w", err))
		return
	}
	a.auditUpdate(r.Context(), actor, "route.security", "route", route.ID, route.Name, "",
		derefSecurity(oldSec), derefSecurity(api.Security))
	writeJSON(w, http.StatusOK, api.Security)
}

// securityOf returns the route's endpoint security, or nil.
func securityOf(route store.Route) *store.EndpointSecurity {
	if route.API == nil {
		return nil
	}
	return route.API.Security
}

// derefSecurity yields a value (never a nil pointer) so the audit diff sees the
// fields rather than "null vs object".
func derefSecurity(s *store.EndpointSecurity) store.EndpointSecurity {
	if s == nil {
		return store.EndpointSecurity{}
	}
	return *s
}

// resolveSpecURL yields the absolute URL of a route's OpenAPI spec: an absolute
// swaggerUrl is used as is; a relative one is resolved against the upstream.
func resolveSpecURL(route store.Route) (string, error) {
	if route.API == nil || strings.TrimSpace(route.API.SwaggerURL) == "" {
		return "", errors.New("this route declares no OpenAPI spec url")
	}
	s := strings.TrimSpace(route.API.SwaggerURL)
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		return s, nil
	}
	base := strings.TrimRight(route.Upstream, "/")
	if base == "" {
		return "", errors.New("a relative spec url needs the route to have an upstream")
	}
	return base + "/" + strings.TrimLeft(s, "/"), nil
}
