package admin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/softwarity/meerkat/internal/openapi"
	"github.com/softwarity/meerkat/internal/routing"
	"github.com/softwarity/meerkat/internal/store"
)

// specClient fetches OpenAPI specs from upstreams server-side. The per-request
// context carries the real deadline; the client Timeout is a backstop.
var specClient = &http.Client{Timeout: 20 * time.Second}

// registerOpenAPI mounts the endpoint-security surface (RBAC-07): read the
// route's OpenAPI operations, and pose per-endpoint access rules. Routing plane
// (GATEWAY scope): root or infra-admin.
func (a *API) registerOpenAPI(mux *http.ServeMux) {
	mux.Handle("GET /api/routes/{id}/operations", a.gw(a.getRouteOperations))
	mux.Handle("PUT /api/routes/{id}/security", a.infraAdmin(a.putRouteSecurity))
}

// routeOperations is what the console consumes to draw the swagger-like editor:
// the API metadata, the flat operation list fetched live from the upstream, and
// the currently saved per-endpoint security to overlay onto it.
type routeOperations struct {
	Title   string `json:"title,omitempty"`
	Version string `json:"version,omitempty"`
	Format  string `json:"format"`
	// Access is the route's base security (the "whole route" default); Endpoints
	// override it per operation.
	Access     store.Access            `json:"access"`
	Operations []openapi.Operation     `json:"operations"`
	Security   *store.EndpointSecurity `json:"security,omitempty"`
}

// routeSecurityPayload is the endpoint-security screen's PUT body: the route's
// base Access plus the per-operation overrides.
type routeSecurityPayload struct {
	Access    store.Access           `json:"access"`
	Endpoints []store.EndpointPolicy `json:"endpoints"`
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
		Access: route.Access, Operations: spec.Operations, Security: securityOf(route),
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
	var payload routeSecurityPayload
	if err := decodeStrict(r, &payload); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed security: "+err.Error())
		return
	}
	sec := store.EndpointSecurity{Endpoints: payload.Endpoints}
	if err := sec.Validate(); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	before := routeSecurityPayload{Access: route.Access, Endpoints: endpointsOf(route)}

	// The whole-route default is the route's own Access; the endpoints override
	// it per operation (kept under API.Security, next to the swagger url).
	route.Access = payload.Access
	api := store.RouteAPI{}
	if route.API != nil {
		api = *route.API // keep openapiUrl and any future API options
	}
	if len(sec.Endpoints) == 0 {
		api.Security = nil
	} else {
		api.Security = &sec
	}
	route.API = &api

	// Compile the whole route (predicates, filters, endpoint security) before
	// persisting, so a bad policy is refused with the engine's precise error.
	if err := a.validateRoute(r.Context(), route); err != nil {
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
	after := routeSecurityPayload{Access: route.Access, Endpoints: sec.Endpoints}
	a.auditUpdate(r.Context(), actor, "route.security", "route", route.ID, route.Name, "", before, after)
	writeJSON(w, http.StatusOK, after)
}

// securityOf returns the route's endpoint security, or nil.
func securityOf(route store.Route) *store.EndpointSecurity {
	if route.API == nil {
		return nil
	}
	return route.API.Security
}

// endpointsOf returns a route's per-operation overrides, or nil.
func endpointsOf(route store.Route) []store.EndpointPolicy {
	if route.API == nil || route.API.Security == nil {
		return nil
	}
	return route.API.Security.Endpoints
}

// resolveSpecURL yields the absolute URL of a route's OpenAPI spec: an absolute
// openapiUrl is used as is; a relative one is resolved THE WAY THE ROUTE'S OWN
// TRAFFIC IS.
//
// That last part is the whole point. A route matching /fpl-svc/** with no
// strip-prefix hands the service paths that still start with /fpl-svc, so its
// spec sits at <upstream>/fpl-svc/openapi.json - resolving against the bare
// upstream asked for <upstream>/openapi.json and got a 404, with the admin
// left wondering which of the two ends was wrong. With a strip-prefix, the
// prefix is gone from what the service sees, and so it is from here.
func resolveSpecURL(route store.Route) (string, error) {
	if route.API == nil || strings.TrimSpace(route.API.OpenapiURL) == "" {
		return "", errors.New("this route declares no OpenAPI spec url")
	}
	s := strings.TrimSpace(route.API.OpenapiURL)
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		return s, nil
	}
	base := strings.TrimRight(route.Upstream, "/")
	if base == "" {
		return "", errors.New("a relative spec url needs the route to have an upstream")
	}
	return base + routeUpstreamPrefix(route) + "/" + strings.TrimLeft(s, "/"), nil
}

// routeUpstreamPrefix is the path prefix an upstream actually receives from
// this route: the literal head of its path predicate, minus whatever
// strip-prefix removes. "" when the route matches everything or strips it all.
func routeUpstreamPrefix(route store.Route) string {
	literal := ""
	for _, p := range route.Predicates {
		if p.Type != "path" {
			continue
		}
		pattern, ok := firstPattern(p.Args["patterns"])
		if !ok {
			continue
		}
		// Only the segments that are literally there: {id} and ** match many
		// things and name none of them.
		for _, seg := range strings.Split(strings.Trim(pattern, "/"), "/") {
			if seg == "" || seg == "**" || strings.HasPrefix(seg, "{") {
				break
			}
			literal += "/" + seg
		}
		break
	}
	if literal == "" {
		return ""
	}
	strip := 0
	for _, f := range route.Filters {
		if f.Type != "strip-prefix" {
			continue
		}
		switch n := f.Args["parts"].(type) {
		case float64:
			strip = int(n)
		case int:
			strip = n
		default:
			strip = 1
		}
	}
	if strip <= 0 {
		return literal
	}
	out := routing.StripSegments(literal, strip)
	if out == "/" {
		return ""
	}
	return out
}

// firstPattern reads the first entry of a path predicate's patterns argument,
// which crosses JSON as []any and Go as []string depending on where it comes
// from.
func firstPattern(v any) (string, bool) {
	switch list := v.(type) {
	case []string:
		if len(list) > 0 {
			return list[0], true
		}
	case []any:
		for _, item := range list {
			if s, ok := item.(string); ok {
				return s, true
			}
		}
	case string:
		return list, true
	}
	return "", false
}
