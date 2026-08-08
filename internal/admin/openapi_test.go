package admin

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/softwarity/meerkat/internal/routing"
	"github.com/softwarity/meerkat/internal/store"
)

const miniSpec = `{
  "openapi": "3.0.0",
  "info": {"title": "Orders", "version": "1"},
  "paths": {
    "/orders": {
      "get": {"operationId": "listOrders", "tags": ["orders"]},
      "post": {"operationId": "createOrder", "tags": ["orders"]}
    }
  }
}`

// The upstream serves its own OpenAPI spec at /spec.json and echoes every other
// path, so we can both read operations and see security enforced.
func specUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/spec.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, miniSpec)
			return
		}
		_, _ = io.WriteString(w, "up:"+r.URL.Path)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestRouteOperationsProjection(t *testing.T) {
	f := setup(t)
	up := specUpstream(t)
	route := fmt.Sprintf(`{
	  "name":"api","order":1,"enabled":true,"upstream":"%s",
	  "predicates":[{"type":"path","args":{"patterns":["/api/**"]}}],
	  "filters":[{"type":"strip-prefix","args":{"parts":1}}],
	  "api":{"openapiUrl":"%s/spec.json"}
	}`, up.URL, up.URL)
	if code, out := f.call(t, "PUT", "/api/routes/r1", route, f.rootC); code != http.StatusOK {
		t.Fatalf("put route: %d %s", code, out)
	}

	// Non-root cannot read the operations (routing plane is gateway scope).
	if code, _ := f.call(t, "GET", "/api/routes/r1/operations", "", f.plainC); code != http.StatusForbidden {
		t.Fatalf("operations authz: %d, want 403", code)
	}
	code, body := f.call(t, "GET", "/api/routes/r1/operations", "", f.rootC)
	if code != http.StatusOK {
		t.Fatalf("operations: %d %s", code, body)
	}
	if !strings.Contains(body, `"format":"3.0.0"`) ||
		!strings.Contains(body, `"path":"/orders"`) ||
		!strings.Contains(body, `"method":"GET"`) ||
		!strings.Contains(body, `"method":"POST"`) {
		t.Fatalf("projection incomplete: %s", body)
	}

	// A route without a spec url gets a clean 422, not a crash.
	plain := fmt.Sprintf(`{
	  "name":"plain","order":2,"enabled":true,"upstream":"%s",
	  "predicates":[{"type":"path","args":{"patterns":["/plain/**"]}}],
	  "filters":[{"type":"strip-prefix","args":{"parts":1}}]
	}`, up.URL)
	if code, out := f.call(t, "PUT", "/api/routes/r2", plain, f.rootC); code != http.StatusOK {
		t.Fatalf("put r2: %d %s", code, out)
	}
	if code, out := f.call(t, "GET", "/api/routes/r2/operations", "", f.rootC); code != http.StatusUnprocessableEntity {
		t.Fatalf("no-spec route: %d %s, want 422", code, out)
	}
}

func TestPutRouteSecurityEnforced(t *testing.T) {
	f := setup(t)
	up := specUpstream(t)
	route := fmt.Sprintf(`{
	  "name":"api","order":1,"enabled":true,"upstream":"%s",
	  "predicates":[{"type":"path","args":{"patterns":["/api/**"]}}],
	  "filters":[{"type":"strip-prefix","args":{"parts":1}}],
	  "api":{"openapiUrl":"%s/spec.json"}
	}`, up.URL, up.URL)
	if code, out := f.call(t, "PUT", "/api/routes/r1", route, f.rootC); code != http.StatusOK {
		t.Fatalf("put route: %d %s", code, out)
	}

	// The route-wide default locks the API; GET /orders is reopened to anonymous.
	sec := `{"access":{"level":"auth"},"endpoints":[{"method":"GET","path":"/orders"}]}`
	// Non-root cannot pose security.
	if code, _ := f.call(t, "PUT", "/api/routes/r1/security", sec, f.plainC); code != http.StatusForbidden {
		t.Fatalf("security authz: %d, want 403", code)
	}
	// A bad policy is refused with the engine's 422.
	bad := `{"endpoints":[{"method":"FOO","path":"/x"}]}`
	if code, out := f.call(t, "PUT", "/api/routes/r1/security", bad, f.rootC); code != http.StatusUnprocessableEntity {
		t.Fatalf("bad policy: %d %s, want 422", code, out)
	}
	// Root poses it: saving IS applying.
	if code, out := f.call(t, "PUT", "/api/routes/r1/security", sec, f.rootC); code != http.StatusOK {
		t.Fatalf("put security: %d %s", code, out)
	}

	// Enforced on the data plane: /api/orders -> /orders is public; anything
	// else is caught by the authenticated route default (anonymous -> 401).
	get := func(path string) int {
		res, err := http.Get(f.appSrv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		return res.StatusCode
	}
	if code := get("/api/orders"); code != http.StatusOK {
		t.Fatalf("public /api/orders: %d, want 200", code)
	}
	if code := get("/api/secret"); code != http.StatusUnauthorized {
		t.Fatalf("route-default /api/secret: %d, want 401", code)
	}

	// Clearing security reopens everything (route has no other gate).
	if code, _ := f.call(t, "PUT", "/api/routes/r1/security", `{}`, f.rootC); code != http.StatusOK {
		t.Fatal("clear security")
	}
	if code := get("/api/secret"); code != http.StatusOK {
		t.Fatalf("after clearing, /api/secret: %d, want 200", code)
	}
}

// A relative spec url is resolved the way the route's own traffic is. Against
// the bare upstream it asked for a path the service never serves, and the 404
// told nobody which end was wrong.
func TestRelativeSpecURLFollowsTheRoutesPath(t *testing.T) {
	route := func(strip bool) store.Route {
		r := store.Route{
			Upstream:   "http://fpl-svc:3000",
			Predicates: []routing.Spec{{Type: "path", Args: map[string]any{"patterns": []string{"/fpl-svc/**"}}}},
			API:        &store.RouteAPI{OpenapiURL: "openapi.json"},
		}
		if strip {
			r.Filters = []routing.Spec{{Type: "strip-prefix", Args: map[string]any{"parts": 1}}}
		}
		return r
	}

	for _, tc := range []struct {
		name string
		r    store.Route
		want string
	}{
		{"no strip: the service still sees the prefix", route(false), "http://fpl-svc:3000/fpl-svc/openapi.json"},
		{"strip-prefix: it does not", route(true), "http://fpl-svc:3000/openapi.json"},
		{"an absolute url is left alone", store.Route{
			Upstream:   "http://fpl-svc:3000",
			Predicates: []routing.Spec{{Type: "path", Args: map[string]any{"patterns": []string{"/fpl-svc/**"}}}},
			API:        &store.RouteAPI{OpenapiURL: "https://elsewhere.example/spec.json"},
		}, "https://elsewhere.example/spec.json"},
		{"a catch-all adds nothing", store.Route{
			Upstream:   "http://portal:9191",
			Predicates: []routing.Spec{{Type: "path", Args: map[string]any{"patterns": []string{"/**"}}}},
			API:        &store.RouteAPI{OpenapiURL: "/v3/api-docs"},
		}, "http://portal:9191/v3/api-docs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveSpecURL(tc.r)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
