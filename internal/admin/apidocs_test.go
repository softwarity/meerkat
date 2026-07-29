package admin

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func readAll(t *testing.T, res *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// noRedirect inspects redirects instead of following them (the fixture mounts
// no /login, so following would 404).
var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}}

func (f fixture) get(t *testing.T, path string, cookie *http.Cookie) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, f.adminSrv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	res, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = res.Body.Close() })
	return res
}

func TestAPIDocsPage(t *testing.T) {
	f := setup(t)

	// Anonymous browsers land on the login page, and come back after.
	res := f.get(t, "/apidocs/", nil)
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/login?next=%2Fapidocs%2F" {
		t.Fatalf("anonymous: %d %q, want 303 to /login?next=%%2Fapidocs%%2F",
			res.StatusCode, res.Header.Get("Location"))
	}

	// /apidocs canonicalizes to /apidocs/.
	if res := f.get(t, "/apidocs", f.rootC); res.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("/apidocs: %d, want 301", res.StatusCode)
	}

	// A signed-in user gets the shell (any console user: bob works too).
	res = f.get(t, "/apidocs/", f.plainC)
	body := readAll(t, res)
	if res.StatusCode != http.StatusOK || !strings.Contains(body, "swagger-ui-bundle.js") {
		t.Fatalf("page: %d, swagger bundle not referenced:\n%.200s", res.StatusCode, body)
	}
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type %q, want text/html", ct)
	}
}

func TestAPIDocsAssets(t *testing.T) {
	f := setup(t)
	for file, wantType := range map[string]string{
		"swagger-ui.css":       "text/css",
		"skin.css":             "text/css",
		"swagger-ui-bundle.js": "application/javascript",
	} {
		res := f.get(t, "/apidocs/assets/"+file, nil)
		if res.StatusCode != http.StatusOK || !strings.HasPrefix(res.Header.Get("Content-Type"), wantType) {
			t.Fatalf("%s: %d %q, want 200 %s", file, res.StatusCode, res.Header.Get("Content-Type"), wantType)
		}
	}
	if res := f.get(t, "/apidocs/assets/nope.js", nil); res.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown asset: %d, want 404", res.StatusCode)
	}
}

func TestAPIDocsAdminSpec(t *testing.T) {
	f := setup(t)
	if res := f.get(t, "/apidocs/specs/meerkat-admin.json", nil); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d, want 401", res.StatusCode)
	}
	res := f.get(t, "/apidocs/specs/meerkat-admin.json", f.plainC)
	var spec struct {
		OpenAPI string `json:"openapi"`
		Info    struct {
			Title   string `json:"title"`
			Version string `json:"version"`
		} `json:"info"`
		Paths map[string]any `json:"paths"`
	}
	if err := json.Unmarshal([]byte(readAll(t, res)), &spec); err != nil {
		t.Fatalf("spec is not JSON: %v", err)
	}
	if spec.Info.Title != "Meerkat Admin API" || !strings.HasPrefix(spec.OpenAPI, "3.") {
		t.Fatalf("unexpected spec header: %+v", spec.Info)
	}
	if len(spec.Paths) < 20 {
		t.Fatalf("suspiciously small spec: %d paths", len(spec.Paths))
	}
	if _, ok := spec.Paths["/api/routes/{id}"]; !ok {
		t.Fatal("spec must describe /api/routes/{id}")
	}
}

func TestAPIDocsSpecListAndRouteProxy(t *testing.T) {
	f := setup(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"openapi":"3.0.0","info":{"title":"petstore","version":"1"},"paths":{}}`)
		case "/echo-cookie":
			_, _ = fmt.Fprint(w, r.Header.Get("Cookie"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(upstream.Close)

	f.api.DataAddr = ":18082" // what main wires: the data plane's -addr

	// One route WITH a declared spec (public prefix /pets, stripped before the
	// upstream — the classic mapping), one without.
	withSpec := fmt.Sprintf(`{"name":"pets","order":1,"enabled":true,"upstream":%q,
		"predicates":[{"type":"path","args":{"patterns":["/pets/**"]}}],
		"filters":[{"type":"strip-prefix","args":{"parts":1}}],
		"api":{"openapiUrl":"/openapi.json"}}`, upstream.URL)
	if code, body := f.call(t, "PUT", "/api/routes/pets", withSpec, f.rootC); code != http.StatusOK {
		t.Fatalf("save pets: %d %s", code, body)
	}
	bare := fmt.Sprintf(`{"name":"bare","order":2,"enabled":true,"upstream":%q,
		"predicates":[{"type":"path","args":{"patterns":["/bare/**"]}}],"filters":[]}`, upstream.URL)
	if code, body := f.call(t, "PUT", "/api/routes/bare", bare, f.rootC); code != http.StatusOK {
		t.Fatalf("save bare: %d %s", code, body)
	}

	// The picker: root sees the admin spec plus the declaring route; a plain
	// user sees only the admin spec (the routing plane is not their business).
	var specs []specRef
	if err := json.Unmarshal([]byte(readAll(t, f.get(t, "/apidocs/specs.json", f.rootC))), &specs); err != nil {
		t.Fatal(err)
	}
	if len(specs) != 2 || specs[0].Name != "Meerkat Admin API" || specs[1].URL != "specs/route/pets" {
		t.Fatalf("root specs = %+v", specs)
	}
	specs = nil
	if err := json.Unmarshal([]byte(readAll(t, f.get(t, "/apidocs/specs.json", f.plainC))), &specs); err != nil {
		t.Fatal(err)
	}
	if len(specs) != 1 {
		t.Fatalf("plain specs = %+v, want the admin spec only", specs)
	}

	// The proxy hands the upstream's spec through, same origin — with its
	// server information REWRITTEN to the route's public base: the admin
	// hostname on the data plane's port, plus the /pets prefix the
	// strip-prefix filter reveals. Try it out crosses the gateway.
	res := f.get(t, "/apidocs/specs/route/pets", f.rootC)
	body := readAll(t, res)
	if res.StatusCode != http.StatusOK || !strings.Contains(body, `"petstore"`) {
		t.Fatalf("proxy: %d %.120s", res.StatusCode, body)
	}
	var spec struct {
		Servers []struct {
			URL string `json:"url"`
		} `json:"servers"`
	}
	if err := json.Unmarshal([]byte(body), &spec); err != nil {
		t.Fatal(err)
	}
	if len(spec.Servers) != 1 || spec.Servers[0].URL != "http://127.0.0.1:18082/pets" {
		t.Fatalf("servers = %+v, want the data plane + the route prefix", spec.Servers)
	}
	if res := f.get(t, "/apidocs/specs/route/pets", f.plainC); res.StatusCode != http.StatusForbidden {
		t.Fatalf("plain user on a route spec: %d, want 403", res.StatusCode)
	}

	// Try it out calls the data plane directly (its CORS for the admin origin
	// lives in internal/gateway) — and the gateway never forwards its own
	// session cookies to an upstream, the application's cookies pass.
	req, _ := http.NewRequest(http.MethodGet, f.appSrv.URL+"/pets/echo-cookie", nil)
	req.AddCookie(&http.Cookie{Name: "MEERKAT_SESSION", Value: "secret"})
	req.AddCookie(&http.Cookie{Name: "MEERKAT_ADMIN_SESSION", Value: "secret"})
	req.AddCookie(&http.Cookie{Name: "app", Value: "keep"})
	res, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = res.Body.Close() })
	if body := readAll(t, res); res.StatusCode != http.StatusOK || body != "app=keep" {
		t.Fatalf("upstream saw cookies %q (%d), want the app cookie alone", body, res.StatusCode)
	}
	if res := f.get(t, "/apidocs/specs/route/bare", f.rootC); res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("route without a spec: %d, want 422", res.StatusCode)
	}
	if res := f.get(t, "/apidocs/specs/route/ghost", f.rootC); res.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown route: %d, want 404", res.StatusCode)
	}
}
