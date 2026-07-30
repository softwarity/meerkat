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

// enableDocs flips the Others-screen switch on: the docs surface ships OFF.
func enableDocs(t *testing.T, f fixture) {
	t.Helper()
	if code, body := f.call(t, "PUT", "/api/settings/api-docs", `{"exposed":true}`, f.rootC); code != 200 {
		t.Fatalf("enable docs: %d %s", code, body)
	}
}

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

// The docs surface ships OFF: every path plays dead (404) until an infra
// admin flips the Others-screen switch — and only an infra admin may.
func TestAPIDocsShipOff(t *testing.T) {
	f := setup(t)
	for _, path := range []string{"/apidocs/", "/apidocs/specs.json",
		"/apidocs/specs/meerkat-admin.json", "/apidocs/try/x", "/apidocs/assets/skin.css"} {
		if res := f.get(t, path, f.rootC); res.StatusCode != http.StatusNotFound {
			t.Fatalf("%s while off: %d, want 404", path, res.StatusCode)
		}
	}
	if code, _ := f.call(t, "PUT", "/api/settings/api-docs", `{"exposed":true}`, f.plainC); code != http.StatusForbidden {
		t.Fatalf("plain user flips the switch: %d, want 403", code)
	}
	enableDocs(t, f)
	if res := f.get(t, "/apidocs/", f.rootC); res.StatusCode != http.StatusOK {
		t.Fatalf("after enabling: %d, want 200", res.StatusCode)
	}
	if code, _ := f.call(t, "PUT", "/api/settings/api-docs", `{"exposed":false}`, f.rootC); code != http.StatusOK {
		t.Fatal("disable failed")
	}
	if res := f.get(t, "/apidocs/", f.rootC); res.StatusCode != http.StatusNotFound {
		t.Fatalf("after disabling: %d, want 404 again", res.StatusCode)
	}
}

// Minting a test token: privileged capabilities only, bounded lifetime, and
// the token authenticates a data-plane call on its own (simulate_test.go
// proves the gate side; here the admin endpoint contract).
func TestAPIDocsMintTestToken(t *testing.T) {
	f := setup(t)
	enableDocs(t, f)
	code, body := f.call(t, "POST", "/api/apidocs/token",
		`{"username":"ghost","roles":["auditor"],"minutes":5}`, f.rootC)
	if code != http.StatusCreated || !strings.Contains(body, `"token":"mksim_`) {
		t.Fatalf("mint: %d %s", code, body)
	}
	if code, _ := f.call(t, "POST", "/api/apidocs/token",
		`{"username":"ghost","roles":[],"minutes":5}`, f.plainC); code != http.StatusForbidden {
		t.Fatalf("plain user mints: %d, want 403", code)
	}
	if code, _ := f.call(t, "POST", "/api/apidocs/token",
		`{"username":"","roles":[],"minutes":5}`, f.rootC); code != http.StatusUnprocessableEntity {
		t.Fatalf("empty username: %d, want 422", code)
	}
}

func TestAPIDocsPage(t *testing.T) {
	f := setup(t)
	enableDocs(t, f)

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
	enableDocs(t, f)
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
	enableDocs(t, f)
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
	enableDocs(t, f)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/openapi.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"openapi":"3.0.0","info":{"title":"petstore","version":"1"},"paths":{}}`)
		case strings.HasSuffix(r.URL.Path, "/echo-cookie"):
			_, _ = fmt.Fprint(w, r.Header.Get("Cookie"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(upstream.Close)

	// One route WITH a declared spec (public prefix /pets, stripped before the
	// upstream — the classic mapping), one without.
	// The route is access-gated: reading its spec must still work (the admin
	// was verified control-plane side), while calls stay gated.
	withSpec := fmt.Sprintf(`{"name":"pets","order":1,"enabled":true,"upstream":%q,
		"access":{"authenticated":true},
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
	// Same-origin tunnel: the page and its Try it out never leave this port.
	if len(spec.Servers) != 1 || spec.Servers[0].URL != "/apidocs/try/pets" {
		t.Fatalf("servers = %+v, want the same-origin tunnel + the route prefix", spec.Servers)
	}
	if res := f.get(t, "/apidocs/specs/route/pets", f.plainC); res.StatusCode != http.StatusForbidden {
		t.Fatalf("plain user on a route spec: %d, want 403", res.StatusCode)
	}

	// Try it out calls the data plane directly (its CORS for the admin origin
	// lives in internal/gateway) — and the gateway never forwards its own
	// session cookies to an upstream, the application's cookies pass. The
	// ungated route is used: the gated one refuses fake sessions, as it must.
	req, _ := http.NewRequest(http.MethodGet, f.appSrv.URL+"/bare/echo-cookie", nil)
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
