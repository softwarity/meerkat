package admin

import (
	"encoding/json"
	"io"
	"net/http"
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

// The console documents the CONTROL plane only: Meerkat's own API, always —
// the routes' specs are the data plane's developer docs business.
func TestAPIDocsConsoleIsMeerkatOnly(t *testing.T) {
	f := setup(t)
	var specs []specRef
	if err := json.Unmarshal([]byte(readAll(t, f.get(t, "/apidocs/specs.json", f.plainC))), &specs); err != nil {
		t.Fatal(err)
	}
	if len(specs) != 1 || specs[0].Name != "Meerkat Admin API" {
		t.Fatalf("console specs = %+v, want the Meerkat spec alone", specs)
	}
	// The retired surfaces stay retired.
	if res := f.get(t, "/apidocs/specs/route/anything", f.rootC); res.StatusCode != http.StatusNotFound {
		t.Fatalf("route specs on the console: %d, want 404", res.StatusCode)
	}
	if res := f.get(t, "/apidocs/try/x", f.rootC); res.StatusCode != http.StatusNotFound {
		t.Fatalf("tunnel on the console: %d, want 404", res.StatusCode)
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

// The Others switch governs the DATA-plane developer docs; here only its
// admin endpoint contract: infra scope, audited, readable back.
func TestAPIDocsSetting(t *testing.T) {
	f := setup(t)
	if code, body := f.call(t, "GET", "/api/settings/api-docs", "", f.rootC); code != http.StatusOK || !strings.Contains(body, `"exposed":false`) {
		t.Fatalf("default: %d %s, want exposed:false", code, body)
	}
	if code, _ := f.call(t, "PUT", "/api/settings/api-docs", `{"exposed":true}`, f.plainC); code != http.StatusForbidden {
		t.Fatalf("plain user flips the switch: %d, want 403", code)
	}
	if code, _ := f.call(t, "PUT", "/api/settings/api-docs", `{"exposed":true}`, f.rootC); code != http.StatusOK {
		t.Fatal("enable failed")
	}
	if code, body := f.call(t, "GET", "/api/settings/api-docs", "", f.rootC); code != http.StatusOK || !strings.Contains(body, `"exposed":true`) {
		t.Fatalf("after enable: %d %s", code, body)
	}
}

// Minting a test token: privileged capabilities only, bounded lifetime, and
// the token authenticates a data-plane call on its own (simulate_test.go
// proves the gate side; here the admin endpoint contract).
func TestAPIDocsMintTestToken(t *testing.T) {
	f := setup(t)
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
