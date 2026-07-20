package admin

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/softwarity/meerkat/internal/gateway"
	"github.com/softwarity/meerkat/internal/session"
	"github.com/softwarity/meerkat/internal/store"
)

type fixture struct {
	adminSrv *httptest.Server // the control plane
	appSrv   *httptest.Server // the data plane, reloaded by the API
	rootC    *http.Cookie
	plainC   *http.Cookie
}

func setup(t *testing.T) fixture {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	if err := st.CreateUser(ctx, store.User{ID: "root", Username: "root", PasswordHash: "x", Root: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUser(ctx, store.User{ID: "bob", Username: "bob", PasswordHash: "x"}); err != nil {
		t.Fatal(err)
	}
	sm := session.NewManager(st)
	router := gateway.New(st, sm)
	if err := router.Reload(ctx); err != nil {
		t.Fatal(err)
	}

	adminMux := http.NewServeMux()
	New(st, sm, router).Register(adminMux)

	f := fixture{
		adminSrv: httptest.NewServer(adminMux),
		appSrv:   httptest.NewServer(router),
		rootC:    issue(t, sm, "root"),
		plainC:   issue(t, sm, "bob"),
	}
	t.Cleanup(f.adminSrv.Close)
	t.Cleanup(f.appSrv.Close)
	return f
}

func issue(t *testing.T, sm *session.Manager, userID string) *http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	if _, err := sm.Issue(context.Background(), rec, httptest.NewRequest("POST", "/login", nil), userID); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return rec.Result().Cookies()[0]
}

func (f fixture) call(t *testing.T, method, path, body string, cookie *http.Cookie) (int, string) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, f.adminSrv.URL+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	return res.StatusCode, string(b)
}

const validRoute = `{
  "name": "api",
  "order": 1,
  "enabled": true,
  "upstream": "%s",
  "predicates": [{"type": "path", "args": {"patterns": ["/api/**"]}}],
  "filters": [{"type": "strip-prefix", "args": {"parts": 1}}]
}`

func TestAuthz(t *testing.T) {
	f := setup(t)
	if code, _ := f.call(t, "GET", "/api/routes", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d, want 401", code)
	}
	if code, _ := f.call(t, "GET", "/api/routes", "", f.plainC); code != http.StatusForbidden {
		t.Fatalf("non-root: %d, want 403", code)
	}
	if code, _ := f.call(t, "GET", "/api/routes", "", f.rootC); code != http.StatusOK {
		t.Fatalf("root: %d, want 200", code)
	}
}

func TestCatalogIsServed(t *testing.T) {
	f := setup(t)
	code, body := f.call(t, "GET", "/api/catalog", "", f.rootC)
	if code != http.StatusOK {
		t.Fatalf("catalog: %d", code)
	}
	var entries []map[string]any
	if err := json.Unmarshal([]byte(body), &entries); err != nil {
		t.Fatalf("catalog not JSON: %v", err)
	}
	kinds := map[string]bool{}
	types := map[string]bool{}
	for _, e := range entries {
		kinds[e["kind"].(string)] = true
		types[e["type"].(string)] = true
	}
	if !kinds["predicate"] || !kinds["filter"] || !types["path"] || !types["inject-head"] {
		t.Fatalf("catalog incomplete: %v", body)
	}
}

func TestPutRouteAppliesImmediately(t *testing.T) {
	f := setup(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello from "+r.URL.Path)
	}))
	t.Cleanup(upstream.Close)

	// Before: the data plane knows nothing.
	res, err := http.Get(f.appSrv.URL + "/api/x")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("before: %d", res.StatusCode)
	}

	body := strings.Replace(validRoute, "%s", upstream.URL, 1)
	code, out := f.call(t, "PUT", "/api/routes/r1", body, f.rootC)
	if code != http.StatusOK {
		t.Fatalf("put: %d %s", code, out)
	}

	// After: saving IS applying — no restart, no explicit reload call.
	res, err = http.Get(f.appSrv.URL + "/api/x")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK || string(got) != "hello from /x" {
		t.Fatalf("after: %d %q", res.StatusCode, got)
	}
}

func TestPutInvalidRouteIsRefusedWithEngineError(t *testing.T) {
	f := setup(t)
	bad := `{
	  "name": "broken", "enabled": true, "upstream": "http://up.invalid",
	  "predicates": [{"type": "path", "args": {"pattern": "/x"}}]
	}`
	code, body := f.call(t, "PUT", "/api/routes/r1", bad, f.rootC)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("code = %d, want 422 (%s)", code, body)
	}
	if !strings.Contains(body, `unknown arg \"pattern\"`) || !strings.Contains(body, "patterns") {
		t.Fatalf("error should carry the engine message: %s", body)
	}
	// Nothing was persisted.
	if _, routes := f.call(t, "GET", "/api/routes", "", f.rootC); routes != "[]\n" {
		t.Fatalf("invalid route persisted: %s", routes)
	}
}

func TestPutRejectsRouteWithoutPredicates(t *testing.T) {
	f := setup(t)
	code, body := f.call(t, "PUT", "/api/routes/r1",
		`{"name": "naked", "enabled": true, "upstream": "http://up.invalid", "predicates": []}`, f.rootC)
	if code != http.StatusUnprocessableEntity || !strings.Contains(body, "at least one predicate") {
		t.Fatalf("%d %s", code, body)
	}
}

func TestGetAndDeleteRoute(t *testing.T) {
	f := setup(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)

	body := strings.Replace(validRoute, "%s", upstream.URL, 1)
	if code, out := f.call(t, "PUT", "/api/routes/r1", body, f.rootC); code != http.StatusOK {
		t.Fatalf("put: %d %s", code, out)
	}
	code, out := f.call(t, "GET", "/api/routes/r1", "", f.rootC)
	if code != http.StatusOK || !strings.Contains(out, `"name":"api"`) {
		t.Fatalf("get: %d %s", code, out)
	}

	if code, _ := f.call(t, "DELETE", "/api/routes/r1", "", f.rootC); code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}
	if code, _ := f.call(t, "DELETE", "/api/routes/r1", "", f.rootC); code != http.StatusNotFound {
		t.Fatalf("re-delete: %d, want 404", code)
	}
	// The data plane dropped it too.
	res, err := http.Get(f.appSrv.URL + "/api/x")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("after delete: %d, want 404", res.StatusCode)
	}
}

func TestPutRejectsUnknownJSONFields(t *testing.T) {
	f := setup(t)
	code, body := f.call(t, "PUT", "/api/routes/r1",
		`{"name": "x", "upstrem": "typo"}`, f.rootC)
	if code != http.StatusBadRequest || !strings.Contains(body, "upstrem") {
		t.Fatalf("%d %s", code, body)
	}
}
