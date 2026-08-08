package admin

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestRegisterConsoleProxiesEverythingButTheAPI(t *testing.T) {
	f := setup(t) // the standard fixture: API mounted, users, sessions

	devServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "dev-console:"+r.URL.Path)
	}))
	t.Cleanup(devServer.Close)

	mux := http.NewServeMux()
	f.api.Register(mux)
	if err := RegisterConsole(mux, devServer.URL, nil, nil); err != nil {
		t.Fatalf("RegisterConsole: %v", err)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// The SPA (and any of its assets) is served through the gateway...
	res, err := http.Get(srv.URL + "/routes")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK || string(body) != "dev-console:/routes" {
		t.Fatalf("console not proxied: %d %q", res.StatusCode, body)
	}

	// ...while the API keeps its own behaviour (401 JSON for anonymous).
	res, err = http.Get(srv.URL + "/api/routes")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized || !strings.Contains(string(body), "authentication required") {
		t.Fatalf("API swallowed by console proxy: %d %q", res.StatusCode, body)
	}
}

func TestRegisterConsoleValidation(t *testing.T) {
	if err := RegisterConsole(http.NewServeMux(), "", nil, nil); err != nil {
		t.Fatalf("empty target must be a no-op, got %v", err)
	}
	if err := RegisterConsole(http.NewServeMux(), "not a url", nil, nil); err == nil {
		t.Fatal("bad target accepted")
	}
}

func TestEmbeddedConsoleServing(t *testing.T) {
	fsys := fstest.MapFS{
		"index.html":     {Data: []byte("<html>shell</html>")},
		"main-K7KMUD.js": {Data: []byte("js")},
	}
	// No store and no sessions: this test is about serving, and an unstamped
	// shell is exactly what an anonymous visitor gets.
	srv := httptest.NewServer(consoleHandler(fsys, nil, nil))
	t.Cleanup(srv.Close)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse // a redirect here would be a regression
	}}

	get := func(t *testing.T, path, acceptLanguage string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		if acceptLanguage != "" {
			req.Header.Set("Accept-Language", acceptLanguage)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = res.Body.Close() })
		return res
	}

	t.Run("build files are served immutable", func(t *testing.T) {
		res := get(t, "/main-K7KMUD.js", "")
		body, _ := io.ReadAll(res.Body)
		if res.StatusCode != http.StatusOK || string(body) != "js" {
			t.Fatalf("got %d %q", res.StatusCode, body)
		}
		if cc := res.Header.Get("Cache-Control"); !strings.Contains(cc, "immutable") {
			t.Fatalf("Cache-Control %q: hashed asset must be immutable", cc)
		}
	})

	t.Run("deep links fall back to the index", func(t *testing.T) {
		for _, path := range []string{"/", "/routes", "/routes/some/deep/link"} {
			res := get(t, path, "")
			body, _ := io.ReadAll(res.Body)
			if res.StatusCode != http.StatusOK || string(body) != "<html>shell</html>" {
				t.Errorf("%s: got %d %q", path, res.StatusCode, body)
			}
			if cc := res.Header.Get("Cache-Control"); cc != "no-cache" {
				t.Errorf("%s: Cache-Control %q, want no-cache (index must revalidate)", path, cc)
			}
		}
	})

	// The console is English-only, and no Accept-Language may resurrect a
	// locale segment: an operator who lands on /routes stays on /routes.
	t.Run("no language negotiation, ever", func(t *testing.T) {
		for _, header := range []string{"", "fr-FR,fr;q=0.9,en;q=0.8", "ar", "de-DE,de;q=0.9"} {
			res := get(t, "/routes", header)
			if res.StatusCode != http.StatusOK {
				t.Errorf("Accept-Language %q: got %d %q, want the shell served in place",
					header, res.StatusCode, res.Header.Get("Location"))
			}
		}
	})
}

func TestConsoleDevServerDownIs502(t *testing.T) {
	mux := http.NewServeMux()
	if err := RegisterConsole(mux, "http://127.0.0.1:1", nil, nil); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	res, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusBadGateway || !strings.Contains(string(body), "npm start") {
		t.Fatalf("%d %q", res.StatusCode, body)
	}
}

// The console HTML gets the signed-in identity stamped on <body> (roles as
// classes, data-meerkat-* attributes); anonymous navigations stay untouched.
func TestConsoleIdentityStamp(t *testing.T) {
	f := setup(t)
	devServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, "<!doctype html><html><head></head><body><app-root></app-root></body></html>")
	}))
	t.Cleanup(devServer.Close)

	mux := http.NewServeMux()
	f.api.Register(mux)
	if err := RegisterConsole(mux, devServer.URL, f.api.st, f.api.sm); err != nil {
		t.Fatalf("RegisterConsole: %v", err)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	get := func(cookie *http.Cookie) string {
		req, _ := http.NewRequest("GET", srv.URL+"/routes", nil)
		req.Header.Set("Accept", "text/html")
		if cookie != nil {
			req.AddCookie(cookie)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		return string(body)
	}

	// Checked piece by piece, not as one frozen string: the stamp also carries
	// what the installation IS, and pinning the whole tag would make every
	// added class look like a regression.
	body := get(f.rootC)
	for _, want := range []string{
		`class="root`,
		`data-meerkat-user-id="root"`,
		`data-meerkat-username="root"`,
		`data-meerkat-primary-tenant="default"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("stamp misses %s: %q", want, body)
		}
	}
	if body := get(nil); !strings.Contains(body, "<body>") {
		t.Fatalf("anonymous body must stay untouched: %q", body)
	}
}

// The EMBEDDED console gets the same stamp as the proxied one. It did not, and
// that made the whole mechanism a development-only thing: a release serves the
// embedded build, so it booted with a bare <body> and rebuilt the classes from
// /api/me afterwards - one paint too late for everything the stamp exists for.
func TestEmbeddedConsoleIsStampedToo(t *testing.T) {
	f := setup(t)

	fsys := fstest.MapFS{
		"index.html": &fstest.MapFile{
			Data: []byte("<!doctype html><html><head></head><body><app-root></app-root></body></html>"),
		},
	}
	mux := http.NewServeMux()
	f.api.Register(mux)
	mux.Handle("/", consoleHandler(fsys, f.api.st, f.api.sm))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	get := func(cookie *http.Cookie) string {
		t.Helper()
		req, _ := http.NewRequest("GET", srv.URL+"/", nil)
		req.Header.Set("Accept", "text/html")
		if cookie != nil {
			req.AddCookie(cookie)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		return string(body)
	}

	body := get(f.rootC)
	for _, want := range []string{`class="root`, `data-meerkat-username="root"`, `data-meerkat-primary-tenant="`} {
		if !strings.Contains(body, want) {
			t.Fatalf("embedded console not stamped (%s): %q", want, body)
		}
	}
	// Anonymous stays untouched: there is nothing to say about them, and the
	// shell has to be servable before anyone signs in.
	if anon := get(nil); !strings.Contains(anon, "<body>") {
		t.Fatalf("anonymous body must stay untouched: %q", anon)
	}
}
