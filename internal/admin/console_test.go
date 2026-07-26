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
		"en/index.html":     {Data: []byte("<html>en shell</html>")},
		"en/main-K7KMUD.js": {Data: []byte("js-en")},
		"fr/index.html":     {Data: []byte("<html>fr shell</html>")},
	}
	srv := httptest.NewServer(consoleHandler(fsys, []string{"en", "fr"}))
	t.Cleanup(srv.Close)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse // inspect redirects, don't follow them
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

	t.Run("root redirects to the Accept-Language locale", func(t *testing.T) {
		for header, want := range map[string]string{
			"":                        "/en/", // no preference → first locale
			"fr-FR,fr;q=0.9,en;q=0.8": "/fr/",
			"de-DE,de;q=0.9":          "/en/", // unknown language → first locale
			"da, fr;q=0.8, en;q=0.7":  "/fr/", // first known primary subtag wins
		} {
			res := get(t, "/", header)
			if res.StatusCode != http.StatusFound || res.Header.Get("Location") != want {
				t.Errorf("Accept-Language %q: got %d %q, want 302 %q",
					header, res.StatusCode, res.Header.Get("Location"), want)
			}
		}
	})

	t.Run("path outside a locale keeps its tail", func(t *testing.T) {
		res := get(t, "/routes", "fr")
		if res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/fr/routes" {
			t.Fatalf("got %d %q", res.StatusCode, res.Header.Get("Location"))
		}
	})

	t.Run("build files are served immutable", func(t *testing.T) {
		res := get(t, "/en/main-K7KMUD.js", "")
		body, _ := io.ReadAll(res.Body)
		if res.StatusCode != http.StatusOK || string(body) != "js-en" {
			t.Fatalf("got %d %q", res.StatusCode, body)
		}
		if cc := res.Header.Get("Cache-Control"); !strings.Contains(cc, "immutable") {
			t.Fatalf("Cache-Control %q: hashed asset must be immutable", cc)
		}
	})

	t.Run("deep links fall back to the locale index", func(t *testing.T) {
		for _, path := range []string{"/en/", "/en/routes", "/en/routes/some/deep/link"} {
			res := get(t, path, "")
			body, _ := io.ReadAll(res.Body)
			if res.StatusCode != http.StatusOK || string(body) != "<html>en shell</html>" {
				t.Errorf("%s: got %d %q", path, res.StatusCode, body)
			}
			if cc := res.Header.Get("Cache-Control"); cc != "no-cache" {
				t.Errorf("%s: Cache-Control %q, want no-cache (index must revalidate)", path, cc)
			}
		}
		res := get(t, "/fr/routes", "")
		body, _ := io.ReadAll(res.Body)
		if res.StatusCode != http.StatusOK || string(body) != "<html>fr shell</html>" {
			t.Fatalf("locales must not leak into each other: got %d %q", res.StatusCode, body)
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

	if body := get(f.rootC); !strings.Contains(body, `<body class="root" data-meerkat-user-id="root" data-meerkat-username="root">`) {
		t.Fatalf("root identity not stamped: %q", body)
	}
	if body := get(nil); !strings.Contains(body, "<body>") {
		t.Fatalf("anonymous body must stay untouched: %q", body)
	}
}
