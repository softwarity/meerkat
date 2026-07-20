package admin

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRegisterConsoleProxiesEverythingButTheAPI(t *testing.T) {
	f := setup(t) // the standard fixture: API mounted, users, sessions

	devServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "dev-console:"+r.URL.Path)
	}))
	t.Cleanup(devServer.Close)

	mux := http.NewServeMux()
	f.api.Register(mux)
	if err := RegisterConsole(mux, devServer.URL); err != nil {
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
	if err := RegisterConsole(http.NewServeMux(), ""); err != nil {
		t.Fatalf("empty target must be a no-op, got %v", err)
	}
	if err := RegisterConsole(http.NewServeMux(), "not a url"); err == nil {
		t.Fatal("bad target accepted")
	}
}

func TestConsoleDevServerDownIs502(t *testing.T) {
	mux := http.NewServeMux()
	if err := RegisterConsole(mux, "http://127.0.0.1:1"); err != nil {
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
