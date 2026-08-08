package gateway

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/softwarity/meerkat/internal/routing"
	"github.com/softwarity/meerkat/internal/store"
)

// The admin console's swagger page (Try it out) calls the data plane straight
// from the control plane's origin: that ONE sibling origin gets CORS, nothing
// else does - the applications behind the gateway keep their own policies.
func TestCORSForAdminConsoleOrigin(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "ok")
	}))
	t.Cleanup(upstream.Close)
	rt := newRouter(t, store.Route{
		ID: "r", Name: "r", Enabled: true, Upstream: upstream.URL,
		Predicates: []routing.Spec{{Type: "path", Args: map[string]any{"patterns": []any{"/**"}}}},
	})
	rt.AdminAddr = ":9092"
	srv := httptest.NewServer(rt)
	t.Cleanup(srv.Close)

	call := func(t *testing.T, method, origin, acrm string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+"/x", nil)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if acrm != "" {
			req.Header.Set("Access-Control-Request-Method", acrm)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = res.Body.Close() })
		return res
	}

	adminOrigin := "http://127.0.0.1:9092" // httptest binds 127.0.0.1: same hostname

	t.Run("preflight from the admin origin is answered by the gateway", func(t *testing.T) {
		res := call(t, http.MethodOptions, adminOrigin, "POST")
		if res.StatusCode != http.StatusNoContent {
			t.Fatalf("preflight: %d, want 204", res.StatusCode)
		}
		if res.Header.Get("Access-Control-Allow-Origin") != adminOrigin ||
			res.Header.Get("Access-Control-Allow-Credentials") != "true" {
			t.Fatalf("preflight headers = %v", res.Header)
		}
	})

	t.Run("actual request carries the CORS headers", func(t *testing.T) {
		res := call(t, http.MethodGet, adminOrigin, "")
		if res.StatusCode != http.StatusOK ||
			res.Header.Get("Access-Control-Allow-Origin") != adminOrigin {
			t.Fatalf("got %d, ACAO %q", res.StatusCode, res.Header.Get("Access-Control-Allow-Origin"))
		}
	})

	t.Run("any other origin gets nothing", func(t *testing.T) {
		for _, origin := range []string{
			"http://evil.test:9092", // right port, wrong hostname
			"http://127.0.0.1:4200", // right hostname, wrong port
		} {
			res := call(t, http.MethodGet, origin, "")
			if acao := res.Header.Get("Access-Control-Allow-Origin"); acao != "" {
				t.Fatalf("origin %s must get no CORS, got ACAO %q", origin, acao)
			}
		}
	})

	t.Run("without AdminAddr nothing changes", func(t *testing.T) {
		rt.AdminAddr = ""
		res := call(t, http.MethodGet, adminOrigin, "")
		if acao := res.Header.Get("Access-Control-Allow-Origin"); acao != "" {
			t.Fatalf("ACAO %q, want none", acao)
		}
		rt.AdminAddr = ":9092"
	})
}
