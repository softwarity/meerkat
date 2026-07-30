package gateway

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/softwarity/meerkat/internal/routing"
	"github.com/softwarity/meerkat/internal/session"
	"github.com/softwarity/meerkat/internal/store"
)

// Identity simulation: a privileged admin session may try a route AS an
// arbitrary user with arbitrary roles; the access gate evaluates the simulated
// identity, and the upstream sees neither the knobs nor the gateway cookies.
func TestIdentitySimulation(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "sim=%s|cookie=%s",
			r.Header.Get(SimulateUserHeader)+r.Header.Get(SimulateRolesHeader), r.Header.Get("Cookie"))
	}))
	t.Cleanup(upstream.Close)

	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	for _, u := range []store.User{
		{ID: "tess", Username: "tess", PasswordHash: "x", Enabled: true, Tester: true},
		{ID: "bob", Username: "bob", PasswordHash: "x", Enabled: true},
	} {
		if err := st.CreateUser(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.SaveRoute(ctx, store.Route{
		ID: "r", Name: "r", Enabled: true, Upstream: upstream.URL,
		Access:     store.Access{Roles: []string{"auditor"}},
		Predicates: []routing.Spec{{Type: "path", Args: map[string]any{"patterns": []any{"/**"}}}},
	}); err != nil {
		t.Fatal(err)
	}
	rt := New(st, session.NewManager(st))
	adminSM := session.NewManager(st, session.ForAdminPlane())
	rt.AdminSessions = adminSM
	if err := rt.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(rt)
	t.Cleanup(srv.Close)

	call := func(t *testing.T, cookie *http.Cookie, user, roles string) (*http.Response, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/x", nil)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		if user != "" {
			req.Header.Set(SimulateUserHeader, user)
		}
		if roles != "" {
			req.Header.Set(SimulateRolesHeader, roles)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = res.Body.Close() })
		return res, readBody(t, res)
	}

	tessC := issueSession(t, adminSM, "tess")
	bobC := issueSession(t, adminSM, "bob")

	t.Run("no session, no simulation: the access gate turns the call away", func(t *testing.T) {
		if res, _ := call(t, nil, "", ""); res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("got %d, want 401", res.StatusCode)
		}
	})

	t.Run("simulation without an admin session is an explicit 403", func(t *testing.T) {
		if res, _ := call(t, nil, "ghost", "auditor"); res.StatusCode != http.StatusForbidden {
			t.Fatalf("got %d, want 403", res.StatusCode)
		}
	})

	t.Run("a plain admin session may not simulate", func(t *testing.T) {
		if res, _ := call(t, bobC, "ghost", "auditor"); res.StatusCode != http.StatusForbidden {
			t.Fatalf("got %d, want 403", res.StatusCode)
		}
	})

	t.Run("a tester simulates and the route grants the simulated role", func(t *testing.T) {
		res, body := call(t, tessC, "ghost", "auditor")
		if res.StatusCode != http.StatusOK {
			t.Fatalf("got %d: %s", res.StatusCode, body)
		}
		// The upstream sees neither the simulation knobs nor gateway cookies.
		if body != "sim=|cookie=" {
			t.Fatalf("upstream saw internals: %q", body)
		}
	})

	t.Run("the simulated roles are what the gate evaluates", func(t *testing.T) {
		if res, _ := call(t, tessC, "ghost", "intern"); res.StatusCode != http.StatusForbidden {
			t.Fatalf("got %d, want 403 (intern is not auditor)", res.StatusCode)
		}
	})

	// Ephemeral test tokens: the token IS the authorization — no cookie, no
	// session — and the upstream never sees it.
	bearer := func(t *testing.T, token string) (*http.Response, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/x", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = res.Body.Close() })
		return res, readBody(t, res)
	}

	t.Run("a minted token passes the gate with its own roles", func(t *testing.T) {
		token, _ := rt.MintSimulationToken("ghost", []string{"auditor"}, time.Minute)
		res, body := bearer(t, token)
		if res.StatusCode != http.StatusOK || body != "sim=|cookie=" {
			t.Fatalf("got %d %q, want 200 with no internals leaked", res.StatusCode, body)
		}
	})

	t.Run("wrong roles in the token are refused by the gate", func(t *testing.T) {
		token, _ := rt.MintSimulationToken("ghost", []string{"intern"}, time.Minute)
		if res, _ := bearer(t, token); res.StatusCode != http.StatusForbidden {
			t.Fatalf("got %d, want 403", res.StatusCode)
		}
	})

	t.Run("expired and tampered tokens are explicit 403s", func(t *testing.T) {
		expired, _ := rt.MintSimulationToken("ghost", []string{"auditor"}, -time.Second)
		if res, _ := bearer(t, expired); res.StatusCode != http.StatusForbidden {
			t.Fatalf("expired: got %d, want 403", res.StatusCode)
		}
		token, _ := rt.MintSimulationToken("ghost", []string{"auditor"}, time.Minute)
		if res, _ := bearer(t, token+"x"); res.StatusCode != http.StatusForbidden {
			t.Fatalf("tampered: got %d, want 403", res.StatusCode)
		}
	})
}

func issueSession(t *testing.T, sm *session.Manager, userID string) *http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	if _, err := sm.Issue(context.Background(), rec, httptest.NewRequest("POST", "/login", nil), userID); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return rec.Result().Cookies()[0]
}

func readBody(t *testing.T, res *http.Response) string {
	t.Helper()
	buf := make([]byte, 4096)
	n, _ := res.Body.Read(buf)
	return string(buf[:n])
}
