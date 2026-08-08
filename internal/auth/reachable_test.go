package auth

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/softwarity/meerkat/internal/routing"
	"github.com/softwarity/meerkat/internal/store"
)

func uiRoute(id string, order int, authenticated bool, requiredRole string) store.Route {
	access := store.Access{}
	if authenticated {
		access.Level = store.AccessAuth
	}
	if requiredRole != "" {
		access.Roles = []string{requiredRole}
	}
	return store.Route{
		ID: id, Name: id, Order: order, Enabled: true, IsUI: true,
		Access:   access,
		UI:       &store.RouteUI{Link: id},
		Upstream: "http://upstream.test",
		Predicates: []routing.Spec{
			{Type: "path", Args: map[string]any{"patterns": []any{"/" + id + "/**"}}},
		},
	}
}

// TestProfileHubAndUserButtonListReachableApps: the profile hub and the
// user-button JSON offer the UI routes THIS session may open - public and
// authenticated ones, never a role-gated one the user does not hold.
func TestProfileHubAndUserButtonListReachableApps(t *testing.T) {
	mux, _, st := mfaSetup(t)
	ctx := context.Background()
	for _, rt := range []store.Route{
		uiRoute("shop", 1, false, ""),
		uiRoute("intranet", 2, true, ""),
		uiRoute("ops", 3, true, "operations"),
	} {
		if err := st.SaveRoute(ctx, rt); err != nil {
			t.Fatalf("SaveRoute %s: %v", rt.ID, err)
		}
	}

	login := do(t, mux, "POST", "/login", url.Values{"username": {"admin"}, "password": {"s3cret"}}, nil)
	var session *http.Cookie
	for _, c := range login.Result().Cookies() {
		if c.Name != browserCookieName {
			session = c
		}
	}

	hub := do(t, mux, "GET", "/profile", nil, session)
	body := bodyString(hub)
	if !strings.Contains(body, `href="/shop"`) || !strings.Contains(body, `href="/intranet"`) {
		t.Fatalf("profile hub must link the reachable apps:\n%.600s", body)
	}
	if strings.Contains(body, `href="/ops"`) {
		t.Fatalf("profile hub must not link a role-gated app the user does not hold")
	}

	btn := do(t, mux, "GET", "/meerkat/user-button.json", nil, session)
	payload := bodyString(btn)
	if !strings.Contains(payload, `"/shop"`) || !strings.Contains(payload, `"/intranet"`) {
		t.Fatalf("user-button apps missing: %s", payload)
	}
	if strings.Contains(payload, `"/ops"`) {
		t.Fatalf("user-button must not offer a role-gated app the user does not hold: %s", payload)
	}
	if !strings.Contains(payload, `"applications"`) {
		t.Fatalf("user-button labels must carry the Applications entry")
	}
}
