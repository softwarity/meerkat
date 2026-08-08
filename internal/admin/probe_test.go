package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/softwarity/meerkat/internal/gateway"
	"github.com/softwarity/meerkat/internal/routing"
	"github.com/softwarity/meerkat/internal/store"
)

func probe(t *testing.T, f fixture, body string) gateway.ProbeResult {
	t.Helper()
	code, out := f.call(t, "POST", "/api/routes/probe", body, f.rootC)
	if code != http.StatusOK {
		t.Fatalf("probe: %d %s", code, out)
	}
	var res gateway.ProbeResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("probe payload: %v - %s", err, out)
	}
	return res
}

// TestProbeWalksTheRoutesInOrder is the whole point of the feature: order
// decides, so a request built for one route must be REFUSED by every route
// above it. The probe shows that walk, and names the predicate each route
// refused on.
func TestProbeWalksTheRoutesInOrder(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	for _, r := range []store.Route{
		{
			ID: "admin", Name: "admin", Order: 1, Enabled: true, Upstream: "http://admin.internal",
			Predicates: []routing.Spec{{Type: "path", Args: map[string]any{"patterns": []any{"/admin/**"}}}},
		},
		{
			ID: "api-v2", Name: "api-v2", Order: 2, Enabled: true, Upstream: "http://v2.internal",
			Predicates: []routing.Spec{
				{Type: "path", Args: map[string]any{"patterns": []any{"/api/**"}}},
				{Type: "header", Args: map[string]any{"name": "X-Api-Version", "regexp": "v2"}},
			},
		},
		{
			ID: "api", Name: "api", Order: 3, Enabled: true, Upstream: "http://v1.internal",
			Predicates: []routing.Spec{{Type: "path", Args: map[string]any{"patterns": []any{"/api/**"}}}},
		},
	} {
		if err := f.api.st.SaveRoute(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.api.router.Reload(ctx); err != nil {
		t.Fatal(err)
	}

	// Aiming at the v1 route: the probe must build a /api/... request, admin
	// must refuse it on its path, api-v2 on its header, and api must win.
	res := probe(t, f, `{"targetRouteId":"api"}`)
	if res.Outcome != "match" || res.WinnerID != "api" {
		t.Fatalf("outcome %q, winner %q, want the target to win: %+v", res.Outcome, res.WinnerID, res.Steps)
	}
	if len(res.Steps) != 3 {
		t.Fatalf("every route must appear in the cascade, got %d", len(res.Steps))
	}
	if res.Steps[0].Matched || res.Steps[0].Preds[0].Type != "path" {
		t.Fatalf("the admin route should refuse on its path: %+v", res.Steps[0])
	}
	if res.Steps[1].Matched {
		t.Fatalf("api-v2 must refuse a request without its header: %+v", res.Steps[1])
	}
	// And it says WHICH predicate: path ok, header not.
	v := res.Steps[1].Preds
	if !v[0].Matched || v[1].Matched || v[1].Type != "header" {
		t.Fatalf("api-v2 verdicts should be path ok / header refused, got %+v", v)
	}

	// Aiming at the route that is BEHIND a stricter one: the synthesis adds the
	// header, so v2 wins on its own probe.
	res = probe(t, f, `{"targetRouteId":"api-v2"}`)
	if res.Outcome != "match" || res.WinnerID != "api-v2" {
		t.Fatalf("the header predicate was not synthesized: %+v", res.Request)
	}
	if got := res.Request.Headers["X-Api-Version"]; got != "v2" {
		t.Fatalf("synthesized header = %q, want v2", got)
	}
}

// TestProbeNamesTheInterceptor: the failure an admin actually hits is "my
// request goes somewhere else". The probe must say WHERE, not just "no".
func TestProbeNamesTheInterceptor(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	// A catch-all sitting ABOVE the specific route swallows everything.
	for _, r := range []store.Route{
		{
			ID: "catch-all", Name: "catch-all", Order: 1, Enabled: true, Upstream: "http://trap.internal",
			Predicates: []routing.Spec{{Type: "path", Args: map[string]any{"patterns": []any{"/**"}}}},
		},
		{
			ID: "billing", Name: "billing", Order: 2, Enabled: true, Upstream: "http://billing.internal",
			Predicates: []routing.Spec{{Type: "path", Args: map[string]any{"patterns": []any{"/billing/**"}}}},
		},
	} {
		if err := f.api.st.SaveRoute(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.api.router.Reload(ctx); err != nil {
		t.Fatal(err)
	}

	res := probe(t, f, `{"targetRouteId":"billing"}`)
	if res.Outcome != "intercepted" || res.WinnerName != "catch-all" {
		t.Fatalf("the interceptor was not named: outcome %q winner %q", res.Outcome, res.WinnerName)
	}
	// The target itself still matches - it was only beaten to it.
	var target ProbeStepAlias
	for _, st := range res.Steps {
		if st.RouteID == "billing" {
			target = ProbeStepAlias(st)
		}
	}
	if !target.Matched {
		t.Fatalf("billing should match its own probe, it was merely too low: %+v", target)
	}
}

// ProbeStepAlias keeps the assertion above readable.
type ProbeStepAlias gateway.ProbeStep

// TestProbeTakesADescribedRequest: the other direction - an admin pastes what
// their client sends and asks where it lands. No target, no synthesis.
func TestProbeTakesADescribedRequest(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if err := f.api.st.SaveRoute(ctx, store.Route{
		ID: "eu", Name: "eu", Order: 1, Enabled: true, Upstream: "http://eu.internal",
		Predicates: []routing.Spec{
			{Type: "host", Args: map[string]any{"hosts": []any{"*.eu.acme.io"}}},
			{Type: "method", Args: map[string]any{"methods": []any{"POST"}}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.api.router.Reload(ctx); err != nil {
		t.Fatal(err)
	}

	res := probe(t, f, `{"request":{"method":"POST","path":"/orders","host":"shop.eu.acme.io"}}`)
	if res.Outcome != "match" || res.WinnerID != "eu" {
		t.Fatalf("described request did not land on eu: %+v", res)
	}
	// A GET on the same host misses, and the verdict points at the method.
	res = probe(t, f, `{"request":{"method":"GET","path":"/orders","host":"shop.eu.acme.io"}}`)
	if res.Outcome != "none" {
		t.Fatalf("a GET must not match a POST-only route: %+v", res)
	}
	v := res.Steps[0].Preds
	if !v[0].Matched || v[1].Matched || v[1].Type != "method" {
		t.Fatalf("the method should be the one refusing: %+v", v)
	}

	// Nothing to probe at all is a clear 422, not an empty cascade.
	code, out := f.call(t, "POST", "/api/routes/probe", `{}`, f.rootC)
	if code != http.StatusUnprocessableEntity || !strings.Contains(out, "nothing to probe") {
		t.Fatalf("empty probe: %d %s", code, out)
	}
	// And it is infra-scoped.
	if code, _ := f.call(t, "POST", "/api/routes/probe", `{"targetRouteId":"eu"}`, f.plainC); code != http.StatusForbidden {
		t.Fatalf("probe authz: %d, want 403", code)
	}
}
