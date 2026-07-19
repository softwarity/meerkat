package routing

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
)

func mustPredicates(t *testing.T, specs ...Spec) CompiledPredicates {
	t.Helper()
	cp, err := CompilePredicates(specs)
	if err != nil {
		t.Fatalf("CompilePredicates: %v", err)
	}
	return cp
}

func req(method, target string, mut ...func(*http.Request)) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	for _, m := range mut {
		m(r)
	}
	return r
}

// ---- path ------------------------------------------------------------------

func TestPathPatterns(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"/api/users", "/api/users", true},
		{"/api/users", "/api/users/", true}, // trailing slash tolerated
		{"/api/users", "/api/users/42", false},
		{"/api/users/{id}", "/api/users/42", true},
		{"/api/users/{id}", "/api/users", false},
		{"/api/users/{id}", "/api/users/42/orders", false},
		{"/demo/**", "/demo", true},
		{"/demo/**", "/demo/a/b/c", true},
		{"/demo/**", "/demolition", false},
		{"/**", "/anything/at/all", true},
	}
	for _, c := range cases {
		cp := mustPredicates(t, Spec{Type: "path", Args: map[string]any{"patterns": c.pattern}})
		if got := cp.Match(req("GET", c.path)); got != c.want {
			t.Errorf("pattern %q vs %q = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

func TestPathPatternValidation(t *testing.T) {
	for _, bad := range []string{"no-slash", "/a/**/b", "/a/{oops"} {
		if _, err := CompilePredicates([]Spec{{Type: "path", Args: map[string]any{"patterns": bad}}}); err == nil {
			t.Errorf("pattern %q accepted, want error", bad)
		}
	}
}

// ---- host / method / header / cookie / query -------------------------------

func TestHostPredicate(t *testing.T) {
	cp := mustPredicates(t, Spec{Type: "host", Args: map[string]any{"hosts": []any{"app.example.com", "*.corp.io"}}})
	cases := map[string]bool{
		"app.example.com":      true,
		"app.example.com:8080": true,
		"other.example.com":    false,
		"x.corp.io":            true,
		"a.b.corp.io":          true,
		"corp.io":              false, // *. requires a subdomain
	}
	for host, want := range cases {
		r := req("GET", "/")
		r.Host = host
		if got := cp.Match(r); got != want {
			t.Errorf("host %q = %v, want %v", host, got, want)
		}
	}
}

func TestMethodPredicate(t *testing.T) {
	cp := mustPredicates(t, Spec{Type: "method", Args: map[string]any{"methods": []any{"get", "POST"}}})
	if !cp.Match(req("GET", "/")) || !cp.Match(req("POST", "/")) || cp.Match(req("DELETE", "/")) {
		t.Fatal("method matching wrong")
	}
}

func TestHeaderCookieQueryPredicates(t *testing.T) {
	header := mustPredicates(t, Spec{Type: "header", Args: map[string]any{"name": "X-Env", "regexp": "prod|staging"}})
	if !header.Match(req("GET", "/", func(r *http.Request) { r.Header.Set("X-Env", "prod") })) {
		t.Fatal("header regexp should match prod")
	}
	if header.Match(req("GET", "/", func(r *http.Request) { r.Header.Set("X-Env", "production") })) {
		t.Fatal("regexp must be a full match (production != prod)")
	}
	if header.Match(req("GET", "/")) {
		t.Fatal("absent header matched")
	}

	cookie := mustPredicates(t, Spec{Type: "cookie", Args: map[string]any{"name": "beta"}})
	if !cookie.Match(req("GET", "/", func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "beta", Value: "1"}) })) {
		t.Fatal("cookie presence should match")
	}
	if cookie.Match(req("GET", "/")) {
		t.Fatal("absent cookie matched")
	}

	query := mustPredicates(t, Spec{Type: "query", Args: map[string]any{"name": "v", "regexp": "2"}})
	if !query.Match(req("GET", "/x?v=2")) || query.Match(req("GET", "/x?v=1")) || query.Match(req("GET", "/x")) {
		t.Fatal("query matching wrong")
	}
}

func TestRemoteAddrPredicate(t *testing.T) {
	cp := mustPredicates(t, Spec{Type: "remote-addr", Args: map[string]any{"cidrs": "10.0.0.0/8"}})
	inside := req("GET", "/")
	inside.RemoteAddr = "10.1.2.3:5555"
	outside := req("GET", "/")
	outside.RemoteAddr = "192.168.1.1:5555"
	if !cp.Match(inside) || cp.Match(outside) {
		t.Fatal("cidr matching wrong")
	}

	fwd := mustPredicates(t, Spec{Type: "remote-addr", Args: map[string]any{"cidrs": "10.0.0.0/8", "useForwarded": true}})
	proxied := req("GET", "/", func(r *http.Request) { r.Header.Set("X-Forwarded-For", "10.9.9.9, 172.16.0.1") })
	proxied.RemoteAddr = "172.16.0.1:80"
	if !fwd.Match(proxied) {
		t.Fatal("forwarded client address should match")
	}
}

// ---- weight ----------------------------------------------------------------

func TestWeightSplitsTraffic(t *testing.T) {
	a := mustPredicates(t, Spec{Type: "weight", Args: map[string]any{"group": "g", "weight": 8}})
	b := mustPredicates(t, Spec{Type: "weight", Args: map[string]any{"group": "g", "weight": 2}})
	if err := ResolveWeights([]*CompiledPredicates{&a, &b}); err != nil {
		t.Fatal(err)
	}
	countA := 0
	for i := 0; i < 1000; i++ {
		lottery := (float64(i) + 0.5) / 1000
		r := req("GET", "/")
		r = r.WithContext(WithLottery(r.Context(), lottery))
		matchA, matchB := a.Match(r), b.Match(r)
		if matchA == matchB {
			t.Fatalf("lottery %v: exactly one route must match (a=%v b=%v)", lottery, matchA, matchB)
		}
		if matchA {
			countA++
		}
	}
	if countA != 800 {
		t.Fatalf("route A took %d/1000 requests, want 800 (weight 8/10)", countA)
	}
}

func TestWeightWithoutLotteryNeverMatches(t *testing.T) {
	a := mustPredicates(t, Spec{Type: "weight", Args: map[string]any{"group": "g", "weight": 1}})
	if err := ResolveWeights([]*CompiledPredicates{&a}); err != nil {
		t.Fatal(err)
	}
	if a.Match(req("GET", "/")) {
		t.Fatal("weight matched without a lottery in context")
	}
}

// ---- args validation -------------------------------------------------------

func TestUnknownTypesAndArgsAreRejected(t *testing.T) {
	if _, err := CompilePredicates([]Spec{{Type: "nope"}}); err == nil || !strings.Contains(err.Error(), "available:") {
		t.Fatalf("unknown predicate: %v", err)
	}
	if _, err := CompileFilters([]Spec{{Type: "nope"}}); err == nil || !strings.Contains(err.Error(), "available:") {
		t.Fatalf("unknown filter: %v", err)
	}
	_, err := CompilePredicates([]Spec{{Type: "path", Args: map[string]any{"pattern": "/x"}}})
	if err == nil || !strings.Contains(err.Error(), `unknown arg "pattern"`) || !strings.Contains(err.Error(), "patterns") {
		t.Fatalf("unknown arg should list allowed args: %v", err)
	}
	if _, err := CompilePredicates([]Spec{{Type: "header", Args: map[string]any{}}}); err == nil || !strings.Contains(err.Error(), `missing required arg "name"`) {
		t.Fatalf("missing required arg: %v", err)
	}
}

// ---- filters ---------------------------------------------------------------

func proxyReq(t *testing.T, target string) *httputil.ProxyRequest {
	t.Helper()
	in := httptest.NewRequest("GET", target, nil)
	out := in.Clone(in.Context())
	return &httputil.ProxyRequest{In: in, Out: out}
}

func mustFilters(t *testing.T, specs ...Spec) CompiledFilters {
	t.Helper()
	cf, err := CompileFilters(specs)
	if err != nil {
		t.Fatalf("CompileFilters: %v", err)
	}
	return cf
}

func TestPathFilters(t *testing.T) {
	cf := mustFilters(t,
		Spec{Type: "strip-prefix", Args: map[string]any{"parts": 2}},
		Spec{Type: "prefix-path", Args: map[string]any{"prefix": "/v2"}},
	)
	pr := proxyReq(t, "/api/users/42")
	for _, f := range cf.Request {
		f(pr)
	}
	if pr.Out.URL.Path != "/v2/42" {
		t.Fatalf("path = %q, want /v2/42", pr.Out.URL.Path)
	}
}

func TestRewritePathFilter(t *testing.T) {
	cf := mustFilters(t, Spec{Type: "rewrite-path", Args: map[string]any{
		"pattern": "^/red/(.*)", "replacement": "/blue/$1",
	}})
	pr := proxyReq(t, "/red/thing")
	cf.Request[0](pr)
	if pr.Out.URL.Path != "/blue/thing" {
		t.Fatalf("path = %q", pr.Out.URL.Path)
	}
}

func TestHeaderAndQueryFilters(t *testing.T) {
	cf := mustFilters(t,
		Spec{Type: "set-request-header", Args: map[string]any{"name": "X-App", "value": "meerkat"}},
		Spec{Type: "add-request-header", Args: map[string]any{"name": "X-Trace", "value": "gw", "ifNotPresent": true}},
		Spec{Type: "remove-request-header", Args: map[string]any{"name": "X-Secret"}},
		Spec{Type: "set-query-param", Args: map[string]any{"name": "tenant", "value": "acme"}},
		Spec{Type: "remove-query-param", Args: map[string]any{"name": "debug"}},
	)
	pr := proxyReq(t, "/x?debug=1")
	pr.Out.Header.Set("X-Secret", "shh")
	pr.Out.Header.Set("X-Trace", "client") // ifNotPresent must keep this one
	for _, f := range cf.Request {
		f(pr)
	}
	if pr.Out.Header.Get("X-App") != "meerkat" ||
		pr.Out.Header.Get("X-Trace") != "client" ||
		pr.Out.Header.Get("X-Secret") != "" {
		t.Fatalf("headers wrong: %+v", pr.Out.Header)
	}
	q := pr.Out.URL.Query()
	if q.Get("tenant") != "acme" || q.Has("debug") {
		t.Fatalf("query wrong: %q", pr.Out.URL.RawQuery)
	}
}

func TestResponseFilters(t *testing.T) {
	cf := mustFilters(t,
		Spec{Type: "set-response-header", Args: map[string]any{"name": "X-Frame-Options", "value": "DENY"}},
		Spec{Type: "remove-response-header", Args: map[string]any{"name": "Server"}},
		Spec{Type: "set-status", Args: map[string]any{"status": 418}},
	)
	res := &http.Response{StatusCode: 200, Header: http.Header{"Server": []string{"leaky"}}}
	for _, f := range cf.Response {
		if err := f(res); err != nil {
			t.Fatal(err)
		}
	}
	if res.Header.Get("X-Frame-Options") != "DENY" || res.Header.Get("Server") != "" || res.StatusCode != 418 {
		t.Fatalf("response wrong: %d %+v", res.StatusCode, res.Header)
	}
}

func TestRedirectIsTerminalAndExclusive(t *testing.T) {
	cf := mustFilters(t, Spec{Type: "redirect", Args: map[string]any{"location": "/moved", "status": 301}})
	if cf.Terminal == nil {
		t.Fatal("redirect did not produce a terminal handler")
	}
	rec := httptest.NewRecorder()
	cf.Terminal.ServeHTTP(rec, req("GET", "/old"))
	if rec.Code != 301 || rec.Header().Get("Location") != "/moved" {
		t.Fatalf("redirect: %d %q", rec.Code, rec.Header().Get("Location"))
	}

	_, err := CompileFilters([]Spec{
		{Type: "redirect", Args: map[string]any{"location": "/x"}},
		{Type: "set-status", Args: map[string]any{"status": 200}},
	})
	if err == nil {
		t.Fatal("terminal filter combined with others must be rejected")
	}
}

// ---- catalog ---------------------------------------------------------------

func TestCatalogDescribesEveryBrick(t *testing.T) {
	entries := Catalog()
	if len(entries) != len(predicateRegistry)+len(filterRegistry) {
		t.Fatalf("catalog has %d entries, want %d", len(entries), len(predicateRegistry)+len(filterRegistry))
	}
	for _, e := range entries {
		if e.Doc == "" {
			t.Errorf("brick %s/%s has no doc", e.Kind, e.Type)
		}
		if e.Kind == "filter" && e.Phase == "" {
			t.Errorf("filter %s has no phase", e.Type)
		}
	}
}

// Guard: query encoding must survive the round trip.
func TestQueryEncodingPreserved(t *testing.T) {
	cf := mustFilters(t, Spec{Type: "set-query-param", Args: map[string]any{"name": "q", "value": "a b&c"}})
	pr := proxyReq(t, "/x?keep=1")
	cf.Request[0](pr)
	parsed, err := url.ParseQuery(pr.Out.URL.RawQuery)
	if err != nil || parsed.Get("q") != "a b&c" || parsed.Get("keep") != "1" {
		t.Fatalf("query round trip broken: %q (%v)", pr.Out.URL.RawQuery, err)
	}
}
