package gateway

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/softwarity/meerkat/internal/routing"
	"github.com/softwarity/meerkat/internal/session"
	"github.com/softwarity/meerkat/internal/store"
)

// The server-side page stamp edits the served HTML directly. These cover the
// fragile string-editing helpers: class merge, attribute set, meta insert.

func TestStampClass(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"bare body", `<html><body>x</body>`, `<html><body class="admin ops">x</body>`},
		{"existing class merges", `<body class="app">x</body>`, `<body class="app admin ops">x</body>`},
		{"dup token skipped", `<body class="admin">x</body>`, `<body class="admin ops">x</body>`},
		{"other attrs kept", `<body id="main" data-x="1">x</body>`, `<body id="main" data-x="1" class="admin ops">x</body>`},
		{"case-insensitive tag, first match", `<BODY>x</BODY>`, `<BODY class="admin ops">x</BODY>`},
	}
	for _, c := range cases {
		got := string(stampClass([]byte(c.in), "body", []string{"admin", "ops"}))
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
	// No target tag: body is returned unchanged.
	if got := string(stampClass([]byte(`<p>x</p>`), "body", []string{"admin"})); got != `<p>x</p>` {
		t.Errorf("missing tag: got %q", got)
	}
	// A custom tag is targeted like body.
	if got := string(stampClass([]byte(`<main>x</main>`), "main", []string{"r"})); got != `<main class="r">x</main>` {
		t.Errorf("custom tag: got %q", got)
	}
}

func TestStampAttr(t *testing.T) {
	// Add when absent, replace when present, escape the value.
	if got := string(stampAttr([]byte(`<body>x</body>`), "body", "data-user", "alice")); got != `<body data-user="alice">x</body>` {
		t.Errorf("add: got %q", got)
	}
	if got := string(stampAttr([]byte(`<body data-user="old">x</body>`), "body", "data-user", "new")); got != `<body data-user="new">x</body>` {
		t.Errorf("replace: got %q", got)
	}
	if got := string(stampAttr([]byte(`<body>x</body>`), "body", "data-name", `a"&<b`)); got != `<body data-name="a&#34;&amp;&lt;b">x</body>` {
		t.Errorf("escape: got %q", got)
	}
}

func TestMetaAndInsertAfterHead(t *testing.T) {
	if got := string(metaTag("meerkat-roles", "admin ops")); got != `<meta name="meerkat-roles" content="admin ops">` {
		t.Errorf("metaTag: got %q", got)
	}
	got := string(insertAfterHead([]byte(`<html><head><title>t</title></head>`), []byte(`<meta name="m" content="v">`)))
	want := `<html><head><meta name="m" content="v"><title>t</title></head>`
	if got != want {
		t.Errorf("insertAfterHead: got %q, want %q", got, want)
	}
	// No head: prepend.
	if got := string(insertAfterHead([]byte(`<p>x</p>`), []byte(`<meta>`))); got != `<meta><p>x</p>` {
		t.Errorf("no head: got %q", got)
	}
}

// End to end: a UI route stamps the signed-in user's identity onto the served
// HTML SERVER-SIDE (in the raw bytes, no client script); anonymous is untouched.
func TestPageStampServerSide(t *testing.T) {
	upstream := htmlUpstream(t, "/page")
	route := pathRoute("r1", "demo", 1, "/demo/**", upstream.URL,
		routing.Spec{Type: "strip-prefix", Args: map[string]any{"parts": 1}})
	route.IsUI = true
	route.UI = &store.RouteUI{
		UserInfo: &store.UserInfoConfig{Enabled: true, Fields: map[string]string{"username": ""}},
	}

	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	if err := st.CreateUser(ctx, store.User{ID: "u1", Username: "alice", PasswordHash: "x", Enabled: true}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := st.SaveRoute(ctx, route); err != nil {
		t.Fatalf("SaveRoute: %v", err)
	}
	sm := session.NewManager(st)
	rt := New(st, sm)
	if err := rt.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	srv := httptest.NewServer(rt)
	t.Cleanup(srv.Close)

	// Anonymous: served untouched (the gate skips before any rewrite).
	res, err := http.Get(srv.URL + "/demo/page")
	if err != nil {
		t.Fatal(err)
	}
	anon, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if strings.Contains(string(anon), "username=") {
		t.Fatalf("anonymous page must not be stamped: %s", anon)
	}

	// Signed in: the username lands on <body> in the RAW bytes, no <script>.
	rec := httptest.NewRecorder()
	if _, err := sm.Issue(ctx, rec, httptest.NewRequest("POST", "/login", nil), "u1"); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	req, _ := http.NewRequest("GET", srv.URL+"/demo/page", nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(rec.Result().Cookies()[0])
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if !strings.Contains(string(body), `<body username="alice">`) {
		t.Fatalf("body must be stamped server-side: %s", body)
	}
	if strings.Contains(string(body), "<script>") {
		t.Fatalf("no client script expected in a server-side stamp: %s", body)
	}
}
