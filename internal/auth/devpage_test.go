package auth

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/softwarity/meerkat/internal/session"
	"github.com/softwarity/meerkat/internal/store"
	"golang.org/x/crypto/bcrypt"
)

// The Developer hub lists its tools: the certificate always, the API docs
// only when the data-plane switch exposes them. The cert lives on its own
// sub-page; a non-dev is refused everywhere.
func TestDeveloperHub(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	hash, _ := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.MinCost)
	if err := st.CreateUser(ctx, store.User{ID: "d", Username: "devon", PasswordHash: string(hash), Enabled: true, Dev: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUser(ctx, store.User{ID: "b", Username: "bob", PasswordHash: string(hash), Enabled: true}); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	New(st, session.NewManager(st)).Register(mux)

	devC := postLogin(t, mux, url.Values{"username": {"devon"}, "password": {"s3cret"}}).Result().Cookies()[0]
	bobC := postLogin(t, mux, url.Values{"username": {"bob"}, "password": {"s3cret"}}).Result().Cookies()[0]

	// The profile shows the Developer entry for a dev, and the hub links the cert.
	if prof := do(t, mux, "GET", "/profile", nil, devC); !strings.Contains(bodyString(prof), `href="/profile/dev"`) {
		t.Fatal("profile missing the Developer link for a dev")
	}
	// Read the body ONCE: bodyString drains the recorder, so a second call
	// answers "" and every Contains on it passes for the wrong reason - which
	// is how the assertion that used to guard the API entry was green while
	// testing nothing at all.
	hub := do(t, mux, "GET", "/profile/dev", nil, devC)
	hubBody := bodyString(hub)
	if hub.Code != http.StatusOK || !strings.Contains(hubBody, `href="/profile/dev/cert"`) {
		t.Fatalf("hub: code=%d, cert link missing", hub.Code)
	}

	// The API entry: the dev capability is the whole gate, so a dev sees it.
	if !strings.Contains(hubBody, `href="/meerkat/apidocs/"`) {
		t.Fatal("API entry missing from the hub of a dev")
	}

	// The user-button payload mirrors the same gate (the Developer submenu):
	// a dev gets the flag, a non-dev never does.
	if body := bodyString(do(t, mux, "GET", "/meerkat/user-button.json", nil, devC)); !strings.Contains(body, `"devDocs":true`) {
		t.Fatalf("user-button payload misses the devDocs flag for a dev: %s", body)
	}
	if body := bodyString(do(t, mux, "GET", "/meerkat/user-button.json", nil, bobC)); strings.Contains(body, `"devDocs"`) {
		t.Fatalf("user-button payload advertises devDocs to a non-dev: %s", body)
	}

	// The cert sub-page renders its form, and a bad PEM is refused there.
	cert := do(t, mux, "GET", "/profile/dev/cert", nil, devC)
	if cert.Code != http.StatusOK || !strings.Contains(bodyString(cert), "BEGIN CERTIFICATE") {
		t.Fatalf("cert page: code=%d", cert.Code)
	}
	bad := do(t, mux, "POST", "/profile/dev-cert", url.Values{"cert": {"not a pem"}}, devC)
	if bad.Code != http.StatusUnprocessableEntity {
		t.Fatalf("bad cert: code=%d, want 422", bad.Code)
	}

	// A non-dev is refused at the hub and the sub-page.
	for _, p := range []string{"/profile/dev", "/profile/dev/cert"} {
		if res := do(t, mux, "GET", p, nil, bobC); res.Code != http.StatusForbidden {
			t.Fatalf("non-dev on %s: code=%d, want 403", p, res.Code)
		}
	}
}
