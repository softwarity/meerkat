package auth

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/softwarity/meerkat/internal/session"
	"github.com/softwarity/meerkat/internal/store"
)

// A 1x1 PNG and a 1x1 GIF, small enough to read: what matters here is which
// one comes back, not what it draws.
const (
	pngURI = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
	icoURI = "data:image/x-icon;base64,AAABAAEAAQEAAAEAIAAwAAAAFgAAACgAAAABAAAAAgAAAAEAIAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

func fetchFavicon(t *testing.T, mux *http.ServeMux) *http.Response {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/meerkat/favicon", nil))
	return rec.Result()
}

func setBranding(t *testing.T, st *store.Store, b store.Branding) {
	t.Helper()
	if err := store.SanitizeBranding(&b); err != nil {
		t.Fatalf("SanitizeBranding: %v", err)
	}
	if err := st.SetSetting(context.Background(), store.SettingBranding, b); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
}

// The cascade, and the middle step is the point: nobody sets a favicon, but
// everybody sets a logo — so an application that never heard of the field
// still gets its own mark in the browser tab instead of ours.
func TestFaviconFollowsTheBranding(t *testing.T) {
	for _, tc := range []struct {
		name     string
		branding store.Branding
		wantType string
	}{
		{"nothing set falls back to Meerkat", store.Branding{AppName: "App"}, "image/svg+xml"},
		{"a logo alone becomes the tab icon", store.Branding{AppName: "App", Logo: pngURI}, "image/png"},
		{"an explicit icon wins over the logo", store.Branding{AppName: "App", Logo: pngURI, Favicon: icoURI}, "image/x-icon"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux, _, st := setupFlow(t)
			setBranding(t, st, tc.branding)

			res := fetchFavicon(t, mux)
			defer func() { _ = res.Body.Close() }()
			if res.StatusCode != http.StatusOK {
				t.Fatalf("status %d", res.StatusCode)
			}
			if got := res.Header.Get("Content-Type"); got != tc.wantType {
				t.Fatalf("Content-Type %q, want %q", got, tc.wantType)
			}
			buf := new(bytes.Buffer)
			if _, err := buf.ReadFrom(res.Body); err != nil {
				t.Fatal(err)
			}
			if buf.Len() == 0 {
				t.Fatal("empty icon")
			}
			// The bytes must be the DECODED image, not the data URI echoed back.
			if bytes.HasPrefix(buf.Bytes(), []byte("data:")) {
				t.Fatalf("the data URI was served verbatim: %q", buf.Bytes()[:32])
			}
		})
	}
}

// The console is Meerkat's own product: it wears Meerkat's face whatever the
// integrator sets, exactly as its theme is not theirs to restyle.
func TestAdminFaviconIgnoresTheBranding(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	setBranding(t, st, store.Branding{AppName: "App", Logo: pngURI, Favicon: icoURI})

	mux := http.NewServeMux()
	NewAdmin(st, session.NewManager(st)).Register(mux)

	res := fetchFavicon(t, mux)
	defer func() { _ = res.Body.Close() }()
	if got := res.Header.Get("Content-Type"); got != "image/svg+xml" {
		t.Fatalf("Content-Type %q: the admin plane must keep the sentinel", got)
	}
}

// A favicon rides on every sign-in page, so the size ceiling is part of the
// contract — and the type list is what keeps a Content-Type from being
// whatever an admin typed.
func TestBrandingRefusesAnUnusableIcon(t *testing.T) {
	big := "data:image/png;base64," + string(bytes.Repeat([]byte("A"), 64_001))
	for _, tc := range []struct {
		name string
		b    store.Branding
	}{
		{"too large", store.Branding{AppName: "App", Favicon: big}},
		{"not an image", store.Branding{AppName: "App", Favicon: "data:text/html;base64,PGgxPmhpPC9oMT4="}},
		{"not a data URI", store.Branding{AppName: "App", Favicon: "https://example.com/favicon.ico"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := tc.b
			if err := store.SanitizeBranding(&b); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}
