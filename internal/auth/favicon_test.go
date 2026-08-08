package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
// everybody sets a logo - so an application that never heard of the field
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
// contract - and the type list is what keeps a Content-Type from being
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

// The admin plane speaks English, whatever the integrator declares for their
// own users: it is the door to a console that speaks English anyway.
func TestAdminSignInIsEnglishOnly(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	// The application declares French and German for ITS users.
	if err := st.SetSetting(context.Background(), store.SettingLanguages, []string{"fr", "de"}); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	NewAdmin(st, session.NewManager(st)).Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.Header.Set("Accept-Language", "fr-FR,fr;q=0.9")
	req.AddCookie(&http.Cookie{Name: "MEERKAT_LANG", Value: "de"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, `<html lang="en"`) {
		t.Fatalf("the admin sign-in page must be English: %q", firstLine(body))
	}
	// One language means no switcher to show. Match the ELEMENT, not the class:
	// the stylesheet always carries .lang-menu, so "lang-menu" alone is a test
	// that fails whatever the page does.
	if strings.Contains(body, `id="lang-menu"`) {
		t.Fatal("the admin sign-in page must not offer a language menu")
	}
}

func firstLine(s string) string {
	if i := strings.Index(s, "\n<title"); i > 0 && i < 400 {
		return s[:i]
	}
	if len(s) > 200 {
		return s[:200]
	}
	return s
}

// The pages sit in FRONT of an application that may only know one look. A
// sign-in page following a dark system, handing over to a light-only portal,
// reads as two products - and the integrator cannot fix that from their side.
func TestPagesSchemeCanBeImposed(t *testing.T) {
	for _, tc := range []struct {
		name, setting, cookie string
		wantScheme            string
		wantSwitch            bool
	}{
		{"the visitor decides by default", "", "", "auto", true},
		{"and their choice is remembered", "", "dark", "dark", true},
		{"imposed light wins over the system", "light", "", "light", false},
		{"imposed light wins over their cookie too", "light", "dark", "light", false},
		{"imposed dark", "dark", "light", "dark", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux, _, st := setupFlow(t)
			if err := st.SetSetting(context.Background(), store.SettingPagesScheme, tc.setting); err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodGet, "/login", nil)
			if tc.cookie != "" {
				req.AddCookie(&http.Cookie{Name: "MEERKAT_SCHEME", Value: tc.cookie})
			}
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			body := rec.Body.String()

			// Match the :root RULE, not the words: the stylesheet mentions
			// color-scheme elsewhere, so a bare Contains passes on anything.
			if tc.wantScheme == "auto" {
				if strings.Contains(body, ":root { color-scheme:") {
					t.Fatal("auto must leave the scheme to the system")
				}
			} else if !strings.Contains(body, ":root { color-scheme: "+tc.wantScheme) {
				t.Fatalf("want :root color-scheme %s", tc.wantScheme)
			}
			// The button that would let a visitor break the pairing goes away
			// with the choice. Match the BUTTON: the page's script mentions
			// data-scheme-next whether or not the button is rendered.
			hasSwitch := strings.Contains(body, `class="scheme-cycle"`)
			if hasSwitch != tc.wantSwitch {
				t.Fatalf("scheme button present=%v, want %v", hasSwitch, tc.wantSwitch)
			}
		})
	}
}

// The passkey block (registering one, signing in with one) is mounted on the
// data plane only, so offering the button on the admin sign-in page pointed at
// an endpoint that is not there - and nothing in the console can register a key
// to begin with.
func TestAdminSignInOffersNoPasskey(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	mux := http.NewServeMux()
	NewAdmin(st, session.NewManager(st)).Register(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login", nil))

	if strings.Contains(rec.Body.String(), "pk-login") {
		t.Fatal("the admin sign-in page must not offer a passkey it cannot honour")
	}
}

// The user button injected into the application's pages follows the imposed
// scheme too. It read the visitor's cookie on its own, so a light-only install
// still handed out a dark button - on the very pages the choice exists for.
func TestUserButtonFollowsTheImposedScheme(t *testing.T) {
	mux, _, st := setupFlow(t)
	if err := st.SetSetting(context.Background(), store.SettingPagesScheme, "light"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/meerkat/user-button.json", nil)
	// The visitor asked for dark on the flow pages: the integrator's choice wins.
	req.AddCookie(&http.Cookie{Name: "MEERKAT_SCHEME", Value: "dark"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var payload struct {
		Scheme        string `json:"scheme"`
		SchemeImposed bool   `json:"schemeImposed"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if payload.Scheme != "light" || !payload.SchemeImposed {
		t.Fatalf("got scheme %q imposed=%v, want light imposed", payload.Scheme, payload.SchemeImposed)
	}
}
