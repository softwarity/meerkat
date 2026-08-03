package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/softwarity/meerkat/internal/session"
	"github.com/softwarity/meerkat/internal/store"
	"golang.org/x/crypto/bcrypt"
)

// The issue-report endpoint: dead while the switch is off, signed-in only,
// stamped with the SESSION's identity (never the body's), bounded, and the
// user-button payload carries the feature flag.
func TestIssueReports(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	hash, _ := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.MinCost)
	if err := st.CreateUser(ctx, store.User{ID: "a", Username: "alice", PasswordHash: string(hash), Enabled: true}); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	New(st, session.NewManager(st)).Register(mux)
	aliceC := postLogin(t, mux, url.Values{"username": {"alice"}, "password": {"s3cret"}}).Result().Cookies()[0]

	postJSON := func(t *testing.T, payload string, cookie *http.Cookie) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest("POST", "/meerkat/issues", strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		if cookie != nil {
			req.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	t.Run("ships OFF: the endpoint plays dead and the payload hides the entry", func(t *testing.T) {
		if rec := postJSON(t, `{"description":"x"}`, aliceC); rec.Code != http.StatusNotFound {
			t.Fatalf("post while off: %d, want 404", rec.Code)
		}
		if body := bodyString(do(t, mux, "GET", "/meerkat/user-button.json", nil, aliceC)); strings.Contains(body, `"issues":true`) {
			t.Fatalf("payload advertises issues while off: %s", body)
		}
	})

	if err := st.SetSetting(ctx, store.SettingIssuesEnabled, true); err != nil {
		t.Fatal(err)
	}

	t.Run("anonymous is refused, the payload advertises the entry once on", func(t *testing.T) {
		if rec := postJSON(t, `{"description":"x"}`, nil); rec.Code != http.StatusUnauthorized {
			t.Fatalf("anonymous post: %d, want 401", rec.Code)
		}
		if body := bodyString(do(t, mux, "GET", "/meerkat/user-button.json", nil, aliceC)); !strings.Contains(body, `"issues":true`) {
			t.Fatalf("payload misses the issues flag: %s", body)
		}
		// The labels ride along for the panel.
		if body := bodyString(do(t, mux, "GET", "/meerkat/user-button.json", nil, aliceC)); !strings.Contains(body, "Report an issue") {
			t.Fatal("payload misses the openIssue label")
		}
	})

	t.Run("a signed-in report is stamped with the session identity", func(t *testing.T) {
		shot := "data:image/jpeg;base64," + strings.Repeat("A", 40)
		rec := postJSON(t, `{"description":"  the cart empties itself  ","url":"https://app/cart",
			"userAgent":"TB/1","viewport":"800x600","screen":"1600x1200","dpr":2,"language":"fr",
			"console":[{"level":"error","at":"t0","text":"boom"}],"screenshot":"`+shot+`"}`, aliceC)
		if rec.Code != http.StatusCreated {
			t.Fatalf("post: %d %s", rec.Code, bodyString(rec))
		}
		var out struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal([]byte(bodyString(rec)), &out); err != nil || out.ID == "" {
			t.Fatalf("post answer: %v %q", err, out.ID)
		}
		is, err := st.GetIssue(ctx, out.ID)
		if err != nil {
			t.Fatal(err)
		}
		if is.ReporterID != "a" || is.ReporterName != "alice" || is.Status != store.IssueOpen ||
			is.Description != "the cart empties itself" || !is.HasScreenshot ||
			len(is.ConsoleLog) != 1 || is.DPR != 2 {
			t.Fatalf("stored issue = %+v", is)
		}
	})

	t.Run("bad reports are refused with names", func(t *testing.T) {
		if rec := postJSON(t, `{"description":"   "}`, aliceC); rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("empty description: %d", rec.Code)
		}
		if rec := postJSON(t, `{"description":"x","screenshot":"http://evil/x.png"}`, aliceC); rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("bad screenshot: %d", rec.Code)
		}
		if rec := postJSON(t, `{"description":"`+strings.Repeat("a", issueMaxBody)+`"}`, aliceC); rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("oversized body: %d", rec.Code)
		}
	})
}
