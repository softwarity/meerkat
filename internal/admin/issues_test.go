package admin

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/softwarity/meerkat/internal/store"
)

// The issue tracker's management side: visibility is scoped (root/infra/app
// admins see everything, a tenant admin their tenants only, anyone else is
// refused), the lifecycle works, the screenshot streams as a real image, and
// the toggle behaves like every other setting pair.
func TestIssuesAPI(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	st := f.api.st

	// tina administers t1 (ADMIN membership); the fixture's bob stays plain.
	if err := st.CreateUser(ctx, store.User{ID: "tina", Username: "tina", PasswordHash: "x", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveTenant(ctx, store.Tenant{ID: "t1", Name: "acme", Enabled: true, OwnerID: "tina"}); err != nil {
		t.Fatal(err)
	}
	tinaC := issue(t, f.api.sm, "tina")

	shot := "data:image/jpeg;base64," + strings.Repeat("QUJD", 12)
	inT1, err := st.AddIssue(ctx, store.Issue{TenantID: "t1", ReporterName: "alice",
		Description: "cart empties itself", Screenshot: shot})
	if err != nil {
		t.Fatal(err)
	}
	global, err := st.AddIssue(ctx, store.Issue{Description: "global glitch"})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("visibility: root sees all, a tenant admin their tenant, others nothing", func(t *testing.T) {
		if code, _ := f.call(t, "GET", "/api/issues", "", nil); code != http.StatusUnauthorized {
			t.Fatalf("anonymous: %d, want 401", code)
		}
		if code, _ := f.call(t, "GET", "/api/issues", "", f.plainC); code != http.StatusForbidden {
			t.Fatalf("plain user: %d, want 403", code)
		}
		code, body := f.call(t, "GET", "/api/issues", "", f.rootC)
		var list []store.Issue
		if err := json.Unmarshal([]byte(body), &list); err != nil || code != http.StatusOK || len(list) != 2 {
			t.Fatalf("root list: %d %v %s", code, err, body)
		}
		code, body = f.call(t, "GET", "/api/issues", "", tinaC)
		if err := json.Unmarshal([]byte(body), &list); err != nil || code != http.StatusOK ||
			len(list) != 1 || list[0].ID != inT1.ID || list[0].TenantName != "acme" {
			t.Fatalf("tenant-admin list: %d %s", code, body)
		}
		// The global report does not exist for tina, not even by id.
		if code, _ := f.call(t, "GET", "/api/issues/"+global.ID, "", tinaC); code != http.StatusNotFound {
			t.Fatalf("out-of-scope get: %d, want 404", code)
		}
	})

	t.Run("the screenshot streams as an image, absent means 404", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, f.adminSrv.URL+"/api/issues/"+inT1.ID+"/screenshot", nil)
		req.AddCookie(tinaC)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusOK || res.Header.Get("Content-Type") != "image/jpeg" || string(raw) != strings.Repeat("ABC", 12) {
			t.Fatalf("screenshot: %d %q %q", res.StatusCode, res.Header.Get("Content-Type"), raw)
		}
		if code, _ := f.call(t, "GET", "/api/issues/"+global.ID+"/screenshot", "", f.rootC); code != http.StatusNotFound {
			t.Fatalf("missing screenshot: %d, want 404", code)
		}
	})

	t.Run("lifecycle: status, comment, delete - audited and validated", func(t *testing.T) {
		code, body := f.call(t, "PUT", "/api/issues/"+inT1.ID+"/status", `{"status":"in-progress"}`, tinaC)
		var is store.Issue
		if err := json.Unmarshal([]byte(body), &is); err != nil || code != http.StatusOK || is.Status != store.IssueInProgress {
			t.Fatalf("status: %d %s", code, body)
		}
		if code, _ := f.call(t, "PUT", "/api/issues/"+inT1.ID+"/status", `{"status":"done"}`, tinaC); code != http.StatusUnprocessableEntity {
			t.Fatalf("bad status: %d, want 422", code)
		}
		code, body = f.call(t, "POST", "/api/issues/"+inT1.ID+"/comments", `{"text":"  looking into it  "}`, tinaC)
		if err := json.Unmarshal([]byte(body), &is); err != nil || code != http.StatusOK ||
			len(is.Comments) != 1 || is.Comments[0].Author != "tina" || is.Comments[0].Text != "looking into it" {
			t.Fatalf("comment: %d %s", code, body)
		}
		if code, _ := f.call(t, "POST", "/api/issues/"+inT1.ID+"/comments", `{"text":"   "}`, tinaC); code != http.StatusUnprocessableEntity {
			t.Fatalf("empty comment: %d, want 422", code)
		}
		// The mutations landed in the audit trail under the issue target.
		events, err := st.ListAuditEvents(ctx, store.AuditFilter{Target: "issue"})
		if err != nil || len(events) != 2 {
			t.Fatalf("audit events = %d, %v", len(events), err)
		}
		if code, _ := f.call(t, "DELETE", "/api/issues/"+inT1.ID, "", tinaC); code != http.StatusNoContent {
			t.Fatalf("delete: %d, want 204", code)
		}
		if code, _ := f.call(t, "GET", "/api/issues/"+inT1.ID, "", f.rootC); code != http.StatusNotFound {
			t.Fatalf("deleted issue still answers: %d", code)
		}
	})

	t.Run("the tracker switch: off by default, infra-gated, audited", func(t *testing.T) {
		if code, body := f.call(t, "GET", "/api/settings/issues", "", f.rootC); code != http.StatusOK || !strings.Contains(body, `"enabled":false`) {
			t.Fatalf("default: %d %s", code, body)
		}
		if code, _ := f.call(t, "PUT", "/api/settings/issues", `{"enabled":true}`, f.plainC); code != http.StatusForbidden {
			t.Fatalf("plain toggle: %d, want 403", code)
		}
		if code, _ := f.call(t, "PUT", "/api/settings/issues", `{"enabled":true}`, f.rootC); code != http.StatusOK {
			t.Fatalf("root toggle: %d", code)
		}
		if code, body := f.call(t, "GET", "/api/settings/issues", "", f.rootC); code != http.StatusOK || !strings.Contains(body, `"enabled":true`) {
			t.Fatalf("read-back: %d %s", code, body)
		}
	})
}
