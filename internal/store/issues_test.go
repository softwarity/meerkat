package store

import (
	"context"
	"strings"
	"testing"
)

// The issue tracker's store contract: reports round-trip with their captured
// context, lists stay light (no screenshot, no console, no comments), the
// screenshot is read on demand, and the lifecycle (status, comments, delete)
// behaves.
func TestIssues(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	if err := s.SaveTenant(ctx, Tenant{ID: "t1", Name: "acme", Enabled: true}); err != nil {
		t.Fatal(err)
	}

	shot := "data:image/jpeg;base64," + strings.Repeat("A", 400)
	filed, err := s.AddIssue(ctx, Issue{
		ReporterID: "u1", ReporterName: "alice", TenantID: "t1",
		Description: "the save button does nothing",
		URL:         "https://app.example/orders", UserAgent: "TestBrowser/1.0",
		Viewport: "1280x720", Screen: "2560x1440", DPR: 2, Language: "fr",
		ConsoleLog: []ConsoleEntry{{Level: "error", Text: "boom"}},
		Screenshot: shot,
	})
	if err != nil {
		t.Fatal(err)
	}
	if filed.ID == "" || filed.CreatedAt == 0 || filed.Status != IssueOpen || !filed.HasScreenshot {
		t.Fatalf("filed issue = %+v (want stamped id/time, open, screenshot flagged)", filed)
	}
	// A second, older-tenant-less report to exercise ordering and scope.
	other, err := s.AddIssue(ctx, Issue{CreatedAt: filed.CreatedAt - 10, Description: "global glitch"})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("lists are newest first, light, and scope by tenant", func(t *testing.T) {
		all, err := s.ListIssues(ctx, IssueFilter{})
		if err != nil {
			t.Fatal(err)
		}
		if len(all) != 2 || all[0].ID != filed.ID || all[1].ID != other.ID {
			t.Fatalf("list order = %+v", all)
		}
		if all[0].TenantName != "acme" || len(all[0].ConsoleLog) != 0 || len(all[0].Comments) != 0 {
			t.Fatalf("list row = %+v (want joined tenant name, no heavy fields)", all[0])
		}
		scoped, err := s.ListIssues(ctx, IssueFilter{TenantIDs: []string{"t1"}})
		if err != nil {
			t.Fatal(err)
		}
		if len(scoped) != 1 || scoped[0].ID != filed.ID {
			t.Fatalf("tenant scope = %+v", scoped)
		}
		// An empty non-nil scope administers nothing and sees nothing.
		if none, err := s.ListIssues(ctx, IssueFilter{TenantIDs: []string{}}); err != nil || len(none) != 0 {
			t.Fatalf("empty scope = %+v, %v", none, err)
		}
	})

	t.Run("the detail carries the console, the screenshot stays on demand", func(t *testing.T) {
		got, err := s.GetIssue(ctx, filed.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(got.ConsoleLog) != 1 || got.ConsoleLog[0].Text != "boom" || !got.HasScreenshot || got.Screenshot != "" {
			t.Fatalf("detail = %+v", got)
		}
		data, err := s.GetIssueScreenshot(ctx, filed.ID)
		if err != nil || data != shot {
			t.Fatalf("screenshot = %d bytes, %v", len(data), err)
		}
	})

	t.Run("lifecycle: status, comments, delete", func(t *testing.T) {
		if ok, err := s.SetIssueStatus(ctx, filed.ID, IssueInProgress); err != nil || !ok {
			t.Fatalf("set status: %v %v", ok, err)
		}
		if _, err := s.SetIssueStatus(ctx, filed.ID, "done"); err == nil {
			t.Fatal("an unknown status must be refused")
		}
		if ok, err := s.AddIssueComment(ctx, filed.ID, IssueComment{AuthorID: "u2", Author: "bob", Text: "on it"}); err != nil || !ok {
			t.Fatalf("comment: %v %v", ok, err)
		}
		if ok, err := s.AddIssueComment(ctx, "ghost", IssueComment{Text: "x"}); err != nil || ok {
			t.Fatalf("comment on a ghost issue: %v %v", ok, err)
		}
		got, err := s.GetIssue(ctx, filed.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Status != IssueInProgress || len(got.Comments) != 1 ||
			got.Comments[0].Author != "bob" || got.Comments[0].ID == "" || got.Comments[0].At == 0 {
			t.Fatalf("after lifecycle = %+v", got)
		}
		if ok, err := s.DeleteIssue(ctx, filed.ID); err != nil || !ok {
			t.Fatalf("delete: %v %v", ok, err)
		}
		if ok, err := s.DeleteIssue(ctx, filed.ID); err != nil || ok {
			t.Fatalf("double delete: %v %v", ok, err)
		}
	})

	t.Run("a screenshot must be a bounded image data URI", func(t *testing.T) {
		if _, err := s.AddIssue(ctx, Issue{Description: "x", Screenshot: "http://evil/img.png"}); err == nil {
			t.Fatal("a non-data-URI screenshot must be refused")
		}
		if _, err := s.AddIssue(ctx, Issue{Description: "x",
			Screenshot: "data:image/jpeg;base64," + strings.Repeat("A", 2_100_000)}); err == nil {
			t.Fatal("an oversized screenshot must be refused")
		}
	})
}
