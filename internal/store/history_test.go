package store

import (
	"context"
	"fmt"
	"testing"
)

func TestLoginEventsNewestFirstAndPruned(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	if err := st.CreateUser(ctx, User{ID: "u1", Username: "alice", PasswordHash: "x", Enabled: true}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// 60 events overflow the retention depth (50): the oldest 10 must go.
	for i := 0; i < 60; i++ {
		e := LoginEvent{
			ID: fmt.Sprintf("e%02d", i), Method: "password",
			Label: "Chrome · macOS", IP: "203.0.113.7", Country: "FR",
			BrowserHash: "h1", At: int64(1000 + i),
		}
		if err := st.AddLoginEvent(ctx, e, "u1"); err != nil {
			t.Fatalf("AddLoginEvent %d: %v", i, err)
		}
	}
	events, err := st.ListLoginEvents(ctx, "u1")
	if err != nil {
		t.Fatalf("ListLoginEvents: %v", err)
	}
	if len(events) != 50 {
		t.Fatalf("kept %d events, want 50", len(events))
	}
	if events[0].ID != "e59" || events[len(events)-1].ID != "e10" {
		t.Fatalf("order/prune wrong: first=%s last=%s", events[0].ID, events[len(events)-1].ID)
	}
	if e := events[0]; e.Method != "password" || e.Label != "Chrome · macOS" ||
		e.IP != "203.0.113.7" || e.Country != "FR" || e.BrowserHash != "h1" || e.At != 1059 {
		t.Fatalf("event round-trip: %+v", e)
	}
}
