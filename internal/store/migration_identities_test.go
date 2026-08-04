package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

// TestIdentityGroupsColumnIsBackfilled: a link table created before v31 has no
// groups column, and every read of the reported names failed with "no such
// column: groups" - which reads like a broken query and is a missing
// migration. Reopening must repair it rather than leave the screen dead.
func TestIdentityGroupsColumnIsBackfilled(t *testing.T) {
	dir := t.TempDir()
	// A pre-v31 shape: the table without its groups column.
	raw, err := sql.Open("sqlite", filepath.Join(dir, "meerkat.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE user_identities (
		provider_id TEXT NOT NULL, external_id TEXT NOT NULL, user_id TEXT NOT NULL,
		created_at INTEGER NOT NULL DEFAULT 0, last_seen_at INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (provider_id, external_id))`); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := Open(dir)
	if err != nil {
		t.Fatalf("opening an older database must repair it: %v", err)
	}
	defer func() { _ = s.Close() }()
	if _, err := s.ReportedGroups(context.Background()); err != nil {
		t.Fatalf("reading the reported groups still fails: %v", err)
	}
}
