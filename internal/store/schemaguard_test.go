package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

// TestAnOlderDatabaseCatchesUp reproduces what actually happened: a database
// created before a column existed. CREATE TABLE IF NOT EXISTS says nothing to
// a table that is already there, so the column has to be added on the way in -
// otherwise the first INSERT naming it fails, three layers up, in the middle
// of a sign-in.
func TestAnOlderDatabaseCatchesUp(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.Close()

	// Rewind: drop the column a later build introduced (SQLite 3.35+ can).
	db, err := sql.Open("sqlite", filepath.Join(dir, "meerkat.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`ALTER TABLE user_identities DROP COLUMN last_seen_at`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	// Opening again must repair it, not refuse and not explode.
	st, err = Open(dir)
	if err != nil {
		t.Fatalf("an older database must catch up on its own: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cols, err := columnsOf(st.db, "user_identities")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range cols {
		if c.name == "last_seen_at" {
			found = true
		}
	}
	if !found {
		t.Fatal("the missing column was not added back")
	}

	// And the write that failed before now goes through.
	ctx := context.Background()
	if err := st.CreateUser(ctx, User{ID: "u1", Username: "bob", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveAuthProvider(ctx, AuthProvider{
		ID: "gh", Kind: ProviderGitHub, Name: "GitHub", Enabled: true,
		Config: map[string]any{"clientId": "x", "clientSecret": "y"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.LinkIdentity(ctx, "gh", "5840045", "u1", nil); err != nil {
		t.Fatalf("linking an identity is exactly what used to fail: %v", err)
	}
}
