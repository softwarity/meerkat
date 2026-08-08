package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/softwarity/meerkat/internal/vault"
)

// Snapshots (STORE-05).
//
// The one piece of backup that only the gateway can do: a COHERENT copy while
// it is running. `cp meerkat.db` on a live database can catch it mid-write or
// out of step with its write-ahead log, and nothing says so - the copy looks
// fine and fails the day it is restored, which is the worst possible day.
//
// Everything else about backups is deliberately NOT here. Scheduling,
// retention, rotation, encryption of the archives, shipping them off the host,
// alerting when one fails: mature tools do all of that (restic, borg, volume
// snapshots, the external database's own PITR), and half-rebuilding it inside
// an app-gateway would serve nobody.
//
// Restoring is not here either, and not by omission: a database cannot be
// replaced underneath the process holding it open, and the sessions and users
// a restore brings back are the very ones the request doing it depends on. It
// happens at startup or with the service stopped (see the -restore flag).

// DBFileName is the embedded database inside the data directory.
const DBFileName = "meerkat.db"

// Layout is where an installation keeps its state, as the console shows it in
// the restore procedure. Nothing here is a secret - a path is not one - but the
// last field matters: a snapshot holds the vault ENCRYPTED, so it is only worth
// what the master key's separation is worth.
type Layout struct {
	DataDir string `json:"dataDir"`
	DBFile  string `json:"dbFile"`
	// KeyFile is the master key's path, "" when it comes from the environment.
	KeyFile string `json:"keyFile,omitempty"`
	// KeyFromEnv says the key is supplied by MEERKAT_VAULT_KEY and never
	// touches this directory - the safer setup, and one the operator should
	// know applies before they copy a snapshot anywhere.
	KeyFromEnv bool `json:"keyFromEnv"`
}

// Where reports the layout of the running installation.
func (s *Store) Where() Layout {
	l := Layout{
		DataDir: s.dataDir,
		DBFile:  filepath.Join(s.dataDir, DBFileName),
	}
	if os.Getenv("MEERKAT_VAULT_KEY") != "" {
		l.KeyFromEnv = true
		return l
	}
	l.KeyFile = filepath.Join(s.dataDir, vault.KeyFileName)
	return l
}

// Snapshot writes a coherent copy of the database to dest and returns its size.
//
// VACUUM INTO does the work: SQLite builds a fresh, compact, fully consistent
// file from a read transaction, so the result never carries a half-written page
// and needs no companion WAL. It also refuses to overwrite, which is why dest
// must not exist.
func (s *Store) Snapshot(ctx context.Context, dest string) (int64, error) {
	if _, err := os.Stat(dest); err == nil {
		return 0, fmt.Errorf("store: %s already exists: a snapshot never overwrites", dest)
	}
	if _, err := s.db.ExecContext(ctx, `VACUUM INTO ?`, dest); err != nil {
		return 0, fmt.Errorf("store: snapshot to %s: %w", dest, err)
	}
	info, err := os.Stat(dest)
	if err != nil {
		return 0, fmt.Errorf("store: snapshot to %s: %w", dest, err)
	}
	return info.Size(), nil
}
