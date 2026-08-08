package admin

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/softwarity/meerkat/internal/store"
)

// Snapshots (STORE-05) - root only.
//
// What the gateway owes an operator is a COHERENT copy taken while it runs;
// everything else about backups belongs to tools that already do it well. What
// it deliberately does NOT offer is a restore button: a database cannot be
// swapped underneath the process holding it open, the sessions and users a
// restore brings back are the ones the request doing it depends on, and
// accepting an arbitrary database as trusted state would turn one borrowed
// admin session into permanent control of the gateway. Restoring happens with
// the service stopped, and the console prints the exact commands.

func (a *API) registerBackup(mux *http.ServeMux) {
	mux.Handle("GET /api/backup", a.rootOnly(a.downloadSnapshot))
	mux.Handle("GET /api/backup/info", a.rootOnly(a.backupInfo))
}

// backupInfo tells the console where this installation keeps its state, so the
// restore procedure it prints carries the REAL paths and can be pasted as is.
func (a *API) backupInfo(w http.ResponseWriter, _ *http.Request, _ store.User) {
	layout := a.st.Where()
	out := map[string]any{
		"dataDir":    layout.DataDir,
		"dbFile":     layout.DBFile,
		"keyFile":    layout.KeyFile,
		"keyFromEnv": layout.KeyFromEnv,
	}
	if info, err := os.Stat(layout.DBFile); err == nil {
		out["size"] = info.Size()
	}
	writeJSON(w, http.StatusOK, out)
}

// downloadSnapshot serves a coherent copy of the database.
//
// Written to a temporary file first rather than streamed: VACUUM INTO needs a
// destination on disk, and finishing the copy BEFORE answering means a failure
// is an error the admin reads, not a truncated download they discover months
// later when they try to use it.
func (a *API) downloadSnapshot(w http.ResponseWriter, r *http.Request, actor store.User) {
	dir, err := os.MkdirTemp("", "meerkat-snapshot-")
	if err != nil {
		a.internal(w, fmt.Errorf("snapshot: %w", err))
		return
	}
	defer func() { _ = os.RemoveAll(dir) }()

	path := filepath.Join(dir, store.DBFileName)
	size, err := a.st.Snapshot(r.Context(), path)
	if err != nil {
		a.internal(w, err)
		return
	}
	f, err := os.Open(path) //nolint:gosec // a path this function just built
	if err != nil {
		a.internal(w, fmt.Errorf("snapshot: %w", err))
		return
	}
	defer func() { _ = f.Close() }()

	// The date is in the name because a snapshot without one is unusable in a
	// directory of snapshots.
	name := "meerkat-" + time.Now().UTC().Format("2006-01-02-1504") + ".db"
	a.auditEvent(r.Context(), actor, "backup.snapshot", "backup", "", name, "",
		fmt.Sprintf("%d bytes", size))
	w.Header().Set("Content-Type", "application/vnd.sqlite3")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	if _, err := io.Copy(w, f); err != nil {
		// The headers are already on the wire: there is no error left to send,
		// only one to record.
		slog.Error("snapshot download interrupted", "err", err)
	}
}
