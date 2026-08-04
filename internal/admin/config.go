package admin

import (
	"fmt"
	"io"
	"net/http"

	"github.com/softwarity/meerkat/internal/config"
	"github.com/softwarity/meerkat/internal/store"
)

// Import and export of the whole configuration (CFG-05).
//
// ROOT only, and not out of caution: a document crosses both planes at once —
// routes belong to infra, authorities and settings to the application — so
// whoever moves one has to administer both. An infra admin importing a file
// that rewrites the sign-in authorities would be a way around RBAC-05, not a
// convenience.

// maxConfigBytes bounds an uploaded document. A theme carries its logo as a
// data URI, so a legitimate file is not tiny; nothing legitimate is this big.
const maxConfigBytes = 8 << 20

func (a *API) registerConfig(mux *http.ServeMux) {
	mux.Handle("GET /api/config/export", a.rootOnly(a.exportConfig))
	mux.Handle("GET /api/config/report", a.rootOnly(a.exportReport))
	mux.Handle("POST /api/config/preview", a.rootOnly(a.previewConfig))
	mux.Handle("POST /api/config/import", a.rootOnly(a.importConfig))
}

// exportConfig serves the configuration, as plain YAML or as a package.
//
// Plain bytes rather than a JSON envelope, so `curl -o meerkat.yaml` is the
// whole story for anyone versioning their exports. Asking for ?format=zip gets
// the YAML with its images beside it instead of inline — both forms are
// self-contained, which is what stops either from ever naming a picture it does
// not carry.
func (a *API) exportConfig(w http.ResponseWriter, r *http.Request, actor store.User) {
	doc, literals, err := config.Export(r.Context(), a.st)
	if err != nil {
		a.internal(w, err)
		return
	}
	name, mime := "meerkat-config.yaml", "application/yaml; charset=utf-8"
	var file []byte
	if r.URL.Query().Get("format") == "zip" {
		if !config.HasImage(doc) {
			writeErr(w, http.StatusUnprocessableEntity,
				"this configuration carries no image: download it as a plain file")
			return
		}
		if file, err = config.MarshalBundle(doc); err != nil {
			a.internal(w, err)
			return
		}
		name, mime = "meerkat-config.zip", "application/zip"
	} else if file, err = config.Marshal(doc); err != nil {
		a.internal(w, err)
		return
	}
	a.auditEvent(r.Context(), actor, "config.export", "config", "", name, "",
		fmt.Sprintf("%d bytes, %d secrets left behind", len(file), len(literals)))
	w.Header().Set("Content-Type", mime)
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	_, _ = w.Write(file)
}

// exportReport says what an export will NOT contain, before it is downloaded:
// the secrets that are literals here and therefore stay behind. The console
// shows it next to the download, which is the moment the admin can still act
// on it (VAULT-05 moves a literal into the vault in one click).
func (a *API) exportReport(w http.ResponseWriter, r *http.Request, _ store.User) {
	doc, literals, err := config.Export(r.Context(), a.st)
	if err != nil {
		a.internal(w, err)
		return
	}
	refs, err := config.Refs(doc)
	if err != nil {
		a.internal(w, err)
		return
	}
	if literals == nil {
		literals = []config.Literal{}
	}
	if refs == nil {
		refs = []string{}
	}
	contents := config.Inventory(doc)
	if contents == nil {
		contents = []config.Section{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"contents": contents,
		"literals": literals,
		"refs":     refs,
	})
}

// previewConfig reports what importing the posted file would do, and changes
// nothing. It is the screen where the missing secrets are asked for: an admin
// has the context now, and will not in a week.
func (a *API) previewConfig(w http.ResponseWriter, r *http.Request, _ store.User) {
	doc, ok := a.readDocument(w, r)
	if !ok {
		return
	}
	plan, err := config.Preview(r.Context(), a.st, doc, prune(r))
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, plan)
}

// importConfig applies the posted file and reports what it did.
func (a *API) importConfig(w http.ResponseWriter, r *http.Request, actor store.User) {
	doc, ok := a.readDocument(w, r)
	if !ok {
		return
	}
	plan, err := config.Apply(r.Context(), a.st, doc, prune(r))
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	a.auditEvent(r.Context(), actor, "config.import", "config", "", "", "", summarise(plan))
	// Saving IS applying, here as everywhere else. A reload that fails means a
	// stored route no longer compiles: say so instead of reporting a clean
	// import — the previous snapshot keeps serving in the meantime.
	if err := a.router.Reload(r.Context()); err != nil {
		a.internal(w, fmt.Errorf("imported, but the routing table could not be reloaded: %w", err))
		return
	}
	writeJSON(w, http.StatusOK, plan)
}

// readDocument reads the request body as a configuration file. YAML or JSON,
// since one parser reads both.
func (a *API) readDocument(w http.ResponseWriter, r *http.Request) (*config.Document, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxConfigBytes+1))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "the file could not be read: "+err.Error())
		return nil, false
	}
	if len(body) > maxConfigBytes {
		writeErr(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("a configuration file is limited to %d MB", maxConfigBytes>>20))
		return nil, false
	}
	// The format is decided by the BYTES: what an admin uploads has been
	// through a browser, a chat and a download folder, and the extension is the
	// first thing to be lost.
	read := config.Unmarshal
	if config.IsBundle(body) {
		read = config.UnmarshalBundle
	}
	doc, err := read(body)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return nil, false
	}
	return doc, true
}

// prune reads the opt-in that removes what the file does not mention. Absent
// means merge, which is the answer that cannot destroy anything.
func prune(r *http.Request) bool { return r.URL.Query().Get("prune") == "true" }

// summarise turns a plan into the one line the audit trail keeps.
func summarise(plan *config.Plan) string {
	counts := map[string]int{}
	for _, c := range plan.Changes {
		counts[c.Action]++
	}
	line := fmt.Sprintf("%d added, %d updated, %d removed, %d unchanged",
		counts[config.ActionAdd], counts[config.ActionUpdate],
		counts[config.ActionRemove], counts[config.ActionSame])
	if n := len(plan.Missing); n > 0 {
		line += fmt.Sprintf("; %d vault entries reserved empty", n)
	}
	return line
}
