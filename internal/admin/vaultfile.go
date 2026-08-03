package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/softwarity/meerkat/internal/store"
	"github.com/softwarity/meerkat/internal/vault"
)

// The vault as an encrypted file (VAULT-03).
//
// The counterpart of the configuration export, and its opposite in every way. A
// configuration is public and carries no secret; this carries nothing else. It
// is encrypted under a passphrase the gateway never stores, it is not something
// to version, and it exists to bootstrap an environment or move a gateway, then
// to be deleted.
//
// Like the rest of the vault surface it is TRANSVERSE: the caller only ever
// exports and imports the scopes their capabilities cover, so a tenant admin
// moving their own entries cannot walk off with the infrastructure's.

// vaultFileRequest carries the passphrase, and on the way in the file too.
type vaultFileRequest struct {
	Passphrase string `json:"passphrase"`
	// File is the whole encrypted document, as it was read from disk.
	File json.RawMessage `json:"file,omitempty"`
	// Overwrite replaces an entry that already holds a DIFFERENT value.
	// Off by default: the entry in place may be what something else resolves,
	// and losing it would break that silently.
	Overwrite bool `json:"overwrite"`
}

// vaultImportReport is what the console shows afterwards. Names only: this
// endpoint answers about secrets, so it says what happened to them and never
// what they are.
type vaultImportReport struct {
	Created   []string `json:"created"`
	Filled    []string `json:"filled"`
	Replaced  []string `json:"replaced"`
	Unchanged []string `json:"unchanged"`
	// Conflicts already hold a different value and were LEFT ALONE.
	Conflicts []string `json:"conflicts"`
	// Skipped belong to a scope this caller does not administer, or to an
	// organisation that does not exist here.
	Skipped []string `json:"skipped"`
}

func (a *API) registerVaultFile(mux *http.ServeMux) {
	mux.Handle("POST /api/vault/export", a.authed(a.exportVault))
	mux.Handle("POST /api/vault/import", a.authed(a.importVault))
}

// exportVault seals every entry the caller administers under their passphrase.
// A POST because a passphrase has no business being in a URL, where it would
// land in access logs and browser history.
func (a *API) exportVault(w http.ResponseWriter, r *http.Request, actor store.User) {
	var req vaultFileRequest
	if err := decodeStrict(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request: "+err.Error())
		return
	}
	if err := vault.CheckPassphrase(req.Passphrase); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	scopes := a.vaultScopes(r.Context(), actor)
	entries, err := a.st.ExportVaultEntries(r.Context(), scopes)
	if err != nil {
		a.internal(w, err)
		return
	}
	if len(entries) == 0 {
		writeErr(w, http.StatusUnprocessableEntity,
			"there is nothing to export: no entry of yours holds a value")
		return
	}
	file, err := vault.SealVault(entries, req.Passphrase)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	body, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		a.internal(w, err)
		return
	}
	// The COUNT is audited, never the names: an audit trail is read by more
	// people than the vault is.
	a.auditEvent(r.Context(), actor, "vault.export", "vault", "", "", "",
		fmt.Sprintf("%d entries, encrypted", len(entries)))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="meerkat-vault.json"`)
	_, _ = w.Write(body)
}

// importVault opens the file and writes what the caller may write.
func (a *API) importVault(w http.ResponseWriter, r *http.Request, actor store.User) {
	var req vaultFileRequest
	if err := decodeStrict(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request: "+err.Error())
		return
	}
	var file vault.PortableFile
	if err := json.Unmarshal(req.File, &file); err != nil {
		writeErr(w, http.StatusUnprocessableEntity,
			"this file is not a Meerkat vault export: "+err.Error())
		return
	}
	entries, err := vault.OpenVault(&file, req.Passphrase)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	report, err := a.applyVaultEntries(r.Context(), entries, a.vaultScopes(r.Context(), actor), req.Overwrite)
	if err != nil {
		a.internal(w, err)
		return
	}
	a.auditEvent(r.Context(), actor, "vault.import", "vault", "", "", "",
		fmt.Sprintf("%d created, %d filled, %d replaced, %d left alone",
			len(report.Created), len(report.Filled), len(report.Replaced),
			len(report.Conflicts)+len(report.Skipped)))
	// New entries change what an already-written $name resolves to, and a route
	// that was inert because its reference held nothing can now serve.
	if err := a.router.Reload(r.Context()); err != nil {
		a.internal(w, fmt.Errorf("imported, but the routing table could not be reloaded: %w", err))
		return
	}
	writeJSON(w, http.StatusOK, report)
}

// applyVaultEntries writes the decrypted entries, deciding one at a time.
//
// The rule that matters: an entry already holding a DIFFERENT value is left
// alone unless asked. Importing a vault over a running gateway is exactly when
// one is least able to tell which of two values is the right one, so the safe
// answer is to change nothing and say so.
//
// An entry holding NOTHING is a different story: it is a hole a configuration
// import reserved, and filling it is the whole point.
func (a *API) applyVaultEntries(
	ctx context.Context, entries []vault.PortableEntry, allowed []string, overwrite bool,
) (*vaultImportReport, error) {
	report := &vaultImportReport{
		Created: []string{}, Filled: []string{}, Replaced: []string{},
		Unchanged: []string{}, Conflicts: []string{}, Skipped: []string{},
	}
	for _, e := range entries {
		label := e.Name
		if e.Scope != vault.ScopeInfra {
			label = e.Scope + "/" + e.Name
		}
		if !slices.Contains(allowed, e.Scope) {
			report.Skipped = append(report.Skipped, label)
			continue
		}
		if tenant := vault.TenantOf(e.Scope); tenant != "" {
			if _, err := a.st.GetTenant(ctx, tenant); err != nil {
				report.Skipped = append(report.Skipped, label)
				continue
			}
		}
		before, err := a.st.GetVaultEntry(ctx, e.Scope, e.Name)
		switch {
		case err != nil: // free name
			report.Created = append(report.Created, label)
		case before.Value == e.Value:
			report.Unchanged = append(report.Unchanged, label)
			continue
		case before.Value == "": // reserved by a configuration import
			report.Filled = append(report.Filled, label)
		case !overwrite:
			report.Conflicts = append(report.Conflicts, label)
			continue
		default:
			report.Replaced = append(report.Replaced, label)
		}
		if err := a.st.SaveVaultEntry(ctx, vault.Entry{
			Name: e.Name, Kind: e.Kind, Scope: e.Scope, Value: e.Value,
			Description: strings.TrimSpace(e.Description), Tags: e.Tags,
		}); err != nil {
			return nil, fmt.Errorf("vault entry %s: %w", label, err)
		}
	}
	return report, nil
}
