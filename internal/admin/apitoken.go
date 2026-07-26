package admin

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/softwarity/meerkat/internal/store"
)

// Control-plane API tokens (foundation for headless management — a CLI or an
// MCP server driving Meerkat, PLANNED). A control-plane token authenticates its
// owner on the ADMIN port only (the plane isolation lives in session.Resolve),
// so it carries no tenant/group context. Minting is root-only: the token acts
// with the owner's capabilities, and only root should hand out control-plane
// access. Only the token HASH is stored; the clear value is shown once.
func (a *API) registerAdminTokens(mux *http.ServeMux) {
	mux.Handle("GET /api/admin-tokens", a.rootOnly(a.listAdminTokens))
	mux.Handle("POST /api/admin-tokens", a.rootOnly(a.createAdminToken))
	mux.Handle("DELETE /api/admin-tokens/{id}", a.rootOnly(a.revokeAdminToken))
	mux.Handle("POST /api/admin-tokens/{id}/toggle", a.rootOnly(a.toggleAdminToken))
}

func (a *API) listAdminTokens(w http.ResponseWriter, r *http.Request, actor store.User) {
	tokens, err := a.st.ListAPITokens(r.Context(), actor.ID, store.PlaneAdmin)
	if err != nil {
		a.internal(w, err)
		return
	}
	if tokens == nil {
		tokens = []store.APIToken{}
	}
	writeJSON(w, http.StatusOK, tokens)
}

func (a *API) createAdminToken(w http.ResponseWriter, r *http.Request, actor store.User) {
	var body struct {
		Name string `json:"name"`
		Days int    `json:"days"` // 0 = never expires
	}
	if err := decodeStrict(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request: "+err.Error())
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		writeErr(w, http.StatusUnprocessableEntity, "token name is required")
		return
	}
	if len(name) > 60 {
		name = name[:60]
	}
	var expiresAt int64
	if body.Days > 0 {
		expiresAt = time.Now().Add(time.Duration(body.Days) * 24 * time.Hour).Unix()
	}
	secret, hash, prefix, err := mintToken()
	if err != nil {
		a.internal(w, err)
		return
	}
	id := newID()
	if err := a.st.AddAPIToken(r.Context(), id, actor.ID, name, hash, prefix, store.PlaneAdmin, "", "", expiresAt); err != nil {
		a.internal(w, err)
		return
	}
	a.auditEvent(r.Context(), actor, "token.create", "token", id, name, "", "control-plane token")
	// The clear value travels exactly once, here.
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": id, "name": name, "prefix": prefix, "token": secret, "expiresAt": expiresAt,
	})
}

func (a *API) revokeAdminToken(w http.ResponseWriter, r *http.Request, actor store.User) {
	id := r.PathValue("id")
	name := adminTokenName(a, r, actor.ID, id) // capture before deletion
	existed, err := a.st.RevokeAPIToken(r.Context(), actor.ID, id)
	if err != nil {
		a.internal(w, err)
		return
	}
	if !existed {
		writeErr(w, http.StatusNotFound, "token not found")
		return
	}
	a.auditEvent(r.Context(), actor, "token.revoke", "token", id, name, "", "")
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) toggleAdminToken(w http.ResponseWriter, r *http.Request, actor store.User) {
	id := r.PathValue("id")
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeStrict(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request: "+err.Error())
		return
	}
	existed, err := a.st.SetAPITokenEnabled(r.Context(), actor.ID, id, body.Enabled)
	if err != nil {
		a.internal(w, err)
		return
	}
	if !existed {
		writeErr(w, http.StatusNotFound, "token not found")
		return
	}
	verb := "token.disable"
	if body.Enabled {
		verb = "token.enable"
	}
	a.auditEvent(r.Context(), actor, verb, "token", id, adminTokenName(a, r, actor.ID, id), "", "")
	w.WriteHeader(http.StatusNoContent)
}

// adminTokenName resolves a token's display name (best-effort) for the audit.
func adminTokenName(a *API, r *http.Request, userID, id string) string {
	tokens, err := a.st.ListAPITokens(r.Context(), userID, store.PlaneAdmin)
	if err != nil {
		return ""
	}
	for _, t := range tokens {
		if t.ID == id {
			return t.Name
		}
	}
	return ""
}

// mintToken generates a fresh "mk_…" secret and returns its clear value, its
// hash (sha256 hex, matching session.hashToken), and a display prefix.
func mintToken() (secret, hash, prefix string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", "", err
	}
	secret = "mk_" + base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(secret))
	hash = hex.EncodeToString(sum[:])
	prefix = secret[:12]
	return secret, hash, prefix, nil
}
