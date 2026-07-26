package admin

import (
	"errors"
	"net/http"
	"strings"

	"github.com/softwarity/meerkat/internal/auth"
	"github.com/softwarity/meerkat/internal/store"
)

// Theme administration (THEME-04): several saved themes, one active; the
// editor previews any of them as the REAL login page before activating.
// Root scope — the theme is a global setting.
func (a *API) registerThemes(mux *http.ServeMux) {
	mux.Handle("GET /api/themes", a.gatewayAdmin(a.listThemes))
	mux.Handle("GET /api/themes/presets", a.gatewayAdmin(a.listPresets))
	mux.Handle("POST /api/themes", a.gatewayAdmin(a.createTheme))
	mux.Handle("PUT /api/themes/{id}", a.gatewayAdmin(a.updateTheme))
	mux.Handle("DELETE /api/themes/{id}", a.gatewayAdmin(a.deleteTheme))
	mux.Handle("POST /api/themes/{id}/activate", a.gatewayAdmin(a.activateTheme))
	mux.Handle("GET /api/themes/{id}/preview", a.gatewayAdmin(a.previewTheme))
	mux.Handle("GET /api/branding", a.gatewayAdmin(a.getBranding))
	mux.Handle("PUT /api/branding", a.gatewayAdmin(a.putBranding))
}

// Branding (THEME-02) is GLOBAL — one application identity whatever theme is
// active — but it is edited on the same Theme screen.
func (a *API) getBranding(w http.ResponseWriter, r *http.Request, _ store.User) {
	b := store.DefaultBranding()
	if err := a.st.GetSetting(r.Context(), store.SettingBranding, &b); err != nil {
		b = store.DefaultBranding()
	}
	writeJSON(w, http.StatusOK, b)
}

func (a *API) putBranding(w http.ResponseWriter, r *http.Request, actor store.User) {
	old := store.DefaultBranding()
	_ = a.st.GetSetting(r.Context(), store.SettingBranding, &old)
	var b store.Branding
	if err := decodeStrict(r, &b); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed branding: "+err.Error())
		return
	}
	if err := store.SanitizeBranding(&b); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err := a.st.SetSetting(r.Context(), store.SettingBranding, b); err != nil {
		a.internal(w, err)
		return
	}
	a.auditUpdate(r.Context(), actor, "theme.branding", "theme", "", "branding", "", old, b)
	writeJSON(w, http.StatusOK, b)
}

// listPresets returns the built-in starting palettes (THEME-04) — the console
// offers them under the "+" button so a deleted preset can be recreated.
func (a *API) listPresets(w http.ResponseWriter, _ *http.Request, _ store.User) {
	writeJSON(w, http.StatusOK, store.PresetThemes())
}

func (a *API) listThemes(w http.ResponseWriter, r *http.Request, _ store.User) {
	themes, err := a.st.ListThemes(r.Context())
	if err != nil {
		a.internal(w, err)
		return
	}
	if themes == nil {
		themes = []store.Theme{}
	}
	writeJSON(w, http.StatusOK, themes)
}

func (a *API) createTheme(w http.ResponseWriter, r *http.Request, actor store.User) {
	var t store.Theme
	if err := decodeStrict(r, &t); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed theme: "+err.Error())
		return
	}
	t.Name = strings.TrimSpace(t.Name)
	if t.Name == "" {
		writeErr(w, http.StatusUnprocessableEntity, "theme name is required")
		return
	}
	t.ID = newID()
	t.Active = false // activation is an explicit, separate act
	if len(t.Dark) == 0 && len(t.Light) == 0 {
		base := store.DefaultTheme()
		t.Dark, t.Light = base.Dark, base.Light
	}
	if err := a.st.SaveTheme(r.Context(), t); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	saved, err := a.st.GetTheme(r.Context(), t.ID)
	if err != nil {
		a.internal(w, err)
		return
	}
	a.auditEvent(r.Context(), actor, "theme.create", "theme", saved.ID, saved.Name, "", "")
	writeJSON(w, http.StatusCreated, saved)
}

func (a *API) updateTheme(w http.ResponseWriter, r *http.Request, actor store.User) {
	var t store.Theme
	if err := decodeStrict(r, &t); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed theme: "+err.Error())
		return
	}
	t.ID = r.PathValue("id")
	current, err := a.st.GetTheme(r.Context(), t.ID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "theme not found")
		return
	}
	t.Active = current.Active // active-ness only changes through /activate
	t.Name = strings.TrimSpace(t.Name)
	if t.Name == "" {
		writeErr(w, http.StatusUnprocessableEntity, "theme name is required")
		return
	}
	if err := a.st.SaveTheme(r.Context(), t); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	saved, err := a.st.GetTheme(r.Context(), t.ID)
	if err != nil {
		a.internal(w, err)
		return
	}
	a.auditUpdate(r.Context(), actor, "theme.update", "theme", saved.ID, saved.Name, "", current, saved)
	writeJSON(w, http.StatusOK, saved)
}

func (a *API) deleteTheme(w http.ResponseWriter, r *http.Request, actor store.User) {
	id := r.PathValue("id")
	theme, _ := a.st.GetTheme(r.Context(), id) // capture the name before deletion
	existed, err := a.st.DeleteTheme(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if !existed {
		writeErr(w, http.StatusNotFound, "theme not found")
		return
	}
	a.auditEvent(r.Context(), actor, "theme.delete", "theme", id, theme.Name, "", "")
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) activateTheme(w http.ResponseWriter, r *http.Request, actor store.User) {
	if err := a.st.ActivateTheme(r.Context(), r.PathValue("id")); err != nil {
		if errors.Is(err, store.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "theme not found")
			return
		}
		a.internal(w, err)
		return
	}
	t, err := a.st.GetActiveTheme(r.Context())
	if err != nil {
		a.internal(w, err)
		return
	}
	a.auditEvent(r.Context(), actor, "theme.activate", "theme", t.ID, t.Name, "", "")
	writeJSON(w, http.StatusOK, t)
}

// previewTheme renders the flow-page specimen in the given theme, one scheme
// forced (?scheme=dark|light) — the console's editor iframes it twice.
func (a *API) previewTheme(w http.ResponseWriter, r *http.Request, _ store.User) {
	t, err := a.st.GetTheme(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "theme not found")
		return
	}
	b := store.DefaultBranding()
	if err := a.st.GetSetting(r.Context(), store.SettingBranding, &b); err != nil {
		b = store.DefaultBranding()
	}
	auth.WriteThemePreview(w, t, b, r.URL.Query().Get("scheme"))
}
