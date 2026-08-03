package auth

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/softwarity/meerkat/internal/store"
)

// Issue reports on the DATA plane (ISSUE-01): the injected user-button panel
// posts here. The whole surface plays dead while the Others-screen switch is
// off (ISSUE-04), and only a signed-in user may file - the report is stamped
// with their identity and CURRENT tenant, never trusted from the body.

// issueMaxBody caps a submission: a bounded screenshot data URI (~1.5 MiB
// binary, ~2 MB base64) plus the console tail and the description.
const issueMaxBody = 2 << 20

// registerIssues mounts the submission endpoint next to the user button's.
func (h *Handler) registerIssues(mux *http.ServeMux) {
	mux.HandleFunc("POST /meerkat/issues", h.postIssue)
}

// issuesEnabled reads the Others-screen switch (missing = off).
func (h *Handler) issuesEnabled(r *http.Request) bool {
	var enabled bool
	_ = h.st.GetSetting(r.Context(), store.SettingIssuesEnabled, &enabled)
	return enabled
}

// issueSubmission is what the panel sends; everything but the description is
// context captured client-side, taken as-is within bounds.
type issueSubmission struct {
	Description string               `json:"description"`
	URL         string               `json:"url"`
	UserAgent   string               `json:"userAgent"`
	Viewport    string               `json:"viewport"`
	Screen      string               `json:"screen"`
	DPR         float64              `json:"dpr"`
	Language    string               `json:"language"`
	Console     []store.ConsoleEntry `json:"console"`
	Screenshot  string               `json:"screenshot"`
}

func issueErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// clip bounds a free-text context field without failing the report over it.
func clip(s string, limit int) string {
	s = strings.TrimSpace(s)
	if len(s) > limit {
		return s[:limit]
	}
	return s
}

func (h *Handler) postIssue(w http.ResponseWriter, r *http.Request) {
	if !h.issuesEnabled(r) {
		http.NotFound(w, r)
		return
	}
	sess, err := h.sm.Resolve(r.Context(), r)
	if err != nil || sess.Pending != "" {
		issueErr(w, http.StatusUnauthorized, "sign in to report an issue")
		return
	}
	u, err := h.st.GetUserByID(r.Context(), sess.UserID)
	if err != nil || !u.Enabled {
		issueErr(w, http.StatusUnauthorized, "sign in to report an issue")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, issueMaxBody)
	var body issueSubmission
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			issueErr(w, http.StatusRequestEntityTooLarge, "the report is too large: keep it under 2 MiB")
			return
		}
		issueErr(w, http.StatusBadRequest, "malformed report: "+err.Error())
		return
	}
	description := clip(body.Description, 4000)
	if description == "" {
		issueErr(w, http.StatusUnprocessableEntity, "a description is required")
		return
	}
	if err := store.SanitizeScreenshot(body.Screenshot); err != nil {
		issueErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if len(body.Console) > 200 {
		body.Console = body.Console[len(body.Console)-200:]
	}
	for i, e := range body.Console {
		body.Console[i] = store.ConsoleEntry{Level: clip(e.Level, 10), At: clip(e.At, 40), Text: clip(e.Text, 600)}
	}
	filed, err := h.st.AddIssue(r.Context(), store.Issue{
		ReporterID: u.ID, ReporterName: u.Username, TenantID: sess.TenantID,
		Description: description,
		URL:         clip(body.URL, 2000), UserAgent: clip(body.UserAgent, 400),
		Viewport: clip(body.Viewport, 20), Screen: clip(body.Screen, 20),
		DPR: body.DPR, Language: clip(body.Language, 20),
		ConsoleLog: body.Console, Screenshot: body.Screenshot,
	})
	if err != nil {
		slog.Error("issue report failed", "user", u.Username, "err", err)
		issueErr(w, http.StatusInternalServerError, "the report could not be saved")
		return
	}
	slog.Info("issue reported", "id", filed.ID, "user", u.Username, "tenant", sess.TenantID,
		"url", filed.URL, "screenshot", filed.HasScreenshot)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"id": filed.ID})
}
