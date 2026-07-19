// Package auth serves Meerkat's own authentication pages and endpoints. The
// pages are deliberately vanilla HTML (PAGE-01): light, framework-free, and
// meant to become integrator-customizable (theme, logo, layouts — PAGE-02/03).
package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/softwarity/meerkat/internal/session"
	"github.com/softwarity/meerkat/internal/store"
)

var loginPage = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sign in · Meerkat</title>
  <style>
    :root { color-scheme: light dark; }
    body { font-family: system-ui, sans-serif; display: grid; place-items: center;
           min-height: 100vh; margin: 0; background: #10131a; color: #e6edf3; }
    form { background: #161b22; border: 1px solid #30363d; border-radius: 10px;
           padding: 32px; width: min(340px, 90vw); display: grid; gap: 14px; }
    h1 { font-size: 1.2rem; margin: 0 0 6px; }
    label { display: grid; gap: 4px; font-size: .85rem; color: #8b949e; }
    input { padding: 9px 10px; border-radius: 6px; border: 1px solid #30363d;
            background: #0d1117; color: inherit; font-size: 1rem; }
    button { padding: 10px; border: 0; border-radius: 6px; background: #7c5cff;
             color: white; font-size: 1rem; cursor: pointer; }
    .error { color: #f85149; font-size: .85rem; margin: 0; }
    .brand { color: #8b949e; font-size: .75rem; text-align: center; margin-top: 4px; }
  </style>
</head>
<body>
  <form method="post" action="login">
    <h1>Sign in</h1>
    {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
    <label>Username <input name="username" autocomplete="username" autofocus required></label>
    <label>Password <input name="password" type="password" autocomplete="current-password" required></label>
    <input type="hidden" name="next" value="{{.Next}}">
    <button type="submit">Sign in</button>
    <p class="brand">guarded by meerkat</p>
  </form>
</body>
</html>`))

// Handler serves /login and /logout.
type Handler struct {
	st *store.Store
	sm *session.Manager
}

// New builds the auth handler.
func New(st *store.Store, sm *session.Manager) *Handler {
	return &Handler{st: st, sm: sm}
}

// Register mounts the auth endpoints on mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /login", h.showLogin)
	mux.HandleFunc("POST /login", h.doLogin)
	mux.HandleFunc("POST /logout", h.doLogout)
}

func (h *Handler) showLogin(w http.ResponseWriter, r *http.Request) {
	h.render(w, r.URL.Query().Get("next"), "", http.StatusOK)
}

func (h *Handler) doLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.PostFormValue("username"))
	password := r.PostFormValue("password")
	next := r.PostFormValue("next")

	user, err := h.st.GetUserByUsername(r.Context(), username)
	// Same code path and same message whether the user is unknown or the
	// password is wrong (SEC-09: no account enumeration).
	if err != nil {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password)) // equalize timing
		h.render(w, next, "Invalid username or password.", http.StatusUnauthorized)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		h.render(w, next, "Invalid username or password.", http.StatusUnauthorized)
		return
	}
	if _, err := h.sm.Issue(r.Context(), w, r, user.ID); err != nil {
		slog.Error("session issue failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, safeNext(next), http.StatusSeeOther)
}

func (h *Handler) doLogout(w http.ResponseWriter, r *http.Request) {
	if err := h.sm.Destroy(r.Context(), w, r); err != nil {
		slog.Error("logout failed", "err", err)
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (h *Handler) render(w http.ResponseWriter, next, errMsg string, status int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = loginPage.Execute(w, struct{ Next, Error string }{Next: next, Error: errMsg})
}

// dummyHash keeps the failure path constant-time-ish for unknown users.
var dummyHash = func() []byte {
	h, _ := bcrypt.GenerateFromPassword([]byte("meerkat-dummy"), bcrypt.DefaultCost)
	return h
}()

// safeNext only allows same-site relative redirects — never an absolute URL
// (open-redirect guard).
func safeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		return "/"
	}
	if u, err := url.Parse(next); err != nil || u.Host != "" || u.Scheme != "" {
		return "/"
	}
	return next
}

// SeedAdmin creates the first root account when no user exists. The password
// comes from MEERKAT_ADMIN_PASSWORD, or is generated and printed once — the
// proper first-start setup page (LIFE-01) will replace this.
func SeedAdmin(ctx context.Context, st *store.Store) error {
	n, err := st.CountUsers(ctx)
	if err != nil || n > 0 {
		return err
	}
	password := os.Getenv("MEERKAT_ADMIN_PASSWORD")
	generated := password == ""
	if generated {
		raw := make([]byte, 12)
		if _, err := rand.Read(raw); err != nil {
			return err
		}
		password = base64.RawURLEncoding.EncodeToString(raw)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if err := st.CreateUser(ctx, store.User{ID: "admin", Username: "admin", PasswordHash: string(hash), Root: true}); err != nil {
		return err
	}
	if generated {
		slog.Warn("first start: admin account created — change this password",
			"username", "admin", "password", password)
	} else {
		slog.Info("first start: admin account created from MEERKAT_ADMIN_PASSWORD", "username", "admin")
	}
	return nil
}
