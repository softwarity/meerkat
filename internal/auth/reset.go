package auth

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/softwarity/meerkat/internal/mail"
	"github.com/softwarity/meerkat/internal/store"
)

// Forgot password (AUTH-21): a one-shot mailed link, 1 hour, that lets the
// user set a new password. Anti-enumeration throughout (the outcome page
// never says whether the address exists), rate-limited per IP, and a
// successful reset REVOKES every session of the account — an intruder's
// stolen session dies with the old password.

const resetPurpose = "reset"

var (
	forgotPage     = flowPage("forgot-password", forgotBody)
	forgotSentPage = flowPage("forgot-sent", forgotSentBody)
	resetPage      = flowPage("reset-password", resetBody)
	resetDonePage  = flowPage("reset-done", resetDoneBody)
)

type forgotData struct {
	flowChrome
	Error string
}

const forgotBody = `    <form method="post" action="/forgot-password">
      <p class="lead">{{.T.forgotLead}}</p>
      {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
      <p class="hint">{{.T.forgotHint}}</p>
      <label class="field">
        <span>{{.T.email}}</span>
        <input name="email" type="email" autocomplete="email" autofocus required>
      </label>
      <button type="submit">{{.T.forgotCta}}</button>
    </form>
    <p class="back"><a href="/login">{{.T.backToLogin}}</a></p>
`

const forgotSentBody = `    <form onsubmit="return false">
      <p class="lead">{{.T.registerSentLead}}</p>
      <p class="hint">{{.T.forgotSentHint}}</p>
    </form>
    <p class="back"><a href="/login">{{.T.backToLogin}}</a></p>
`

type resetData struct {
	flowChrome
	Token string
	Error string
}

const resetBody = `    <form method="post" action="/reset-password">
      <p class="lead">{{.T.resetLead}}</p>
      {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
      <label class="field">
        <span>{{.T.newPassword}}</span>
        <input name="password" type="password" autocomplete="new-password" autofocus required minlength="8">
      </label>
      <label class="field">
        <span>{{.T.confirmPassword}}</span>
        <input name="confirm" type="password" autocomplete="new-password" required minlength="8">
      </label>
      <input type="hidden" name="token" value="{{.Token}}">
      <button type="submit">{{.T.resetCta}}</button>
    </form>
`

const resetDoneBody = `    <form onsubmit="return false">
      <p class="lead">{{.T.resetDoneLead}}</p>
      <p class="hint">{{.T.resetDoneHint}}</p>
      <a class="choice" style="text-decoration:none" href="/login">{{.T.signIn}}</a>
    </form>
`

func (h *Handler) showForgot(w http.ResponseWriter, r *http.Request) {
	if !h.forgotOpen(r) {
		http.NotFound(w, r)
		return
	}
	writeFlow(w, forgotPage, forgotData{flowChrome: h.flowData(r, "titleForgot")}, http.StatusOK)
}

// forgotOpen: the reset flow needs working outbound mail, and a local password
// that still opens something (AUTH-24). Resetting a password the data plane
// refuses is a journey that succeeds at every step and helps nobody.
//
// Under "admins only" it stays open: an administrator keeps a password worth
// resetting. WHO actually receives a mail is decided in doForgot, per account.
func (h *Handler) forgotOpen(r *http.Request) bool {
	return h.Mailer != nil && h.st.GetSMTP(r.Context()).Configured() &&
		(h.adminPlane || h.st.GetPasswordLoginPolicy(r.Context()).Mode != store.PasswordLoginNobody)
}

func (h *Handler) doForgot(w http.ResponseWriter, r *http.Request) {
	if !h.forgotOpen(r) {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	email := strings.TrimSpace(r.PostFormValue("email"))
	if email == "" {
		writeFlow(w, forgotPage, forgotData{
			flowChrome: h.flowData(r, "titleForgot"), Error: h.tr(r, "errBadEmail"),
		}, http.StatusUnprocessableEntity)
		return
	}
	if !h.registerAllow(clientIP(r)) {
		writeFlow(w, forgotPage, forgotData{
			flowChrome: h.flowData(r, "titleForgot"), Error: h.tr(r, "errTooManyAttempts"),
		}, http.StatusTooManyRequests)
		return
	}
	// Whatever happens next, the SAME outcome page: no address enumeration.
	if userID, err := h.st.UserIDByEmail(r.Context(), email); err == nil {
		// localPasswordAllowed decides per ACCOUNT: under "admins only" the
		// administrators get their mail and the users do not. The page below is
		// the same either way — telling them apart would be an enumeration
		// oracle, and a better one than the address itself.
		if u, err := h.st.GetUserByID(r.Context(), userID); err == nil &&
			u.Enabled && (!u.SelfRegistered || u.EmailVerified) &&
			h.localPasswordAllowed(r.Context(), u) {
			if err := h.sendReset(r, u.ID, u.Email, u.Locale); err != nil {
				slog.Error("reset e-mail failed", "user", u.Username, "err", err)
			}
		}
	}
	writeFlow(w, forgotSentPage, struct{ flowChrome }{h.flowData(r, "titleForgot")}, http.StatusOK)
}

func (h *Handler) sendReset(r *http.Request, userID, email, locale string) error {
	token, err := randToken()
	if err != nil {
		return err
	}
	if err := h.st.PutEmailToken(r.Context(), hashTrust(token), userID, resetPurpose,
		time.Now().Add(time.Hour).Unix()); err != nil {
		return err
	}
	link := h.externalURL(r) + "/reset-password?token=" + token
	if locale == "" {
		locale = prefsOf(r, h.offeredLanguages()).Lang
	}
	t := messagesFor(locale)
	_, brand := h.chrome()
	return h.sendMail(r.Context(), mail.Message{
		To:      []string{email},
		Subject: fmt.Sprintf(t["mailResetSubject"], brand.AppName),
		Text:    fmt.Sprintf(t["mailResetBody"], brand.AppName, link),
		HTML: fmt.Sprintf(`<p>%s</p><p><a href="%s">%s</a></p>`,
			fmt.Sprintf(t["mailResetHTML"], brand.AppName), link, t["mailResetCta"]),
	})
}

// showReset displays the new-password form. The token is only PEEKED here:
// mail scanners prefetch links, a consuming GET would kill them for the
// human. Consumption happens on the POST.
func (h *Handler) showReset(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.NotFound(w, r)
		return
	}
	if _, err := h.st.PeekEmailToken(r.Context(), hashTrust(token), resetPurpose, time.Now().Unix()); err != nil {
		http.Error(w, h.tr(r, "errResetExpired"), http.StatusUnprocessableEntity)
		return
	}
	writeFlow(w, resetPage, resetData{
		flowChrome: h.flowData(r, "titleReset"), Token: token,
	}, http.StatusOK)
}

func (h *Handler) doReset(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	token := r.PostFormValue("token")
	password := r.PostFormValue("password")
	renderErr := func(key string, status int) {
		writeFlow(w, resetPage, resetData{
			flowChrome: h.flowData(r, "titleReset"), Token: token, Error: h.tr(r, key),
		}, status)
	}
	switch {
	case token == "":
		http.NotFound(w, r)
		return
	case len(password) < 8:
		renderErr("errPwTooShort", http.StatusUnprocessableEntity)
		return
	case password != r.PostFormValue("confirm"):
		renderErr("errPwMismatch", http.StatusUnprocessableEntity)
		return
	}
	userID, err := h.st.TakeEmailToken(r.Context(), hashTrust(token), resetPurpose, time.Now().Unix())
	if err != nil {
		http.Error(w, h.tr(r, "errResetExpired"), http.StatusUnprocessableEntity)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := h.st.SetUserPassword(r.Context(), userID, string(hash), false); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, h.tr(r, "errResetExpired"), http.StatusUnprocessableEntity)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// The new password KILLS every live session of the account: whoever held
	// one (including a possible intruder) signs in again or is out.
	if _, err := h.st.DeleteSessionsForUser(r.Context(), userID); err != nil {
		slog.Warn("session revocation after reset failed", "err", err)
	}
	// Tell the owner (best-effort): an unexpected reset is worth an alarm.
	if u, err := h.st.GetUserByID(r.Context(), userID); err == nil && u.Email != "" {
		t := messagesFor(u.Locale)
		_, brand := h.chrome()
		if err := h.sendMail(r.Context(), mail.Message{
			To:      []string{u.Email},
			Subject: fmt.Sprintf(t["mailPwChangedSubject"], brand.AppName),
			Text:    fmt.Sprintf(t["mailPwChangedBody"], brand.AppName),
		}); err != nil {
			slog.Warn("password-changed notice failed", "user", u.Username, "err", err)
		}
	}
	writeFlow(w, resetDonePage, struct{ flowChrome }{h.flowData(r, "titleReset")}, http.StatusOK)
}
