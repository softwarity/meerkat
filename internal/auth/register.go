package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	netmail "net/mail"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/softwarity/meerkat/internal/captcha"
	"github.com/softwarity/meerkat/internal/mail"
	"github.com/softwarity/meerkat/internal/store"
)

// Self-registration (AUTH-20): an OPT-IN policy. The account is created
// disabled-for-login until its address is confirmed through a one-shot mailed
// link; once confirmed, the app-admins are notified and the user waits on
// /account-pending until someone (or a mapping rule, later) grants access.
//
// Anti-enumeration: the outcome page is the same whether the account was
// created or the username/address was already taken.

const confirmPurpose = "confirm"

// selfRegisterOpen reports whether /register is reachable: the policy must be
// on AND the gateway must be able to send the confirmation e-mail.
func (h *Handler) selfRegisterOpen(ctx context.Context) bool {
	return !h.adminPlane &&
		h.st.GetRegistrationPolicy(ctx).LocalEnabled &&
		h.st.GetSMTP(ctx).Configured()
}

// captchaRequired: the home-grown anti-robot check rides /register unless the
// admin explicitly turned it off.
func (h *Handler) captchaRequired(ctx context.Context) bool {
	return !h.st.GetRegistrationPolicy(ctx).CaptchaDisabled
}

const captchaPrefix = "captcha:" // challenge ids are namespaced per purpose

// newCaptcha mints a code, stores its HASH as a 10-minute one-shot challenge,
// and hands the template the id + inline PNG.
func (h *Handler) newCaptcha(ctx context.Context) (id string, img template.URL, err error) {
	code, png, err := captcha.Generate()
	if err != nil {
		return "", "", err
	}
	id = randomID()
	if err := h.st.PutChallenge(ctx, captchaPrefix+id, hashTrust(code),
		time.Now().Add(10*time.Minute).Unix()); err != nil {
		return "", "", err
	}
	//nolint:gosec // a data: URI of our own freshly encoded PNG
	return id, template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png)), nil
}

// checkCaptcha consumes the challenge (one shot, right or wrong) and compares
// the visitor's answer to the stored hash.
func (h *Handler) checkCaptcha(ctx context.Context, id, answer string) bool {
	if id == "" {
		return false
	}
	want, err := h.st.TakeChallenge(ctx, captchaPrefix+id, time.Now().Unix())
	if err != nil {
		return false
	}
	return want == hashTrust(strings.TrimSpace(answer))
}

func (h *Handler) sendMail(ctx context.Context, msg mail.Message) error {
	if h.Mailer == nil {
		return fmt.Errorf("mail: SMTP is not configured")
	}
	return h.Mailer(ctx, msg)
}

// rateLimiter is a small sliding-window attempt counter (SEC-10). Lives ON
// the handler (not a package global) so instances — and tests — never share
// counters. In-memory, per node: enough for the single-binary deployment;
// the cluster backend will revisit it.
type rateLimiter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

func newRateLimiter() *rateLimiter { return &rateLimiter{hits: map[string][]time.Time{}} }

// hit records one attempt for key, pruning entries older than window.
func (l *rateLimiter) hit(key string, window time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.hits[key] = append(l.prune(key, window), time.Now())
}

// count reports the live attempts for key within window.
func (l *rateLimiter) count(key string, window time.Duration) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	kept := l.prune(key, window)
	l.hits[key] = kept
	return len(kept)
}

// reset clears the key (a successful sign-in forgives the failures).
func (l *rateLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.hits, key)
}

// allow counts THIS attempt against the limit (register-style: every try
// costs, success or not).
func (l *rateLimiter) allow(key string, limit int, window time.Duration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	kept := l.prune(key, window)
	if len(kept) >= limit {
		l.hits[key] = kept
		return false
	}
	l.hits[key] = append(kept, time.Now())
	return true
}

func (l *rateLimiter) prune(key string, window time.Duration) []time.Time {
	now := time.Now()
	kept := l.hits[key][:0]
	for _, t := range l.hits[key] {
		if now.Sub(t) < window {
			kept = append(kept, t)
		}
	}
	return kept
}

// registerAllow is the fixed policy of the unauthenticated WRITE endpoints
// (/register, /forgot-password): 5 tries per IP per 15 minutes.
func (h *Handler) registerAllow(ip string) bool {
	return h.regLimit.allow("reg|"+ip, 5, 15*time.Minute)
}

// ---- pages ----

var (
	registerPage     = flowPage("register", registerBody)
	registerSentPage = flowPage("register-sent", registerSentBody)
	confirmedPage    = flowPage("confirmed", confirmedBody)
	pendingPage      = flowPage("account-pending", pendingBody)
)

type registerData struct {
	flowChrome
	Error    string
	Username string
	Email    string
	Fullname string
	// The home-grown captcha (empty id = check disabled by policy).
	CaptchaID  string
	CaptchaImg template.URL
}

const registerBody = `    <style>
      .captcha-row { display: flex; align-items: center; gap: 10px; }
      .captcha-row img {
        border: 1px solid var(--mk-outline); border-radius: var(--mk-radius-small);
        max-width: calc(100% - 46px); height: auto;
      }
      /* small round refresh, same family as the scheme pills */
      .captcha-new {
        margin: 0; padding: 0; width: 32px; height: 32px; flex: none;
        border: 1px solid transparent; border-radius: 50%;
        background: none; box-shadow: none; color: var(--mk-on-surface-variant);
        font-size: 1.1rem; line-height: 1; cursor: pointer;
        display: grid; place-items: center;
      }
      .captcha-new:hover {
        color: var(--mk-primary); border-color: var(--mk-outline);
        background: var(--mk-surface-container); filter: none; box-shadow: none;
      }
      .captcha-new:active { transform: none; }
    </style>
    <form method="post" action="/register">
      <p class="lead">{{.T.registerLead}}</p>
      {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
      <label class="field">
        <span>{{.T.username}}</span>
        <input name="username" autocomplete="username" value="{{.Username}}" autofocus required>
      </label>
      <label class="field">
        <span>{{.T.email}}</span>
        <input name="email" type="email" autocomplete="email" value="{{.Email}}" required>
      </label>
      <label class="field">
        <span>{{.T.fullname}}</span>
        <input name="fullname" autocomplete="name" value="{{.Fullname}}">
      </label>
      <label class="field">
        <span>{{.T.password}}</span>
        <input name="password" type="password" autocomplete="new-password" required minlength="8">
      </label>
      <label class="field">
        <span>{{.T.confirmPassword}}</span>
        <input name="confirm" type="password" autocomplete="new-password" required minlength="8">
      </label>
      {{if .CaptchaID}}
      <label class="field">
        <span>{{.T.captchaLabel}}</span>
        <div class="captcha-row">
          <img id="cap-img" src="{{.CaptchaImg}}" alt="{{.T.captchaAlt}}">
          <button type="button" class="captcha-new" id="cap-new" title="{{.T.captchaNew}}" aria-label="{{.T.captchaNew}}">&#8635;</button>
        </div>
        <input name="captcha" inputmode="numeric" autocomplete="off" required>
        <input type="hidden" name="captcha_id" id="cap-id" value="{{.CaptchaID}}">
      </label>
      <script>
      (() => {
        const btn = document.getElementById('cap-new');
        if (!btn) return;
        btn.addEventListener('click', async () => {
          try {
            const c = await fetch('/register/captcha', { method: 'POST' }).then((r) => r.json());
            document.getElementById('cap-img').src = c.img;
            document.getElementById('cap-id').value = c.id;
          } catch (e) { /* keep the current image */ }
        });
      })();
      </script>
      {{end}}
      <button type="submit">{{.T.registerCta}}</button>
    </form>
    <p class="back"><a href="/login">{{.T.backToLogin}}</a></p>
`

const registerSentBody = `    <form onsubmit="return false">
      <p class="lead">{{.T.registerSentLead}}</p>
      <p class="hint">{{.T.registerSentHint}}</p>
    </form>
    <p class="back"><a href="/login">{{.T.backToLogin}}</a></p>
`

const confirmedBody = `    <form onsubmit="return false">
      <p class="lead">{{.T.confirmedLead}}</p>
      <p class="hint">{{.T.confirmedHint}}</p>
      <a class="choice" style="text-decoration:none" href="/login">{{.T.signIn}}</a>
    </form>
`

type pendingData struct {
	flowChrome
	Public []publicLink
}

const pendingBody = `    <form onsubmit="return false">
      <p class="lead">{{.T.pendingLead}}</p>
      <p class="hint">{{.T.pendingHint}}</p>
    </form>
    {{if .Public}}<div class="public">
      <p class="lead">{{.T.continueWithout}}</p>
      <nav class="public-links">
        {{range .Public}}<a href="{{.Href}}">{{.Name}}</a>{{end}}
      </nav>
    </div>{{end}}
    <p class="back"><a href="/profile">{{.T.backToProfile}}</a></p>
`

// ---- handlers ----

func (h *Handler) showRegister(w http.ResponseWriter, r *http.Request) {
	if !h.selfRegisterOpen(r.Context()) {
		http.NotFound(w, r)
		return
	}
	h.renderRegister(w, r, registerData{}, http.StatusOK)
}

func (h *Handler) renderRegister(w http.ResponseWriter, r *http.Request, data registerData, status int) {
	data.flowChrome = h.flowData(r, "titleRegister")
	// Every render carries a FRESH captcha (the previous one, consumed or
	// not, never comes back).
	if h.captchaRequired(r.Context()) {
		id, img, err := h.newCaptcha(r.Context())
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		data.CaptchaID, data.CaptchaImg = id, img
	}
	writeFlow(w, registerPage, data, status)
}

// doRegisterCaptcha hands the refresh button a fresh image (JSON, POST so it
// is never cached or prefetched).
func (h *Handler) doRegisterCaptcha(w http.ResponseWriter, r *http.Request) {
	if !h.selfRegisterOpen(r.Context()) || !h.captchaRequired(r.Context()) {
		http.NotFound(w, r)
		return
	}
	id, img, err := h.newCaptcha(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]string{"id": id, "img": string(img)})
}

func (h *Handler) doRegister(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !h.selfRegisterOpen(ctx) {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	data := registerData{
		Username: strings.TrimSpace(r.PostFormValue("username")),
		Email:    strings.TrimSpace(r.PostFormValue("email")),
		Fullname: strings.TrimSpace(r.PostFormValue("fullname")),
	}
	password := r.PostFormValue("password")
	switch {
	case data.Username == "" || data.Email == "":
		h.renderRegister(w, r, withErr(data, h.tr(r, "errRegisterMissing")), http.StatusUnprocessableEntity)
		return
	case len(password) < 8:
		h.renderRegister(w, r, withErr(data, h.tr(r, "errPwTooShort")), http.StatusUnprocessableEntity)
		return
	case password != r.PostFormValue("confirm"):
		h.renderRegister(w, r, withErr(data, h.tr(r, "errPwMismatch")), http.StatusUnprocessableEntity)
		return
	}
	if _, err := netmail.ParseAddress(data.Email); err != nil {
		h.renderRegister(w, r, withErr(data, h.tr(r, "errBadEmail")), http.StatusUnprocessableEntity)
		return
	}
	if !h.registerAllow(clientIP(r)) {
		h.renderRegister(w, r, withErr(data, h.tr(r, "errTooManyAttempts")), http.StatusTooManyRequests)
		return
	}
	// The anti-robot check consumes its challenge whatever the outcome — a
	// wrong copy means solving a brand-new image.
	if h.captchaRequired(ctx) && !h.checkCaptcha(ctx, r.PostFormValue("captcha_id"), r.PostFormValue("captcha")) {
		h.renderRegister(w, r, withErr(data, h.tr(r, "errCaptcha")), http.StatusUnprocessableEntity)
		return
	}

	// Taken username or address: SAME outcome page, nothing created, nothing
	// revealed (SEC-09 spirit).
	taken := false
	if _, err := h.st.GetUserByUsername(ctx, data.Username); err == nil {
		taken = true
	}
	if _, err := h.st.UserIDByEmail(ctx, data.Email); err == nil {
		taken = true
	}
	if !taken {
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		u := store.User{
			ID: randomID(), Username: data.Username, PasswordHash: string(hash),
			Email: data.Email, Fullname: data.Fullname, Enabled: true,
			Locale: prefsOf(r, h.offeredLanguages()).Lang,
			// The whole point: unusable until the address is confirmed.
			EmailVerified: false, SelfRegistered: true,
		}
		if err := h.st.CreateUser(ctx, u); err != nil {
			// A race on uniqueness lands here: still the neutral outcome.
			slog.Warn("self-registration create failed", "err", err)
		} else if err := h.sendConfirmation(r, u); err != nil {
			slog.Error("confirmation e-mail failed", "user", u.Username, "err", err)
		}
	}
	writeFlow(w, registerSentPage, struct{ flowChrome }{h.flowData(r, "titleRegister")}, http.StatusOK)
}

func withErr(d registerData, msg string) registerData { d.Error = msg; return d }

// sendConfirmation mints the one-shot token and mails the /confirm link, in
// the user's language.
func (h *Handler) sendConfirmation(r *http.Request, u store.User) error {
	token, err := randToken()
	if err != nil {
		return err
	}
	if err := h.st.PutEmailToken(r.Context(), hashTrust(token), u.ID, confirmPurpose,
		time.Now().Add(24*time.Hour).Unix()); err != nil {
		return err
	}
	link := h.externalURL(r) + "/confirm?token=" + token
	t := messagesFor(u.Locale)
	_, brand := h.chrome()
	subject := fmt.Sprintf(t["mailConfirmSubject"], brand.AppName)
	body := fmt.Sprintf(t["mailConfirmBody"], brand.AppName, link)
	return h.sendMail(r.Context(), mail.Message{
		To: []string{u.Email}, Subject: subject, Text: body,
		HTML: fmt.Sprintf(`<p>%s</p><p><a href="%s">%s</a></p>`,
			fmt.Sprintf(t["mailConfirmHTML"], brand.AppName), link, t["mailConfirmCta"]),
	})
}

// externalURL rebuilds the address this request was reached on — the only
// base a mailed link can use (the gateway fronts arbitrary domains).
func (h *Handler) externalURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func (h *Handler) doConfirm(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.NotFound(w, r)
		return
	}
	userID, err := h.st.TakeEmailToken(r.Context(), hashTrust(token), confirmPurpose, time.Now().Unix())
	if err != nil {
		http.Error(w, h.tr(r, "errConfirmExpired"), http.StatusUnprocessableEntity)
		return
	}
	if err := h.st.MarkEmailVerified(r.Context(), userID); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if u, err := h.st.GetUserByID(r.Context(), userID); err == nil {
		h.notifyAdminsNewAccount(r.Context(), u)
	}
	writeFlow(w, confirmedPage, struct{ flowChrome }{h.flowData(r, "titleConfirmed")}, http.StatusOK)
}

// notifyAdminsNewAccount tells every app-admin (and root) that a confirmed
// account waits for access — each in their own language. Best-effort.
func (h *Handler) notifyAdminsNewAccount(ctx context.Context, u store.User) {
	admins, err := h.st.ListNotifiableAdmins(ctx)
	if err != nil {
		slog.Warn("admin notification failed", "err", err)
		return
	}
	_, brand := h.chrome()
	for _, a := range admins {
		t := messagesFor(a.Locale)
		msg := mail.Message{
			To:      []string{a.Email},
			Subject: fmt.Sprintf(t["mailNewAccountSubject"], brand.AppName),
			Text:    fmt.Sprintf(t["mailNewAccountBody"], u.Username, u.Email, brand.AppName),
		}
		if err := h.sendMail(ctx, msg); err != nil {
			slog.Warn("admin notification failed", "admin", a.Username, "err", err)
		}
	}
}

// showAccountPending is the waiting room (AUTH-20): signed in, confirmed, but
// no access granted yet — offer the public routes meanwhile.
func (h *Handler) showAccountPending(w http.ResponseWriter, r *http.Request) {
	sess, err := h.sm.Resolve(r.Context(), r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if sess.Pending != "" {
		http.Redirect(w, r, "/"+sess.Pending, http.StatusSeeOther)
		return
	}
	// The waiting room offers whatever THIS session may already open — the
	// public routes at least, plus the authenticated ones.
	writeFlow(w, pendingPage, pendingData{
		flowChrome: h.flowData(r, "titlePending"),
		Public:     h.reachableLinks(r.Context(), sess),
	}, http.StatusOK)
}

// waitingRoom reports whether a fresh session has nothing to reach: no
// membership, no capability — the default landing would only hit the traps.
func waitingRoom(user store.User, memberships int) bool {
	return memberships == 0 && !user.Root && !user.InfraAdmin && !user.AppAdmin &&
		!user.Dev && !user.TenantCreator
}

// messagesFor picks a mail catalogue by stored locale, falling back to en.
func messagesFor(locale string) map[string]string {
	if t, ok := messages[locale]; ok {
		return t
	}
	return messages["en"]
}
