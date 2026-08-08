package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/softwarity/meerkat/internal/mfa"
	"github.com/softwarity/meerkat/internal/store"
)

// trustCookieName carries the opaque trusted-browser token (MFA-03) - a factor
// entirely separate from the session cookie; only its hash is stored.
const trustCookieName = "MEERKAT_TRUST"

func hashTrust(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func trustTokenOf(r *http.Request) string {
	if c, err := r.Cookie(trustCookieName); err == nil {
		return c.Value
	}
	return ""
}

func randToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// browserTrusted reports whether this request rides a live trusted browser for
// the user AND the policy currently allows skipping the challenge (MFA-03).
func (h *Handler) browserTrusted(ctx context.Context, userID, token string) bool {
	if token == "" {
		return false
	}
	pol, err := h.st.GetTrustedBrowserPolicy(ctx)
	if err != nil || !pol.Allowed {
		return false
	}
	ok, err := h.st.IsBrowserTrusted(ctx, userID, hashTrust(token), time.Now().Unix())
	return err == nil && ok
}

// issueTrust remembers this browser (if the policy allows) so the next login
// skips the TOTP challenge until the trust expires. Best-effort: on any failure
// no cookie is set and the user is simply challenged next time.
func (h *Handler) issueTrust(w http.ResponseWriter, r *http.Request, userID string) {
	pol, err := h.st.GetTrustedBrowserPolicy(r.Context())
	if err != nil || !pol.Allowed {
		return
	}
	d, err := store.ParseISODuration(pol.TTL)
	if err != nil || d <= 0 {
		return
	}
	token, err := randToken()
	if err != nil {
		return
	}
	id, err := randToken()
	if err != nil {
		return
	}
	if err := h.st.AddTrustedBrowser(r.Context(), id, userID, hashTrust(token), browserLabel(r), time.Now().Add(d).Unix()); err != nil {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     trustCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(d.Seconds()),
	})
}

// browserLabel is a human hint for the trusted-browser list: "Chrome - macOS"
// style, derived from the User-Agent with a light sniff - no parsing library
// (offline-first); an unrecognized UA falls back to its head, trimmed.
func browserLabel(r *http.Request) string {
	ua := strings.TrimSpace(r.UserAgent())
	if ua == "" {
		return "Unknown browser"
	}
	browser := ""
	switch {
	case strings.Contains(ua, "Edg/"):
		browser = "Edge"
	case strings.Contains(ua, "OPR/") || strings.Contains(ua, "Opera"):
		browser = "Opera"
	case strings.Contains(ua, "Chrome/"):
		browser = "Chrome"
	case strings.Contains(ua, "Firefox/"):
		browser = "Firefox"
	case strings.Contains(ua, "Safari/"):
		browser = "Safari"
	}
	osName := ""
	switch {
	case strings.Contains(ua, "iPhone"):
		osName = "iPhone"
	case strings.Contains(ua, "iPad"):
		osName = "iPad"
	case strings.Contains(ua, "Android"):
		osName = "Android"
	case strings.Contains(ua, "Mac OS X"), strings.Contains(ua, "Macintosh"):
		osName = "macOS"
	case strings.Contains(ua, "Windows"):
		osName = "Windows"
	case strings.Contains(ua, "CrOS"):
		osName = "ChromeOS"
	case strings.Contains(ua, "Linux"):
		osName = "Linux"
	}
	switch {
	case browser != "" && osName != "":
		return browser + " - " + osName
	case browser != "":
		return browser
	case osName != "":
		return osName
	}
	if len(ua) > 60 {
		ua = ua[:60]
	}
	return ua
}

// ttlDays renders an ISO-8601 trust duration as a whole number of days for the
// checkbox label ("Trust this browser for N days").
func ttlDays(iso string) int {
	d, err := store.ParseISODuration(iso)
	if err != nil {
		return 0
	}
	days := int(d.Hours() / 24)
	if days < 1 {
		days = 1
	}
	return days
}

// The second factor (MFA-01) as flow pages: a login-time challenge for an
// enrolled user, forced enrolment when MFA is mandatory, and self-service
// management from the profile. Everything renders through the shared chrome and
// the enrolment QR is produced locally (internal/mfa) - no external request, so
// it works on an air-gapped gateway.

var (
	totpChallengePage    = flowPage("Two-factor - Meerkat", totpChallengeBody)
	totpEnrollPage       = flowPage("Set up two-factor - Meerkat", totpEnrollBody)
	profileMFAManagePage = flowPage("Two-factor - Meerkat", profileMFAManageBody)
)

// scratchCodeCount is how many single-use backup codes an enrolment mints.
const scratchCodeCount = 10

type totpChallengeData struct {
	flowChrome
	Error      string
	AllowTrust bool   // policy permits "remember this browser" (MFA-03)
	TrustLabel string // localized "Trust this browser for N days"
}

type totpEnrollData struct {
	flowChrome
	Error     string
	QR        template.URL // data: URI of the enrolment QR (empty -> manual entry only)
	Secret    string       // base32, for manual key entry
	Scratch   []string     // set -> show the backup-codes view (shown once)
	Mandatory bool         // forced enrolment (no way out) vs opt-in
	Action    string       // absolute path the forms post to
	Cancel    string       // absolute path for the cancel link ("" -> no cancel)
}

type profileMFAManageData struct {
	flowChrome
	Error       string
	Required    bool   // mandatory here -> cannot be turned off
	StatusLine  string // localized "Enabled - N backup codes left"
	ScratchLeft int
	AllowTrust  bool          // trusted browsers permitted by policy
	Trusted     []trustedView // the user's remembered browsers
}

// trustedView is a trusted browser prepared for display (date pre-formatted -
// html/template has no date helper).
type trustedView struct {
	ID         string
	Label      string
	UntilLabel string // localized "until YYYY-MM-DD"
	// Current marks the trust THIS browser carries (its cookie's hash).
	Current bool
}

// ---- login-flow challenge (enrolled users) ----

func (h *Handler) showTOTP(w http.ResponseWriter, r *http.Request) {
	sess, err := h.sm.Resolve(r.Context(), r)
	if err != nil {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.String()), http.StatusSeeOther)
		return
	}
	if sess.Pending != stepTOTP {
		http.Redirect(w, r, stepDest(sess), http.StatusSeeOther)
		return
	}
	h.renderChallenge(w, r, "", http.StatusOK)
}

func (h *Handler) doTOTP(w http.ResponseWriter, r *http.Request) {
	sess, err := h.sm.Resolve(r.Context(), r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if sess.Pending != stepTOTP {
		http.Error(w, "no second factor is pending on this session", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// A 6-digit code brute-forces fast (SEC-10): after N wrong codes the
	// challenge refuses until the window slides; a right code forgives.
	pol := h.st.GetRateLimitPolicy(r.Context())
	window := 15 * time.Minute
	if d, err := store.ParseISODuration(pol.LoginWindow); err == nil && d > 0 {
		window = d
	}
	totpKey := "totp|" + sess.UserID
	if pol.TotpAttempts > 0 && h.regLimit.count(totpKey, window) >= pol.TotpAttempts {
		h.renderChallenge(w, r, h.tr(r, "errTooManyAttempts"), http.StatusTooManyRequests)
		return
	}
	if !h.verifySecondFactor(r, sess.UserID, r.PostFormValue("code")) {
		h.regLimit.hit(totpKey, window)
		h.renderChallenge(w, r, h.tr(r, "errBadCode"), http.StatusUnprocessableEntity)
		return
	}
	h.regLimit.reset(totpKey)
	// "Remember this browser" (MFA-03) - best-effort; issueTrust re-checks policy.
	if r.PostFormValue("trust") != "" {
		h.issueTrust(w, r, sess.UserID)
	}
	h.finishFlow(w, r, sess)
}

// verifySecondFactor accepts either a live TOTP or a single-use backup code
// (the latter is burned on success - MFA-01).
func (h *Handler) verifySecondFactor(r *http.Request, userID, code string) bool {
	totp, err := h.st.GetUserTOTP(r.Context(), userID)
	if err != nil {
		return false
	}
	if mfa.Validate(totp.Secret, code, time.Now()) {
		return true
	}
	ok, err := h.st.ConsumeScratch(r.Context(), userID, code)
	return err == nil && ok
}

func (h *Handler) renderChallenge(w http.ResponseWriter, r *http.Request, errMsg string, status int) {
	data := totpChallengeData{flowChrome: h.flowData(r, "titleTwoFactor"), Error: errMsg}
	if pol, err := h.st.GetTrustedBrowserPolicy(r.Context()); err == nil && pol.Allowed {
		data.AllowTrust = true
		data.TrustLabel = fmt.Sprintf(data.T["trustDays"], ttlDays(pol.TTL))
	}
	writeFlow(w, totpChallengePage, data, status)
}

// ---- login-flow forced enrolment (MFA mandatory, not yet enrolled) ----

func (h *Handler) showTOTPEnroll(w http.ResponseWriter, r *http.Request) {
	sess, err := h.sm.Resolve(r.Context(), r)
	if err != nil {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.String()), http.StatusSeeOther)
		return
	}
	if sess.Pending != stepTOTPEnroll {
		http.Redirect(w, r, stepDest(sess), http.StatusSeeOther)
		return
	}
	// Reload after a completed enrolment (backup codes already shown): just move
	// on - the codes are never re-displayed.
	if totp, err := h.st.GetUserTOTP(r.Context(), sess.UserID); err == nil && totp.Enrolled {
		h.finishFlow(w, r, sess)
		return
	}
	h.renderEnrollSetup(w, r, sess.UserID, "/totp-enroll", "", true, "", http.StatusOK)
}

func (h *Handler) doTOTPEnroll(w http.ResponseWriter, r *http.Request) {
	sess, err := h.sm.Resolve(r.Context(), r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if sess.Pending != stepTOTPEnroll {
		http.Error(w, "no enrolment is pending on this session", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	switch r.PostFormValue("step") {
	case "ack":
		// The user acknowledged their backup codes -> the flow may proceed.
		if totp, err := h.st.GetUserTOTP(r.Context(), sess.UserID); err != nil || !totp.Enrolled {
			http.Redirect(w, r, "/totp-enroll", http.StatusSeeOther)
			return
		}
		h.finishFlow(w, r, sess)
	default: // "confirm"
		scratch, ok := h.confirmEnrolment(w, r, sess.UserID, "/totp-enroll", "", true)
		if !ok {
			return
		}
		writeFlow(w, totpEnrollPage, totpEnrollData{
			flowChrome: h.flowData(r, "titleSetupTwoFactor"),
			Scratch:    scratch, Action: "/totp-enroll", Mandatory: true,
		}, http.StatusOK)
	}
}

// ---- self-service management (profile) ----

func (h *Handler) showProfileMFA(w http.ResponseWriter, r *http.Request) {
	sess, err := h.sm.Resolve(r.Context(), r)
	if err != nil {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.String()), http.StatusSeeOther)
		return
	}
	if sess.Pending != "" {
		http.Redirect(w, r, "/"+sess.Pending, http.StatusSeeOther)
		return
	}
	totp, err := h.st.GetUserTOTP(r.Context(), sess.UserID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	required, _ := h.st.MFARequiredForUser(r.Context(), sess.UserID)
	if totp.Enrolled {
		pol, _ := h.st.GetTrustedBrowserPolicy(r.Context())
		h.renderMFAManage(w, r, profileMFAManageData{
			Required: required, ScratchLeft: len(totp.Scratch),
			AllowTrust: pol.Allowed, Trusted: h.trustedViews(r, sess.UserID),
		}, http.StatusOK)
		return
	}
	h.renderEnrollSetup(w, r, sess.UserID, "/profile/mfa", "/profile", required, "", http.StatusOK)
}

// trustedViews loads the user's trusted browsers ready for display.
func (h *Handler) trustedViews(r *http.Request, userID string) []trustedView {
	list, err := h.st.ListTrustedBrowsers(r.Context(), userID)
	if err != nil {
		return nil
	}
	until := h.tr(r, "untilDate")
	current := ""
	if token := trustTokenOf(r); token != "" {
		current, _ = h.st.TrustedBrowserIDByHash(r.Context(), userID, hashTrust(token), time.Now().Unix())
	}
	out := make([]trustedView, 0, len(list))
	for _, b := range list {
		isCurrent := b.ID == current
		label := b.Label
		if isCurrent {
			// We ARE this browser: no need to name the browser/OS.
			label = h.tr(r, "thisBrowser")
		}
		out = append(out, trustedView{
			ID: b.ID, Label: label,
			UntilLabel: fmt.Sprintf(until, time.Unix(b.ExpiresAt, 0).Format("2006-01-02")),
			Current:    isCurrent,
		})
	}
	return out
}

func (h *Handler) doProfileMFA(w http.ResponseWriter, r *http.Request) {
	sess, err := h.sm.Resolve(r.Context(), r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if sess.Pending != "" {
		http.Redirect(w, r, "/"+sess.Pending, http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	required, _ := h.st.MFARequiredForUser(r.Context(), sess.UserID)
	switch r.PostFormValue("step") {
	case "renew":
		// Start a fresh enrolment; the current secret stays active until a new
		// code confirms it.
		secret, err := mfa.NewSecret()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if err := h.st.SetUserTOTPPending(r.Context(), sess.UserID, secret); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		h.renderEnrollSetup(w, r, sess.UserID, "/profile/mfa", "/profile", required, "", http.StatusOK)
	case "confirm":
		scratch, ok := h.confirmEnrolment(w, r, sess.UserID, "/profile/mfa", "/profile", required)
		if !ok {
			return
		}
		writeFlow(w, totpEnrollPage, totpEnrollData{
			flowChrome: h.flowData(r, "titleSetupTwoFactor"),
			Scratch:    scratch, Action: "/profile/mfa", Cancel: "/profile",
		}, http.StatusOK)
	case "regen":
		totp, err := h.st.GetUserTOTP(r.Context(), sess.UserID)
		if err != nil || !totp.Enrolled {
			http.Redirect(w, r, "/profile/mfa", http.StatusSeeOther)
			return
		}
		plain, hashes, err := mfa.NewScratchCodes(scratchCodeCount)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if err := h.st.EnableUserTOTP(r.Context(), sess.UserID, totp.Secret, hashes); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		writeFlow(w, totpEnrollPage, totpEnrollData{
			flowChrome: h.flowData(r, "titleSetupTwoFactor"),
			Scratch:    plain, Action: "/profile/mfa", Cancel: "/profile",
		}, http.StatusOK)
	case "disable":
		if required {
			h.renderMFAManage(w, r, profileMFAManageData{
				Required: true, Error: h.tr(r, "errMfaRequiredOff"),
			}, http.StatusForbidden)
			return
		}
		if err := h.st.DisableUserTOTP(r.Context(), sess.UserID); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		_ = h.st.RevokeAllTrustedBrowsers(r.Context(), sess.UserID)
		http.Redirect(w, r, "/profile", http.StatusSeeOther)
	case "revoke":
		if _, err := h.st.RevokeTrustedBrowser(r.Context(), sess.UserID, r.PostFormValue("id")); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/profile/mfa", http.StatusSeeOther)
	case "revoke-all":
		if err := h.st.RevokeAllTrustedBrowsers(r.Context(), sess.UserID); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/profile/mfa", http.StatusSeeOther)
	default: // "ack" or unknown -> back to the profile
		http.Redirect(w, r, "/profile", http.StatusSeeOther)
	}
}

// ---- shared enrolment rendering ----

// renderEnrollSetup shows the QR + confirm form, minting a pending secret the
// first time. action/cancel/mandatory tailor it to the forced-login vs
// self-service context.
func (h *Handler) renderEnrollSetup(w http.ResponseWriter, r *http.Request, userID, action, cancel string, mandatory bool, errMsg string, status int) {
	totp, err := h.st.GetUserTOTP(r.Context(), userID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	secret := totp.Pending
	if secret == "" {
		secret, err = mfa.NewSecret()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if err := h.st.SetUserTOTPPending(r.Context(), userID, secret); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}
	chrome := h.flowData(r, "titleSetupTwoFactor")
	qr := h.enrolQR(chrome.Brand, h.accountLabel(r, userID), secret)
	writeFlow(w, totpEnrollPage, totpEnrollData{
		flowChrome: chrome, QR: qr, Secret: secret,
		Action: action, Cancel: cancel, Mandatory: mandatory, Error: errMsg,
	}, status)
}

// confirmEnrolment validates the submitted code against the pending secret and,
// on success, commits the secret + fresh backup codes and returns the plaintext
// codes (shown once). On failure it re-renders the setup and returns ok=false.
func (h *Handler) confirmEnrolment(w http.ResponseWriter, r *http.Request, userID, action, cancel string, mandatory bool) ([]string, bool) {
	totp, err := h.st.GetUserTOTP(r.Context(), userID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return nil, false
	}
	if totp.Pending == "" {
		http.Redirect(w, r, action, http.StatusSeeOther)
		return nil, false
	}
	if !mfa.Validate(totp.Pending, r.PostFormValue("code"), time.Now()) {
		h.renderEnrollSetup(w, r, userID, action, cancel, mandatory, h.tr(r, "errBadCodeRetry"), http.StatusUnprocessableEntity)
		return nil, false
	}
	plain, hashes, err := mfa.NewScratchCodes(scratchCodeCount)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return nil, false
	}
	if err := h.st.EnableUserTOTP(r.Context(), userID, totp.Pending, hashes); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return nil, false
	}
	// Replacing the authenticator invalidates every remembered browser: old
	// trust must not skip the new factor (no-op on a first enrolment).
	_ = h.st.RevokeAllTrustedBrowsers(r.Context(), userID)
	return plain, true
}

func (h *Handler) renderMFAManage(w http.ResponseWriter, r *http.Request, data profileMFAManageData, status int) {
	data.flowChrome = h.flowData(r, "titleTwoFactor")
	// Spell the backup-code count out against its total ("7 of 10") - a bare
	// "10 left" reads like noise when you never knew there were 10.
	data.StatusLine = fmt.Sprintf(data.T["mfaStatus"], data.ScratchLeft, scratchCodeCount)
	writeFlow(w, profileMFAManagePage, data, status)
}

// enrolQR renders the otpauth:// provisioning QR locally; on failure it returns
// an empty URL so the page falls back to manual key entry.
func (h *Handler) enrolQR(brand brandView, account, secret string) template.URL {
	issuer := brand.AppName
	if issuer == "" {
		issuer = "Meerkat"
	}
	data, err := mfa.QRDataURI(mfa.ProvisioningURI(issuer, account, secret))
	if err != nil {
		return ""
	}
	return template.URL(data)
}

// accountLabel is the human name shown in the authenticator entry (the user's
// username, falling back to the id).
func (h *Handler) accountLabel(r *http.Request, userID string) string {
	if u, err := h.st.GetUserByID(r.Context(), userID); err == nil && u.Username != "" {
		return u.Username
	}
	return userID
}

// stepDest is where to send a request that landed on the wrong step: the step it
// actually owes, or its final destination if the flow is complete.
func stepDest(sess store.Session) string {
	if sess.Pending != "" {
		return "/" + sess.Pending
	}
	return safeNext(sess.Next)
}

func writeFlow(w http.ResponseWriter, page *template.Template, data any, status int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = page.Execute(w, data)
}

const totpChallengeBody = `    <form method="post" action="/totp">
      <p class="lead">{{.T.twoFactor}}</p>
      {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
      <p class="hint">{{.T.challengeHint}}</p>
      <label class="field">
        <span>{{.T.authCode}}</span>
        <input name="code" inputmode="numeric" autocomplete="one-time-code" autofocus required>
      </label>
      {{if .AllowTrust}}
      <label class="trust">
        <input type="checkbox" name="trust" value="1">
        <span>{{.TrustLabel}}</span>
      </label>
      {{end}}
      <button type="submit">{{.T.verify}}</button>
    </form>
    <form method="post" action="/logout" class="signout">
      <button class="choice" type="submit">{{.T.signOut}}</button>
    </form>
    <style>
      .hint { margin: 0; font-size: .82rem; color: var(--mk-on-surface-variant); }
      form.signout { margin-top: 14px; }
      .trust { display: flex; align-items: center; gap: 9px; font-size: .82rem; color: var(--mk-on-surface-variant); cursor: pointer; }
      .trust input { width: auto; margin: 0; accent-color: var(--mk-primary); }
    </style>
`

const totpEnrollBody = `    <style>
      .hint { margin: 0; font-size: .82rem; color: var(--mk-on-surface-variant); }
      .qr {
        display: block; margin: 4px auto; width: 208px; height: 208px;
        border-radius: var(--mk-radius-small); background: #fff; padding: 10px;
      }
      .secret {
        margin: 0; text-align: center; font-family: var(--mk-mono); font-size: .8rem;
        letter-spacing: .12em; word-break: break-all; color: var(--mk-on-surface-variant);
      }
      .codes {
        margin: 4px 0; padding: 14px 16px; list-style: none;
        display: grid; grid-template-columns: 1fr 1fr; gap: 8px 18px;
        background: var(--mk-surface-container-high); border: 1px solid var(--mk-outline);
        border-radius: var(--mk-radius-small);
        font-family: var(--mk-mono); font-size: .9rem; letter-spacing: .06em;
      }
      .back { margin-top: 2px; text-align: center; font-size: .8rem; color: var(--mk-on-surface-variant); }
      .back a { color: var(--mk-primary); text-decoration: none; }
    </style>
    {{if .Scratch}}
    <form method="post" action="{{.Action}}">
      <p class="lead">{{.T.saveBackupCodes}}</p>
      <p class="hint">{{.T.backupHint}}</p>
      <ul class="codes">{{range .Scratch}}<li>{{.}}</li>{{end}}</ul>
      <input type="hidden" name="step" value="ack">
      <button type="submit">{{.T.savedContinue}}</button>
    </form>
    {{else}}
    <form method="post" action="{{.Action}}">
      <p class="lead">{{if .Mandatory}}{{.T.mfaRequiredLead}}{{else}}{{.T.setupLead}}{{end}}</p>
      {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
      <p class="hint">{{.T.scanHint}}</p>
      {{if .QR}}<img class="qr" src="{{.QR}}" alt="{{.T.qrAlt}}" width="200" height="200">{{end}}
      <p class="secret" aria-label="{{.T.setupKey}}">{{.Secret}}</p>
      <label class="field">
        <span>{{.T.sixDigitCode}}</span>
        <input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]*" autofocus required>
      </label>
      <input type="hidden" name="step" value="confirm">
      <button type="submit">{{.T.confirm}}</button>
    </form>
    {{if .Cancel}}<p class="back"><a href="{{.Cancel}}">{{.T.cancel}}</a></p>{{end}}
    {{end}}
`

const profileMFAManageBody = `    <style>
      .hint { margin: 0; font-size: .82rem; color: var(--mk-on-surface-variant); }
      .status {
        margin: 0 0 4px; padding: 9px 12px; border-radius: var(--mk-radius-small);
        color: var(--mk-primary); font-size: .84rem; font-weight: 600;
        background: color-mix(in srgb, var(--mk-primary) 12%, transparent);
        border: 1px solid color-mix(in srgb, var(--mk-primary) 30%, transparent);
      }
      form.mfa-action { margin: 0; }
      button.danger {
        background: color-mix(in srgb, var(--mk-error) 14%, transparent);
        color: var(--mk-error); border-color: color-mix(in srgb, var(--mk-error) 34%, transparent);
      }
      button.danger:hover { border-color: var(--mk-error); }
      .back { margin: 6px 0 0; text-align: center; font-size: .8rem; }
      .back a { color: var(--mk-primary); text-decoration: none; }
      /* width is pinned to the column: the wrap centers CHILDREN (not
         stretch), so an unconstrained panel would grow to its longest
         nowrap label and overflow off-center. */
      .trusted { margin: 8px 0 0; display: grid; gap: 8px; width: 100%; min-width: 0; }
      .tb-panel { min-width: 0; }
      /* the section title lives INSIDE the panel, like the 2FA card's lead */
      .trusted h2 {
        margin: 0; padding: 12px 0 2px; text-align: left;
        font-family: var(--mk-mono); font-size: .62rem; letter-spacing: .16em;
        text-transform: uppercase; color: var(--mk-on-surface-variant); font-weight: 600;
      }
      /* the list lives in a PANEL, same family as the option blocks */
      .tb-panel {
        padding: 2px 16px; position: relative;
        background: var(--mk-surface-container-high);
        border: 1px solid var(--mk-outline); border-radius: var(--mk-radius-small);
      }
      /* same hairline mint accent as the flow card's top edge */
      .tb-panel::before {
        content: ''; position: absolute; inset: 0 0 auto 0; height: 2px;
        border-radius: var(--mk-radius-small) var(--mk-radius-small) 0 0;
        background: linear-gradient(90deg, transparent, var(--mk-primary), transparent);
        opacity: calc(.85 * var(--mk-glow, 1));
      }
      .tb {
        display: flex; align-items: center; gap: 10px; padding: 10px 0;
      }
      .tb + .tb { border-top: 1px solid color-mix(in srgb, var(--mk-outline) 45%, transparent); }
      .tb .tb-label { flex: 1; min-width: 0; font-size: .85rem; text-align: left; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
      .tb .tb-label.here { color: var(--mk-primary); font-weight: 500; }
      .tb .tb-exp { font-family: var(--mk-mono); font-size: .62rem; letter-spacing: .1em; color: var(--mk-on-surface-variant); }
      .tb-this {
        font-family: var(--mk-mono); font-size: .58rem; letter-spacing: .12em;
        text-transform: uppercase; color: var(--mk-primary);
        padding: 2px 8px; border-radius: 999px;
        background: color-mix(in srgb, var(--mk-primary) 12%, transparent);
      }
      /* the row's form must NOT be the flow card: strip it entirely */
      .tb form {
        margin: 0; padding: 0; width: auto; display: inline-grid;
        background: none; border: 0; box-shadow: none; backdrop-filter: none;
        animation: none;
      }
      .tb form::before { display: none; }
      /* small round revoke, same family as the scheme pills */
      .tb .tb-x {
        margin: 0; padding: 0; width: 28px; height: 28px;
        border: 1px solid transparent; border-radius: 50%;
        background: none; box-shadow: none; color: var(--mk-on-surface-variant);
        cursor: pointer; display: grid; place-items: center;
      }
      .tb .tb-x svg { display: block; }
      .tb .tb-x:hover {
        color: var(--mk-error); border-color: var(--mk-outline);
        background: var(--mk-surface-container); filter: none; box-shadow: none;
      }
      .tb .tb-x:active { transform: none; }
      /* revoke-all closes the panel: an inline form, NOT the flow card */
      .tb-ra {
        margin: 0; padding: 10px 0; width: auto; display: grid;
        background: none; border: 0; box-shadow: none; backdrop-filter: none;
        animation: none; border-top: 1px solid var(--mk-outline); border-radius: 0;
      }
      .tb-ra::before { display: none; }
    </style>
    <form class="mfa-action" method="post" action="/profile/mfa">
      <p class="lead">{{.T.twoFactor}}</p>
      {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
      <p class="status">{{.StatusLine}}</p>
      <button class="choice" type="submit" name="step" value="renew">{{.T.replaceAuth}}</button>
      <button class="choice" type="submit" name="step" value="regen">{{.T.regenCodes}}</button>
      {{if not .Required}}<button class="choice danger" type="submit" name="step" value="disable">{{.T.turnOffMfa}}</button>{{end}}
      {{if .Required}}<p class="hint">{{.T.mfaRequiredNote}}</p>{{end}}
    </form>
    {{if .Trusted}}
    <div class="trusted">
      <div class="tb-panel">
        <h2>{{.T.trustedBrowsers}}</h2>
        {{range .Trusted}}
        <div class="tb">
          <span class="tb-label{{if .Current}} here{{end}}" title="{{.Label}}">{{.Label}}</span>
          <span class="tb-exp">{{.UntilLabel}}</span>
          <form method="post" action="/profile/mfa">
            <input type="hidden" name="step" value="revoke">
            <input type="hidden" name="id" value="{{.ID}}">
            <button class="tb-x" type="submit" title="{{$.T.revoke}}" aria-label="{{$.T.revoke}}"><svg viewBox="0 -960 960 960" width="15" height="15" fill="currentColor" aria-hidden="true"><path d="m256-200-56-56 224-224-224-224 56-56 224 224 224-224 56 56-224 224 224 224-56 56-224-224-224 224Z"/></svg></button>
          </form>
        </div>
        {{end}}
        <form class="tb-ra" method="post" action="/profile/mfa">
          <input type="hidden" name="step" value="revoke-all">
          <button class="choice danger" type="submit">{{.T.revokeAll}}</button>
        </form>
      </div>
    </div>
    {{end}}
    <p class="back"><a href="/profile/security">{{.T.back}}</a></p>
`
