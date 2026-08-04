package auth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/softwarity/meerkat/internal/store"
)

// passkeyCookie remembers which passkey THIS browser registered or last
// used, so the Security page can badge it — a hint, not a credential.
const passkeyCookie = "MEERKAT_PASSKEY"

func setPasskeyCookie(w http.ResponseWriter, r *http.Request, id string) {
	http.SetCookie(w, &http.Cookie{
		Name: passkeyCookie, Value: id, Path: "/",
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode,
		MaxAge: 365 * 24 * 3600,
	})
}

// Passkeys (AUTH-15): WebAuthn ceremonies over the v12 store foundation. A
// passkey REPLACES password + TOTP (both factors in one), so a passkey login
// lands directly on the tenant resolution — no pending steps. Registration is
// self-service on /profile; sign-in is the usernameless (discoverable) flow
// from the login page.

// hostOnly strips the port from a Host header value (IPv6 brackets kept).
func hostOnly(hostport string) string {
	if i := strings.LastIndexByte(hostport, ':'); i >= 0 && !strings.Contains(hostport[i:], "]") {
		return hostport[:i]
	}
	return hostport
}

// webAuthnFor builds the relying party for THIS request: the RP ID is the
// served hostname (the gateway fronts many domains; localhost works for dev).
func (h *Handler) webAuthnFor(r *http.Request) (*webauthn.WebAuthn, error) {
	host := hostOnly(r.Host)
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	_, brand := h.chrome()
	return webauthn.New(&webauthn.Config{
		RPID:          host,
		RPDisplayName: brand.AppName,
		RPOrigins:     []string{scheme + "://" + r.Host},
	})
}

// webauthnUser adapts a store.User (+ its credentials) to the library. The
// user HANDLE is the store ID: the discoverable login hands it back and the
// gateway resolves the account from it.
type webauthnUser struct {
	u     store.User
	creds []webauthn.Credential
}

func (w webauthnUser) WebAuthnID() []byte { return []byte(w.u.ID) }
func (w webauthnUser) WebAuthnName() string {
	return w.u.Username
}
func (w webauthnUser) WebAuthnDisplayName() string {
	if w.u.Fullname != "" {
		return w.u.Fullname
	}
	return w.u.Username
}
func (w webauthnUser) WebAuthnCredentials() []webauthn.Credential { return w.creds }

// passkeyCredentials loads and decodes a user's stored credentials.
func (h *Handler) passkeyCredentials(r *http.Request, userID string) ([]webauthn.Credential, error) {
	blobs, err := h.st.PasskeyBlobs(r.Context(), userID)
	if err != nil {
		return nil, err
	}
	creds := make([]webauthn.Credential, 0, len(blobs))
	for _, b := range blobs {
		var c webauthn.Credential
		if err := json.Unmarshal([]byte(b), &c); err != nil {
			return nil, fmt.Errorf("bad stored credential: %w", err)
		}
		creds = append(creds, c)
	}
	return creds, nil
}

func randomID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err) // the OS RNG never fails in practice
	}
	return hex.EncodeToString(b)
}

// passkeysEnabled gates every WebAuthn ceremony behind the gateway-wide
// policy: when the admin disabled passkeys, registration AND sign-in refuse
// (existing credentials stay stored, revocation stays possible).
func (h *Handler) passkeysEnabled(w http.ResponseWriter, r *http.Request) bool {
	if h.st.PasskeysAllowed(r.Context()) {
		return true
	}
	http.Error(w, "passkeys are disabled by the administrator", http.StatusForbidden)
	return false
}

// passkeySession resolves a COMPLETE session (no pending step) or answers
// 401; the passkey endpoints are JSON, never redirects.
func (h *Handler) passkeySession(w http.ResponseWriter, r *http.Request) (store.Session, store.User, bool) {
	sess, err := h.sm.Resolve(r.Context(), r)
	if err != nil || sess.Pending != "" {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return store.Session{}, store.User{}, false
	}
	u, err := h.st.GetUserByID(r.Context(), sess.UserID)
	if err != nil || !u.Enabled {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return store.Session{}, store.User{}, false
	}
	return sess, u, true
}

// passkeyRegisterStart begins the enrolment ceremony: options for the browser
// plus a one-shot challenge id. Resident keys are REQUIRED so the passkey is
// discoverable (usernameless sign-in).
func (h *Handler) passkeyRegisterStart(w http.ResponseWriter, r *http.Request) {
	if !h.passkeysEnabled(w, r) {
		return
	}
	_, u, ok := h.passkeySession(w, r)
	if !ok {
		return
	}
	// Refused here rather than discovered later: a key someone registers and
	// cannot use is worse than one they were never offered.
	if allowed, why := h.passkeyRegistrationAllowed(r.Context(), u); !allowed {
		http.Error(w, why, http.StatusForbidden)
		return
	}
	wa, err := h.webAuthnFor(r)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	creds, err := h.passkeyCredentials(r, u.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	exclusions := make([]protocol.CredentialDescriptor, 0, len(creds))
	for _, c := range creds {
		exclusions = append(exclusions, c.Descriptor())
	}
	creation, session, err := wa.BeginRegistration(webauthnUser{u: u, creds: creds},
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithExclusions(exclusions),
	)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	sessJSON, err := json.Marshal(session)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	id := randomID()
	if err := h.st.PutChallenge(r.Context(), id, string(sessJSON), time.Now().Add(5*time.Minute).Unix()); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"challenge": id, "options": creation})
}

// passkeyRegisterFinish validates the authenticator's answer and stores the
// credential, labeled like a trusted browser ("Chrome · macOS").
func (h *Handler) passkeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if !h.passkeysEnabled(w, r) {
		return
	}
	_, u, ok := h.passkeySession(w, r)
	if !ok {
		return
	}
	sessJSON, err := h.st.TakeChallenge(r.Context(), r.URL.Query().Get("challenge"), time.Now().Unix())
	if err != nil {
		http.Error(w, "challenge expired: start again", http.StatusUnprocessableEntity)
		return
	}
	var session webauthn.SessionData
	if err := json.Unmarshal([]byte(sessJSON), &session); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(r.Body)
	if err != nil {
		http.Error(w, "malformed credential: "+err.Error(), http.StatusBadRequest)
		return
	}
	wa, err := h.webAuthnFor(r)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	creds, err := h.passkeyCredentials(r, u.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	cred, err := wa.CreateCredential(webauthnUser{u: u, creds: creds}, session, parsed)
	if err != nil {
		http.Error(w, "the passkey could not be verified", http.StatusUnprocessableEntity)
		return
	}
	blob, err := json.Marshal(cred)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	credID := protocol.URLEncodedBase64(cred.ID).String()
	rowID := randomID()
	if err := h.st.AddPasskey(r.Context(), rowID, u.ID, credID, string(blob), browserLabel(r)); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	setPasskeyCookie(w, r, rowID)
	w.WriteHeader(http.StatusNoContent)
}

// passkeyDelete revokes one of the user's own passkeys.
func (h *Handler) passkeyDelete(w http.ResponseWriter, r *http.Request) {
	sess, _, ok := h.passkeySession(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if _, err := h.st.RevokePasskey(r.Context(), sess.UserID, r.PostFormValue("id")); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/profile/security", http.StatusSeeOther)
}

// passkeyLoginStart begins the usernameless assertion: anyone may ask, the
// answer only carries a challenge.
func (h *Handler) passkeyLoginStart(w http.ResponseWriter, r *http.Request) {
	if !h.passkeysEnabled(w, r) {
		return
	}
	wa, err := h.webAuthnFor(r)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	assertion, session, err := wa.BeginDiscoverableLogin()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	sessJSON, err := json.Marshal(session)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	id := randomID()
	if err := h.st.PutChallenge(r.Context(), id, string(sessJSON), time.Now().Add(5*time.Minute).Unix()); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"challenge": id, "options": assertion})
}

// passkeyLoginFinish validates the assertion, updates the credential's
// counter, and issues a FULL session (a passkey carries both factors): the
// usual tenant resolution decides where the redirect chain lands, and the
// page's fetch follows it.
func (h *Handler) passkeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	if !h.passkeysEnabled(w, r) {
		return
	}
	sessJSON, err := h.st.TakeChallenge(r.Context(), r.URL.Query().Get("challenge"), time.Now().Unix())
	if err != nil {
		http.Error(w, "challenge expired: start again", http.StatusUnprocessableEntity)
		return
	}
	var session webauthn.SessionData
	if err := json.Unmarshal([]byte(sessJSON), &session); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(r.Body)
	if err != nil {
		http.Error(w, "malformed assertion: "+err.Error(), http.StatusBadRequest)
		return
	}
	wa, err := h.webAuthnFor(r)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var matched store.User
	cred, err := wa.ValidateDiscoverableLogin(func(_, userHandle []byte) (webauthn.User, error) {
		u, err := h.st.GetUserByID(r.Context(), string(userHandle))
		if err != nil || !u.Enabled {
			return nil, fmt.Errorf("unknown or disabled user")
		}
		creds, err := h.passkeyCredentials(r, u.ID)
		if err != nil {
			return nil, err
		}
		matched = u
		return webauthnUser{u: u, creds: creds}, nil
	}, session, parsed)
	if err != nil {
		http.Error(w, "the passkey could not be verified", http.StatusUnauthorized)
		return
	}
	// The key checked out; the ACCOUNT still has to. A passkey is a shortcut
	// past the authority that owns this person, not a way around it: without
	// this, disabling them in the directory would leave them a door it believes
	// it has closed (see revalidate.go).
	if ok, why := h.stillRecognised(r.Context(), matched); !ok {
		slog.Info("passkey refused: the authority no longer recognises the account",
			"user", matched.Username, "reason", why)
		http.Error(w, why, http.StatusForbidden)
		return
	}
	if blob, err := json.Marshal(cred); err == nil {
		credID := protocol.URLEncodedBase64(cred.ID).String()
		_ = h.st.UpdatePasskeyData(r.Context(), credID, string(blob))
		if rowID, err := h.st.PasskeyIDByCredential(r.Context(), matched.ID, credID); err == nil {
			setPasskeyCookie(w, r, rowID)
		}
	}
	next := safeNext(r.URL.Query().Get("next"))
	h.resolveTenantAndGo(w, r, matched, next, next, loginMethodPasskey)
}
