package admin

import (
	"net/http"
	"strings"

	"github.com/softwarity/meerkat/internal/mail"
	"github.com/softwarity/meerkat/internal/store"
)

// The mail relay (AUTH-20) is INFRASTRUCTURE: a third-party service reached by
// host and port, with credentials. It belongs to the infra plane for the same
// reason a route's upstream does, and an app admin has no business holding a
// relay's password just to word an account e-mail. What the recipient SEES —
// the sender address — stays with the application (see settingsPayload.SMTP).
func (a *API) registerMailRelay(mux *http.ServeMux) {
	mux.Handle("GET /api/settings/mail-relay", a.infraAdmin(a.getMailRelay))
	mux.Handle("PUT /api/settings/mail-relay", a.infraAdmin(a.putMailRelay))
	mux.Handle("POST /api/settings/mail-relay/test", a.infraAdmin(a.testMailRelay))
}

// mailRelayPayload is the transport as the console sees it: the password is
// WRITE-ONLY — accepted on PUT ("" keeps the stored one), never returned.
type mailRelayPayload struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Security    string `json:"security"` // "" | starttls | tls | none
	Username    string `json:"username"`
	Password    string `json:"password"`
	PasswordSet bool   `json:"passwordSet"`
	// From is read-only here: it is the application's to set.
	From string `json:"from,omitempty"`
}

func (a *API) relayView(cfg mail.Config) mailRelayPayload {
	return mailRelayPayload{
		Host: cfg.Host, Port: cfg.Port, Security: cfg.Security,
		Username: cfg.Username, PasswordSet: cfg.Password != "", From: cfg.From,
	}
}

func (a *API) getMailRelay(w http.ResponseWriter, r *http.Request, _ store.User) {
	writeJSON(w, http.StatusOK, a.relayView(a.st.GetSMTP(r.Context())))
}

func (a *API) putMailRelay(w http.ResponseWriter, r *http.Request, actor store.User) {
	var p mailRelayPayload
	if err := decodeStrict(r, &p); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed mail relay: "+err.Error())
		return
	}
	switch p.Security {
	case "", "starttls", "tls", "none":
	default:
		writeErr(w, http.StatusUnprocessableEntity, "mail relay security must be starttls, tls or none")
		return
	}
	// The SENDER is not ours to change: carry the stored one forward.
	stored := a.st.GetSMTP(r.Context())
	cfg := mail.Config{
		Host: strings.TrimSpace(p.Host), Port: p.Port, Security: p.Security,
		Username: p.Username, From: stored.From, Password: p.Password,
	}
	if cfg.Password == "" {
		cfg.Password = stored.Password
	}
	if err := a.st.SetSetting(r.Context(), store.SettingSMTP, cfg); err != nil {
		a.internal(w, err)
		return
	}
	before, after := a.relayView(stored), a.relayView(cfg)
	a.auditUpdate(r.Context(), actor, "mailrelay.update", "settings", "", "", "", before, after)
	writeJSON(w, http.StatusOK, after)
}

// mailRelayTest is the relay being tried, straight from the form: testing must
// answer "does THIS work", not "did what I saved earlier work".
type mailRelayTest struct {
	mailRelayPayload
	To string `json:"to"`
}

// testMailRelay sends one message through the config IN THE PAYLOAD, without
// saving anything: an admin tries a relay, sees it work, and only then saves.
// Two fields still come from the store: the password when left blank (the
// console never receives it, so it cannot resend it) and the sender address,
// which belongs to the application plane.
func (a *API) testMailRelay(w http.ResponseWriter, r *http.Request, actor store.User) {
	var body mailRelayTest
	if err := decodeStrict(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request: "+err.Error())
		return
	}
	to := strings.TrimSpace(body.To)
	if to == "" {
		to = actor.Email
	}
	if to == "" {
		writeErr(w, http.StatusUnprocessableEntity, "no recipient: pass one, or set an email on your account")
		return
	}
	switch body.Security {
	case "", "starttls", "tls", "none":
	default:
		writeErr(w, http.StatusUnprocessableEntity, "mail relay security must be starttls, tls or none")
		return
	}
	// GetSMTP already returns the STORED relay with its references resolved.
	stored := a.st.GetSMTP(r.Context())
	// The form's own fields may still carry references ("${smtp-password}"):
	// resolve them too, or the test would try to authenticate with the literal
	// text instead of the secret.
	host, username, password := a.st.ExpandRelay(r.Context(),
		strings.TrimSpace(body.Host), body.Username, body.Password)
	cfg := mail.Config{
		Host: host, Port: body.Port, Security: body.Security,
		Username: username, From: stored.From, Password: password,
	}
	if cfg.Password == "" {
		cfg.Password = stored.Password
	}
	if cfg.Host == "" {
		writeErr(w, http.StatusUnprocessableEntity, "set a relay host before testing")
		return
	}
	if cfg.From == "" {
		writeErr(w, http.StatusUnprocessableEntity,
			"no sender address: an app admin sets it in the application settings")
		return
	}
	send := a.MailerWith
	if send == nil {
		send = mail.Send
	}
	if err := send(r.Context(), cfg, mail.Message{
		To:      []string{to},
		Subject: "Meerkat mail relay test",
		Text:    "This is Meerkat's test message. Outbound e-mail works.",
	}); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"sent": to})
}
