package admin

import (
	"net/http"
	"strings"

	"github.com/softwarity/meerkat/internal/mail"
	"github.com/softwarity/meerkat/internal/store"
	"github.com/softwarity/meerkat/internal/vault"
)

// The mail relay (AUTH-20) is INFRASTRUCTURE: a third-party service reached by
// host and port, with credentials. It belongs to the infra plane for the same
// reason a route's upstream does, and an app admin has no business holding a
// relay's password just to word an account e-mail.
//
// The sender ADDRESS lives here too, because it is not really a free choice: a
// provider refuses (or rewrites) a MAIL FROM that is not the account it just
// authenticated, so the address travels with the credentials. What the product
// does choose is the display NAME in front of it, and that stays with the
// application (see settingsPayload.SMTP).
func (a *API) registerMailRelay(mux *http.ServeMux) {
	mux.Handle("GET /api/settings/mail-relay", a.infraAdmin(a.getMailRelay))
	mux.Handle("PUT /api/settings/mail-relay", a.infraAdmin(a.putMailRelay))
	mux.Handle("POST /api/settings/mail-relay/test", a.infraAdmin(a.testMailRelay))
}

// mailRelayPayload is the transport as the console sees it. Same rule as
// everywhere else: a REFERENCE is public and comes back as itself, a LITERAL
// password never leaves - it is accepted on PUT ("" keeps the stored one) and
// only reported as being set.
type mailRelayPayload struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Security string `json:"security"` // "" | starttls | tls | none
	// Auth is the mode: "" or "password", or "oauth2". The two carry
	// different fields and are edited as different forms.
	Auth     string `json:"auth"`
	Username string `json:"username"`
	Password string `json:"password"`
	// PasswordSet says a LITERAL password is stored: something is configured
	// that this payload does not carry. A reference is carried, so it does not
	// raise this flag - the console tells the two states apart by that.
	PasswordSet bool `json:"passwordSet"`
	// From is the sender ADDRESS, editable here. Empty means "the account", as
	// long as Username is itself an address.
	From string `json:"from"`
	// FromName is read-only here: the display name is the application's to set.
	FromName string `json:"fromName,omitempty"`
	// Sender is what the recipient will actually see, address and name
	// combined: the console shows it rather than making an admin guess.
	Sender string `json:"sender,omitempty"`
	// OAuth2 carries the client-credentials settings of the oauth2 mode. Its
	// client secret follows the rule every secret follows (VAULT-05): a
	// reference travels, a literal never does and only raises OAuth2SecretSet.
	OAuth2          mail.OAuth2Config `json:"oauth2"`
	OAuth2SecretSet bool              `json:"oauth2SecretSet"`
}

// relayView takes the relay AS STORED, so every editable field comes back the
// way it was written, references included.
func (a *API) relayView(cfg mail.Config) mailRelayPayload {
	v := mailRelayPayload{
		Host: cfg.Host, Port: cfg.Port, Security: cfg.Security,
		Username: cfg.Username, From: cfg.From, FromName: cfg.FromName,
	}
	if vault.IsRef(cfg.Password) {
		v.Password = cfg.Password
	} else {
		v.PasswordSet = cfg.Password != ""
	}
	v.Auth = cfg.Auth
	v.OAuth2 = cfg.OAuth2
	// Same treatment as the password: the literal is stripped, a reference
	// stays, or the console could not show WHICH vault entry is used.
	if !vault.IsRef(cfg.OAuth2.ClientSecret) {
		v.OAuth2.ClientSecret = ""
		v.OAuth2SecretSet = cfg.OAuth2.ClientSecret != ""
	}
	return v
}

func (a *API) getMailRelay(w http.ResponseWriter, r *http.Request, _ store.User) {
	v := a.relayView(a.st.RawSMTP(r.Context()))
	// Sender is the one READ-ONLY field: it previews what a recipient will
	// actually see, so it is answered from the RESOLVED relay. Showing
	// "${mail-from}" there would preview nothing.
	v.Sender = a.st.GetSMTP(r.Context()).Sender()
	writeJSON(w, http.StatusOK, v)
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
	// The display NAME is not ours to change: carry the stored one forward.
	// Read the relay UNRESOLVED, or saving would replace every reference the
	// form carries with whatever it currently resolves to.
	stored := a.st.RawSMTP(r.Context())
	if !mail.ValidAuth(p.Auth) {
		writeErr(w, http.StatusUnprocessableEntity,
			"mail relay authentication must be "+mail.AuthPassword+" or "+mail.AuthOAuth2)
		return
	}
	cfg := mail.Config{
		Host: strings.TrimSpace(p.Host), Port: p.Port, Security: p.Security,
		Auth: p.Auth, Username: p.Username, From: strings.TrimSpace(p.From),
		FromName: stored.FromName, Password: p.Password, OAuth2: p.OAuth2,
	}
	// Both secrets are carried forward when the form sends nothing: the console
	// never received the literal, so a blank means "leave it alone" rather than
	// "erase it" (VAULT-05).
	if cfg.Password == "" {
		cfg.Password = stored.Password
	}
	if strings.TrimSpace(cfg.OAuth2.ClientSecret) == "" {
		cfg.OAuth2.ClientSecret = stored.OAuth2.ClientSecret
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
		Auth: body.Auth, Username: username,
		From:     a.st.ExpandInfra(r.Context(), strings.TrimSpace(body.From)),
		FromName: stored.FromName, Password: password, OAuth2: body.OAuth2,
	}
	if cfg.Password == "" {
		cfg.Password = stored.Password
	}
	// The oauth2 side is resolved and carried forward the same way: a test has
	// to try what the form holds, secrets included, without ever asking the
	// console to resend one it never received.
	if strings.TrimSpace(cfg.OAuth2.ClientSecret) == "" {
		cfg.OAuth2.ClientSecret = stored.OAuth2.ClientSecret
	} else {
		cfg.OAuth2.ClientSecret = a.st.ExpandInfra(r.Context(), cfg.OAuth2.ClientSecret)
	}
	cfg.OAuth2.TokenURL = a.st.ExpandInfra(r.Context(), strings.TrimSpace(cfg.OAuth2.TokenURL))
	cfg.OAuth2.ClientID = a.st.ExpandInfra(r.Context(), strings.TrimSpace(cfg.OAuth2.ClientID))
	if cfg.Host == "" {
		writeErr(w, http.StatusUnprocessableEntity, "set a relay host before testing")
		return
	}
	if cfg.Address() == "" {
		writeErr(w, http.StatusUnprocessableEntity,
			"no sender address: set one, or use a relay account that is an e-mail address")
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
