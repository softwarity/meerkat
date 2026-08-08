// Package mail is Meerkat's outbound e-mail: one SMTP config (a gateway-wide
// setting), one Send. Pure Go (net/smtp + crypto/tls), offline-friendly - a
// missing config is a normal, explicit error, never a crash.
package mail

import (
	"context"
	"crypto/tls"
	"fmt"
	"mime"
	"net"
	netmail "net/mail"
	"net/smtp"
	"strings"
	"time"
)

// Config is the gateway-wide SMTP setting (stored under the "smtp" key).
type Config struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	// Security: "starttls" (587, default), "tls" (465, implicit), "none".
	Security string `json:"security"`
	// Auth picks HOW the relay is authenticated: "" or "password" is the
	// ordinary account and secret, "oauth2" is XOAUTH2 with a token minted by
	// client credentials. The two are separate modes with separate fields
	// rather than one generic form, because they have nothing in common: one
	// asks for a password, the other for a tenant, an application and a scope.
	//
	// The second exists because Microsoft 365 REFUSES basic SMTP AUTH outright:
	// without it a password-only client cannot send through the relay most
	// companies actually run.
	Auth     string `json:"auth"`
	Username string `json:"username"`
	Password string `json:"password"`
	// OAuth2 holds the client-credentials settings of the "oauth2" mode.
	OAuth2 OAuth2Config `json:"oauth2"`
	// From is the sender ADDRESS. It belongs to the relay, not to the product:
	// most providers refuse (or silently rewrite) a MAIL FROM that is not the
	// account they authenticated, so it is set with the transport. Empty falls
	// back to Username when that is itself an address, the common case.
	From string `json:"from"`
	// FromName is the display name in front of the address ("Meerkat" in
	// `Meerkat <no-reply@acme.io>`). THIS is the product's to choose: it is
	// what the recipient reads, and no relay constrains it.
	FromName string `json:"fromName"`
}

// The two authentication modes.
const (
	// AuthPassword is the zero value: an account and a secret, sent as PLAIN
	// over TLS. What every transactional relay uses (SendGrid, Mailgun, SES,
	// Postmark), and what Gmail still accepts with an application password.
	AuthPassword = "password"
	// AuthOAuth2 is XOAUTH2: a token obtained by client credentials stands in
	// for the password. Required by Microsoft 365, which has switched basic
	// SMTP AUTH off for good.
	AuthOAuth2 = "oauth2"
)

// ValidAuth reports whether m is a known mode ("" reads as password).
func ValidAuth(m string) bool {
	return m == "" || m == AuthPassword || m == AuthOAuth2
}

// OAuth2Config is the client-credentials grant that mints the SMTP token. The
// mailbox is Username, as in the other mode: XOAUTH2 authenticates an
// application but still sends AS someone.
type OAuth2Config struct {
	// TokenURL is the token endpoint, e.g.
	// https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token
	TokenURL string `json:"tokenUrl"`
	ClientID string `json:"clientId"`
	// ClientSecret is a SECRET field (see idp.SecretFields for the same rule
	// on the authorities): a vault reference travels, a literal never does.
	ClientSecret string `json:"clientSecret"`
	// Scope defaults to Microsoft's SMTP scope, the only one anybody asks for
	// today, so the common case needs no typing.
	Scope string `json:"scope"`
}

// EffectiveScope is Scope, or Microsoft's SMTP scope when unset.
func (o OAuth2Config) EffectiveScope() string {
	if s := strings.TrimSpace(o.Scope); s != "" {
		return s
	}
	return "https://outlook.office365.com/.default"
}

// Address is the envelope sender: the explicit From, or the relay account when
// it is an address (a provider that only lets you send as yourself).
func (c Config) Address() string {
	if c.From != "" {
		return c.From
	}
	if strings.Contains(c.Username, "@") {
		return c.Username
	}
	return ""
}

// Sender renders the From header: the address alone, or the display name in
// front of it (RFC 2047-encoded, so an accent never breaks the header).
func (c Config) Sender() string {
	addr := c.Address()
	if addr == "" || c.FromName == "" {
		return addr
	}
	return (&netmail.Address{Name: c.FromName, Address: addr}).String()
}

// auth builds the mechanism for the configured mode. The token is minted per
// send: it is short lived, and a gateway sends few enough mails that caching
// one would buy nothing but a stale-token bug.
func (c Config) auth(ctx context.Context) (smtp.Auth, error) {
	if c.Auth == AuthOAuth2 {
		token, err := fetchToken(ctx, c.OAuth2)
		if err != nil {
			return nil, err
		}
		return xoauth2Auth{username: c.Username, token: token}, nil
	}
	return smtp.PlainAuth("", c.Username, c.Password, c.Host), nil
}

// Configured reports whether the config can send at all.
func (c Config) Configured() bool { return c.Host != "" && c.Address() != "" }

// Message is one outbound e-mail: text always, HTML optionally alongside.
type Message struct {
	To      []string
	Subject string
	Text    string
	HTML    string
}

// Send delivers msg through cfg. The dial is bounded; every failure names the
// step so an admin can act on it.
func Send(ctx context.Context, cfg Config, msg Message) error {
	if !cfg.Configured() {
		return fmt.Errorf("mail: SMTP is not configured (a host and a sender address are required; " +
			"the address defaults to the relay account when that is an e-mail)")
	}
	from, err := netmail.ParseAddress(cfg.Address())
	if err != nil {
		return fmt.Errorf("mail: bad from address %q: %w", cfg.Address(), err)
	}
	port := cfg.Port
	if port == 0 {
		port = 587
	}
	addr := net.JoinHostPort(cfg.Host, fmt.Sprint(port))

	d := net.Dialer{Timeout: 10 * time.Second}
	var conn net.Conn
	if cfg.Security == "tls" {
		conn, err = tls.DialWithDialer(&d, "tcp", addr, &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12})
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("mail: connect %s: %w", addr, err)
	}
	c, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("mail: SMTP handshake with %s: %w", addr, err)
	}
	defer func() { _ = c.Close() }()

	if cfg.Security == "" || cfg.Security == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(&tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}); err != nil {
				return fmt.Errorf("mail: STARTTLS with %s: %w", addr, err)
			}
		} else if cfg.Security == "starttls" {
			return fmt.Errorf("mail: %s does not offer STARTTLS (allowed security modes: starttls, tls, none)", addr)
		}
	}
	if cfg.Username != "" {
		auth, err := cfg.auth(ctx)
		if err != nil {
			return err
		}
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("mail: authentication refused by %s: %w", addr, err)
		}
	}
	if err := c.Mail(from.Address); err != nil {
		return fmt.Errorf("mail: sender refused: %w", err)
	}
	for _, to := range msg.To {
		if err := c.Rcpt(to); err != nil {
			return fmt.Errorf("mail: recipient %q refused: %w", to, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("mail: DATA refused: %w", err)
	}
	if _, err := w.Write(Build(cfg.Sender(), msg)); err != nil {
		return fmt.Errorf("mail: write body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("mail: message refused: %w", err)
	}
	return c.Quit()
}

// Build renders the RFC 5322 message: text/plain alone, or
// multipart/alternative when an HTML part rides along.
func Build(from string, msg Message) []byte {
	var b strings.Builder
	crlf := func(s string) {
		b.WriteString(strings.ReplaceAll(s, "\n", "\r\n"))
		b.WriteString("\r\n")
	}
	crlf("From: " + from)
	crlf("To: " + strings.Join(msg.To, ", "))
	crlf("Subject: " + mime.QEncoding.Encode("utf-8", msg.Subject))
	crlf("Date: " + time.Now().Format(time.RFC1123Z))
	crlf("MIME-Version: 1.0")
	if msg.HTML == "" {
		crlf(`Content-Type: text/plain; charset="utf-8"`)
		crlf("")
		crlf(msg.Text)
		return []byte(b.String())
	}
	const boundary = "meerkat-alt-9d41c6"
	crlf(`Content-Type: multipart/alternative; boundary="` + boundary + `"`)
	crlf("")
	crlf("--" + boundary)
	crlf(`Content-Type: text/plain; charset="utf-8"`)
	crlf("")
	crlf(msg.Text)
	crlf("--" + boundary)
	crlf(`Content-Type: text/html; charset="utf-8"`)
	crlf("")
	crlf(msg.HTML)
	crlf("--" + boundary + "--")
	return []byte(b.String())
}
