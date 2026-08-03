package mail

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"net/url"
	"strings"
	"time"
)

// XOAUTH2, the mode Microsoft 365 leaves as the only way in.
//
// Two halves. A token is minted by the client-credentials grant, which is a
// plain form post; then that token replaces the password in a SASL exchange
// whose payload is not a password at all but a small framed string. Both are
// short, and neither is worth a dependency.

// tokenClient is the one used to reach the token endpoint. Separate from the
// SMTP dial so a hanging identity provider cannot hold a send open.
var tokenClient = &http.Client{Timeout: 15 * time.Second}

// fetchToken runs the client-credentials grant and returns the access token.
// Errors name the endpoint, because the two things that go wrong here (a wrong
// tenant in the URL, an application without the SMTP permission) look the same
// from the SMTP side: "authentication refused".
func fetchToken(ctx context.Context, cfg OAuth2Config) (string, error) {
	endpoint := strings.TrimSpace(cfg.TokenURL)
	if endpoint == "" || strings.TrimSpace(cfg.ClientID) == "" {
		return "", fmt.Errorf("mail: the oauth2 mode needs a token URL and a client id")
	}
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {cfg.ClientID},
		"client_secret": {cfg.ClientSecret},
		"scope":         {cfg.EffectiveScope()},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("mail: token request for %s: %w", endpoint, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := tokenClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("mail: token endpoint %s unreachable: %w", endpoint, err)
	}
	defer func() { _ = res.Body.Close() }()

	var payload struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		return "", fmt.Errorf("mail: token endpoint %s answered %s, unreadable: %w",
			endpoint, res.Status, err)
	}
	// An identity provider says what is wrong in the body, and it is usually
	// precise ("AADSTS7000215: invalid client secret"). Carry it through
	// instead of replacing it with a status code.
	if payload.Error != "" {
		msg := payload.Error
		if payload.Description != "" {
			msg += ": " + shortReason(payload.Description)
		}
		return "", fmt.Errorf("mail: token refused by %s: %s", endpoint, msg)
	}
	if payload.AccessToken == "" {
		return "", fmt.Errorf("mail: token endpoint %s returned no access token (%s)",
			endpoint, res.Status)
	}
	return payload.AccessToken, nil
}

// shortReason trims a provider's error description to the part that helps.
// Microsoft appends a trace id, a correlation id and a timestamp, and it does
// so SOMETIMES behind a newline and sometimes on the same line, so cutting at
// the line break alone leaves the noise in half the cases (observed against
// the real endpoint). The markers are cut as well.
func shortReason(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	for _, marker := range []string{"Trace ID:", "Correlation ID:", "Timestamp:"} {
		if i := strings.Index(s, marker); i >= 0 {
			s = s[:i]
		}
	}
	return strings.TrimSpace(s)
}

// xoauth2Auth is the SASL XOAUTH2 mechanism. net/smtp ships PLAIN and CRAM-MD5
// only, and the interface is small enough that implementing it beats pulling a
// library in for one exchange.
type xoauth2Auth struct {
	username string
	token    string
}

// Start hands over the whole credential at once: XOAUTH2 has no challenge in
// the success case. The framing is the mechanism's own, control characters
// included, and is not base64 here: net/smtp encodes what Start returns.
func (a xoauth2Auth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	// Refuse to speak on a connection nobody encrypted: this hands over a
	// bearer token, which is as reusable as a password and usually broader.
	if !server.TLS {
		return "", nil, fmt.Errorf("mail: refusing to send an OAuth2 token to %s over an unencrypted connection", server.Name)
	}
	resp := []byte("user=" + a.username + "\x01auth=Bearer " + a.token + "\x01\x01")
	return "XOAUTH2", resp, nil
}

// Next is reached only when the server rejects the token: it then sends a
// base64 JSON error and waits for an empty answer before failing the command.
// Answering it is what turns a protocol hang into a clean refusal.
func (a xoauth2Auth) Next(_ []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	return []byte(""), nil
}
