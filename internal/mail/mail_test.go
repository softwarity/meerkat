package mail

import (
	"strings"
	"testing"
)

func TestBuildPlainText(t *testing.T) {
	raw := string(Build("Meerkat <no-reply@test>", Message{
		To: []string{"a@test"}, Subject: "Vérifiez votre adresse", Text: "line1\nline2",
	}))
	for _, want := range []string{
		"From: Meerkat <no-reply@test>\r\n",
		"To: a@test\r\n",
		"MIME-Version: 1.0\r\n",
		`Content-Type: text/plain; charset="utf-8"`,
		"line1\r\nline2\r\n",
	} {
		if !strings.Contains(raw, want) {
			t.Fatalf("missing %q in:\n%s", want, raw)
		}
	}
	// A non-ASCII subject is RFC 2047 encoded.
	if strings.Contains(raw, "Subject: Vérifiez votre adresse") {
		t.Fatalf("subject must be encoded:\n%s", raw)
	}
	if !strings.Contains(raw, "Subject: =?utf-8?") {
		t.Fatalf("no encoded subject in:\n%s", raw)
	}
}

func TestBuildMultipart(t *testing.T) {
	raw := string(Build("no-reply@test", Message{
		To: []string{"a@test"}, Subject: "hi", Text: "text", HTML: "<p>html</p>",
	}))
	for _, want := range []string{
		"multipart/alternative",
		`Content-Type: text/plain; charset="utf-8"`,
		`Content-Type: text/html; charset="utf-8"`,
		"<p>html</p>",
	} {
		if !strings.Contains(raw, want) {
			t.Fatalf("missing %q in:\n%s", want, raw)
		}
	}
}

func TestSendRefusesUnconfigured(t *testing.T) {
	err := Send(t.Context(), Config{}, Message{To: []string{"a@test"}, Subject: "x", Text: "y"})
	if err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("want explicit not-configured error, got %v", err)
	}
}

// TestSenderHeaderCarriesTheDisplayName: the address is the relay's (a provider
// only accepts the account it authenticated), the name in front of it is the
// product's. A non-ASCII name must be encoded, or the header breaks.
func TestSenderHeaderCarriesTheDisplayName(t *testing.T) {
	cases := []struct {
		cfg  Config
		want string
	}{
		{Config{From: "no-reply@acme.io"}, "no-reply@acme.io"},
		{Config{From: "no-reply@acme.io", FromName: "Acme"}, `"Acme" <no-reply@acme.io>`},
		{Config{Username: "robot@acme.io"}, "robot@acme.io"},
		{Config{Username: "robot", From: ""}, ""},
	}
	for _, c := range cases {
		if got := c.cfg.Sender(); got != c.want {
			t.Fatalf("Sender() for %+v = %q, want %q", c.cfg, got, c.want)
		}
	}
	// An accent survives as an RFC 2047 encoded word, and the address stays raw.
	got := Config{From: "no-reply@acme.io", FromName: "Sécurité"}.Sender()
	if !strings.Contains(got, "=?utf-8?") || !strings.HasSuffix(got, "<no-reply@acme.io>") {
		t.Fatalf("accented display name not encoded: %q", got)
	}
	// And that header is the one the message carries.
	if body := string(Build(got, Message{To: []string{"a@b.c"}, Subject: "s", Text: "t"})); !strings.Contains(body, "From: "+got) {
		t.Fatalf("the built message does not carry the sender header:\n%s", body)
	}
}
