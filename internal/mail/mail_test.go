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
