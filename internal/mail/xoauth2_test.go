package mail

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/smtp"
	"strings"
	"testing"
)

// TestXOAUTH2Framing pins the wire format. It is the part everyone gets wrong,
// because it looks like a password field and is not: the control characters
// are the mechanism's own framing, and one missing byte reads as "invalid
// credentials" with nothing to go on.
func TestXOAUTH2Framing(t *testing.T) {
	a := xoauth2Auth{username: "bot@acme.io", token: "ya29.TOKEN"}
	name, resp, err := a.Start(&smtp.ServerInfo{Name: "smtp.office365.com", TLS: true})
	if err != nil {
		t.Fatal(err)
	}
	if name != "XOAUTH2" {
		t.Fatalf("mechanism = %q", name)
	}
	want := "user=bot@acme.io\x01auth=Bearer ya29.TOKEN\x01\x01"
	if string(resp) != want {
		t.Fatalf("framing = %q, want %q", resp, want)
	}
	// What actually travels, for the record: net/smtp base64-encodes it.
	if enc := base64.StdEncoding.EncodeToString(resp); enc == "" {
		t.Fatal("empty encoding")
	}
	// A rejected token makes the server talk once more; answering empty is
	// what turns a hang into a refusal.
	next, err := a.Next([]byte(`{"status":"401"}`), true)
	if err != nil || len(next) != 0 {
		t.Fatalf("Next = %q, %v", next, err)
	}
}

// TestXOAUTH2RefusesCleartext: this hands over a bearer token, which is as
// reusable as a password and usually grants more. It must never leave on a
// connection nobody encrypted.
func TestXOAUTH2RefusesCleartext(t *testing.T) {
	a := xoauth2Auth{username: "bot@acme.io", token: "tok"}
	_, _, err := a.Start(&smtp.ServerInfo{Name: "smtp.acme.io", TLS: false})
	if err == nil || !strings.Contains(err.Error(), "unencrypted") {
		t.Fatalf("cleartext must be refused, got %v", err)
	}
}

// TestFetchTokenCarriesTheProviderWords: a wrong tenant and an application
// missing the SMTP permission both surface as "authentication refused" from
// the SMTP side. The identity provider is the only one that says which, so its
// words have to reach the admin.
func TestFetchTokenCarriesTheProviderWords(t *testing.T) {
	var gotForm string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.PostForm.Encode()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided.\r\nTrace ID: abc\r\nTimestamp: 2026-01-01"}`))
	}))
	defer srv.Close()

	_, err := fetchToken(context.Background(), OAuth2Config{
		TokenURL: srv.URL, ClientID: "cid", ClientSecret: "wrong",
	})
	if err == nil {
		t.Fatal("a refused token must be an error")
	}
	if !strings.Contains(err.Error(), "AADSTS7000215") {
		t.Fatalf("the provider's own words must come through, got %v", err)
	}
	// And without the trace: it is noise in a one-line error.
	if strings.Contains(err.Error(), "Trace ID") {
		t.Fatalf("the trailing trace should be trimmed, got %v", err)
	}

	// The same thing on ONE line, which is how the real endpoint answered when
	// this was tried against it: cutting at the newline alone was not enough.
	if got := shortReason("AADSTS900021: Requested tenant identifier is not valid. Trace ID: abc Correlation ID: def Timestamp: 2026"); got != "AADSTS900021: Requested tenant identifier is not valid." {
		t.Fatalf("single-line trim = %q", got)
	}
	// The grant is client_credentials, with Microsoft's SMTP scope by default.
	for _, want := range []string{"grant_type=client_credentials", "outlook.office365.com"} {
		if !strings.Contains(gotForm, strings.ReplaceAll(want, ":", "%3A")) &&
			!strings.Contains(gotForm, want) {
			t.Fatalf("form %q lacks %q", gotForm, want)
		}
	}
}

func TestFetchTokenSucceeds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"ya29.TOKEN","expires_in":3599}`))
	}))
	defer srv.Close()

	tok, err := fetchToken(context.Background(), OAuth2Config{
		TokenURL: srv.URL, ClientID: "cid", ClientSecret: "s", Scope: "https://graph.example/.default",
	})
	if err != nil || tok != "ya29.TOKEN" {
		t.Fatalf("token = %q, err = %v", tok, err)
	}
}

// TestOAuth2NeedsItsFields: half a configuration is refused here rather than
// discovered as an SMTP refusal three layers down.
func TestOAuth2NeedsItsFields(t *testing.T) {
	_, err := fetchToken(context.Background(), OAuth2Config{ClientID: "cid"})
	if err == nil || !strings.Contains(err.Error(), "token URL") {
		t.Fatalf("a missing token URL must be named, got %v", err)
	}
}
