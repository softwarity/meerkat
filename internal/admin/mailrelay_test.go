package admin

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/softwarity/meerkat/internal/mail"
	"github.com/softwarity/meerkat/internal/store"
	"github.com/softwarity/meerkat/internal/vault"
)

// TestMailRelayTestDoesNotSave is the point of splitting Test from Save: the
// test tries the relay ON SCREEN, so an admin can check a host before
// committing to it — and a failed attempt leaves the stored relay untouched.
func TestMailRelayTestDoesNotSave(t *testing.T) {
	f := setup(t)
	ctx := context.Background()

	// A sender is required to send at all; it belongs to the application plane.
	if err := f.api.st.SetSetting(ctx, store.SettingSMTP,
		mail.Config{From: "no-reply@example.com", Host: "saved.example.com", Port: 25}); err != nil {
		t.Fatal(err)
	}

	var used mail.Config
	f.api.MailerWith = func(_ context.Context, cfg mail.Config, _ mail.Message) error {
		used = cfg
		return nil
	}

	body := `{"host":"tried.example.com","port":2525,"security":"tls","username":"u","password":"","to":"probe@example.com"}`
	if code, out := f.call(t, "POST", "/api/settings/mail-relay/test", body, f.rootC); code != http.StatusOK {
		t.Fatalf("test: %d %s", code, out)
	}
	// It tried the PAYLOAD's relay, with the stored sender.
	if used.Host != "tried.example.com" || used.Port != 2525 || used.Security != "tls" {
		t.Fatalf("the test did not use the payload relay: %+v", used)
	}
	if used.From != "no-reply@example.com" {
		t.Fatalf("the sender must come from the application settings: %+v", used)
	}
	// And it saved NOTHING.
	if stored := f.api.st.GetSMTP(ctx); stored.Host != "saved.example.com" || stored.Port != 25 {
		t.Fatalf("testing must not persist the relay, got %+v", stored)
	}

	// Only an infra admin may fire it.
	if code, _ := f.call(t, "POST", "/api/settings/mail-relay/test", body, f.plainC); code != http.StatusForbidden {
		t.Fatalf("relay test authz: %d, want 403", code)
	}

	// Saving, on the other hand, does persist — and keeps the sender.
	save := `{"host":"kept.example.com","port":465,"security":"tls","username":"u","password":"p"}`
	if code, out := f.call(t, "PUT", "/api/settings/mail-relay", save, f.rootC); code != http.StatusOK {
		t.Fatalf("save: %d %s", code, out)
	}
	stored := f.api.st.GetSMTP(ctx)
	if stored.Host != "kept.example.com" || stored.From != "no-reply@example.com" {
		t.Fatalf("save lost the sender or the host: %+v", stored)
	}
	// The relay view never returns the password.
	if _, out := f.call(t, "GET", "/api/settings/mail-relay", "", f.rootC); strings.Contains(out, `"p"`) {
		t.Fatalf("the relay view leaked the password: %s", out)
	}
}

// TestMailRelayTestResolvesVaultRefs: the form may hold "${smtp-password}"
// rather than the secret itself, so the test must resolve it before connecting
// — otherwise it would authenticate with the literal text and fail for the
// wrong reason. The reference resolves in the INFRA scope, where the relay
// lives: an app admin cannot decide what the relay authenticates with.
func TestMailRelayTestResolvesVaultRefs(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if err := f.api.st.SetSetting(ctx, store.SettingSMTP, mail.Config{From: "no-reply@example.com"}); err != nil {
		t.Fatal(err)
	}
	// Same name in both planes: only the infra one must answer.
	for _, e := range []vault.Entry{
		{Name: "smtp-password", Kind: vault.KindSecret, Scope: vault.ScopeInfra, Value: "real-secret"},
		{Name: "smtp-password", Kind: vault.KindSecret, Scope: vault.ScopeApp, Value: "wrong-plane"},
		{Name: "smtp-host", Kind: vault.KindValue, Scope: vault.ScopeInfra, Value: "relay.example.com"},
	} {
		if err := f.api.st.SaveVaultEntry(ctx, e); err != nil {
			t.Fatal(err)
		}
	}

	var used mail.Config
	f.api.MailerWith = func(_ context.Context, cfg mail.Config, _ mail.Message) error {
		used = cfg
		return nil
	}
	body := `{"host":"${smtp-host}","port":587,"security":"starttls","username":"u",` +
		`"password":"${smtp-password}","to":"probe@example.com"}`
	if code, out := f.call(t, "POST", "/api/settings/mail-relay/test", body, f.rootC); code != http.StatusOK {
		t.Fatalf("test: %d %s", code, out)
	}
	if used.Password != "real-secret" {
		t.Fatalf("the password reference was not resolved in the infra scope: %q", used.Password)
	}
	if used.Host != "relay.example.com" {
		t.Fatalf("the host reference was not resolved: %q", used.Host)
	}
}
