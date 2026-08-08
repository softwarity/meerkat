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
// committing to it - and a failed attempt leaves the stored relay untouched.
// The sender ADDRESS is part of that relay (a provider only accepts the account
// it authenticated), so it is tried from the payload too; only the display NAME
// comes from the application.
func TestMailRelayTestDoesNotSave(t *testing.T) {
	f := setup(t)
	ctx := context.Background()

	if err := f.api.st.SetSetting(ctx, store.SettingSMTP, mail.Config{
		From: "saved@example.com", FromName: "Acme", Host: "saved.example.com", Port: 25,
	}); err != nil {
		t.Fatal(err)
	}

	var used mail.Config
	f.api.MailerWith = func(_ context.Context, cfg mail.Config, _ mail.Message) error {
		used = cfg
		return nil
	}

	body := `{"host":"tried.example.com","port":2525,"security":"tls","username":"u",` +
		`"password":"","from":"tried@example.com","to":"probe@example.com"}`
	if code, out := f.call(t, "POST", "/api/settings/mail-relay/test", body, f.rootC); code != http.StatusOK {
		t.Fatalf("test: %d %s", code, out)
	}
	// It tried the PAYLOAD's relay, address included.
	if used.Host != "tried.example.com" || used.Port != 2525 || used.Security != "tls" {
		t.Fatalf("the test did not use the payload relay: %+v", used)
	}
	if used.From != "tried@example.com" {
		t.Fatalf("the test must try the address on screen, got %+v", used)
	}
	// The display name is the application's, so it rides along from the store.
	if used.Sender() != `"Acme" <tried@example.com>` {
		t.Fatalf("sender header: %q", used.Sender())
	}
	// And it saved NOTHING.
	if stored := f.api.st.GetSMTP(ctx); stored.Host != "saved.example.com" || stored.From != "saved@example.com" {
		t.Fatalf("testing must not persist the relay, got %+v", stored)
	}

	// Only an infra admin may fire it.
	if code, _ := f.call(t, "POST", "/api/settings/mail-relay/test", body, f.plainC); code != http.StatusForbidden {
		t.Fatalf("relay test authz: %d, want 403", code)
	}

	// Saving persists the address with the transport, and keeps the app's name.
	save := `{"host":"kept.example.com","port":465,"security":"tls","username":"u",` +
		`"password":"p","from":"kept@example.com"}`
	if code, out := f.call(t, "PUT", "/api/settings/mail-relay", save, f.rootC); code != http.StatusOK {
		t.Fatalf("save: %d %s", code, out)
	}
	stored := f.api.st.GetSMTP(ctx)
	if stored.Host != "kept.example.com" || stored.From != "kept@example.com" || stored.FromName != "Acme" {
		t.Fatalf("save lost the address or the display name: %+v", stored)
	}
	// The relay view never returns the password.
	if _, out := f.call(t, "GET", "/api/settings/mail-relay", "", f.rootC); strings.Contains(out, `"p"`) {
		t.Fatalf("the relay view leaked the password: %s", out)
	}
}

// TestMailRelayAddressDefaultsToTheAccount: most providers refuse a sender that
// is not the authenticated account, so leaving the address empty means "send as
// the account" whenever the account is itself an address - no second field to
// keep in sync, and no silent failure at the provider.
func TestMailRelayAddressDefaultsToTheAccount(t *testing.T) {
	f := setup(t)
	var used mail.Config
	f.api.MailerWith = func(_ context.Context, cfg mail.Config, _ mail.Message) error {
		used = cfg
		return nil
	}
	body := `{"host":"smtp.example.com","port":587,"security":"starttls",` +
		`"username":"robot@example.com","password":"x","from":"","to":"probe@example.com"}`
	if code, out := f.call(t, "POST", "/api/settings/mail-relay/test", body, f.rootC); code != http.StatusOK {
		t.Fatalf("test: %d %s", code, out)
	}
	if used.Address() != "robot@example.com" {
		t.Fatalf("an empty address must fall back to the account, got %q", used.Address())
	}

	// A relay account that is NOT an address leaves nothing to send as: say so
	// rather than letting the provider reject the message later.
	nonAddr := `{"host":"smtp.example.com","port":587,"security":"starttls",` +
		`"username":"robot","password":"x","from":"","to":"probe@example.com"}`
	code, out := f.call(t, "POST", "/api/settings/mail-relay/test", nonAddr, f.rootC)
	if code != http.StatusUnprocessableEntity || !strings.Contains(out, "sender address") {
		t.Fatalf("missing sender: %d %s", code, out)
	}
}

// TestMailRelayTestResolvesVaultRefs: the form may hold "${smtp-password}"
// rather than the secret itself, so the test must resolve it before connecting
// - otherwise it would authenticate with the literal text and fail for the
// wrong reason. Every relay field, the sender address included, resolves in the
// INFRA scope: an app admin cannot decide what the relay authenticates with.
func TestMailRelayTestResolvesVaultRefs(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	// Same name in both planes: only the infra one must answer.
	for _, e := range []vault.Entry{
		{Name: "smtp-password", Kind: vault.KindSecret, Scope: vault.ScopeInfra, Value: "real-secret"},
		{Name: "smtp-password", Kind: vault.KindSecret, Scope: vault.ScopeApp, Value: "wrong-plane"},
		{Name: "smtp-host", Kind: vault.KindValue, Scope: vault.ScopeInfra, Value: "relay.example.com"},
		{Name: "smtp-from", Kind: vault.KindValue, Scope: vault.ScopeInfra, Value: "no-reply@example.com"},
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
		`"password":"${smtp-password}","from":"${smtp-from}","to":"probe@example.com"}`
	if code, out := f.call(t, "POST", "/api/settings/mail-relay/test", body, f.rootC); code != http.StatusOK {
		t.Fatalf("test: %d %s", code, out)
	}
	if used.Password != "real-secret" {
		t.Fatalf("the password reference was not resolved in the infra scope: %q", used.Password)
	}
	if used.Host != "relay.example.com" {
		t.Fatalf("the host reference was not resolved: %q", used.Host)
	}
	if used.From != "no-reply@example.com" {
		t.Fatalf("the sender reference was not resolved: %q", used.From)
	}
}
