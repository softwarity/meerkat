package config

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/softwarity/meerkat/internal/store"
	"github.com/softwarity/meerkat/internal/vault"
)

const pass = "correct horse battery staple"

func vaultFile(t *testing.T, entries ...vault.PortableEntry) string {
	t.Helper()
	sealed, err := vault.SealVault(entries, pass)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(sealed)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "vault.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestSeedVaultFillsAndDoesNotReplay: this is what makes an unattended start
// work - file plus passphrase, the gateway comes up complete. And the same file
// at the next restart changes nothing, so a compose that keeps it around cannot
// resurrect a secret someone rotated in the console.
func TestSeedVaultFillsAndDoesNotReplay(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	path := vaultFile(t,
		vault.PortableEntry{Name: "api-host", Kind: vault.KindValue, Scope: vault.ScopeInfra, Value: "api.internal"},
		vault.PortableEntry{Name: "smtp-password", Kind: vault.KindSecret, Scope: vault.ScopeApp, Value: "hunter2"},
	)

	done, err := SeedVault(ctx, s, path, pass, 1000)
	if err != nil || !done {
		t.Fatalf("SeedVault = %v, %v", done, err)
	}
	e, err := s.GetVaultEntry(ctx, vault.ScopeApp, "smtp-password")
	if err != nil || e.Value != "hunter2" {
		t.Fatalf("the secret was not ingested: %+v %v", e, err)
	}

	// Someone rotates it in the console, then the gateway restarts.
	if err := s.SaveVaultEntry(ctx, vault.Entry{
		Name: "smtp-password", Kind: vault.KindSecret, Scope: vault.ScopeApp, Value: "rotated",
	}); err != nil {
		t.Fatal(err)
	}
	done, err = SeedVault(ctx, s, path, pass, 2000)
	if err != nil || done {
		t.Fatalf("the file must not be replayed: %v, %v", done, err)
	}
	if e, _ := s.GetVaultEntry(ctx, vault.ScopeApp, "smtp-password"); e.Value != "rotated" {
		t.Fatalf("the rotated secret came back to %q", e.Value)
	}
}

// TestSeedVaultFillsAReservedEntry: the pairing with a configuration seed. The
// configuration reserves the names it references, the vault file fills them,
// and the route serves.
func TestSeedVaultFillsAReservedEntry(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	if _, err := s.ReserveVaultEntry(ctx, vault.Entry{
		Name: "api-host", Kind: vault.KindValue, Scope: vault.ScopeInfra,
	}); err != nil {
		t.Fatal(err)
	}
	path := vaultFile(t, vault.PortableEntry{
		Name: "api-host", Kind: vault.KindValue, Scope: vault.ScopeInfra, Value: "api.internal",
	})
	if _, err := SeedVault(ctx, s, path, pass, 1000); err != nil {
		t.Fatalf("SeedVault: %v", err)
	}
	if e, _ := s.GetVaultEntry(ctx, vault.ScopeInfra, "api-host"); e.Value != "api.internal" {
		t.Fatalf("the reserved entry was not filled: %q", e.Value)
	}
}

// TestSeedVaultNeedsItsPassphrase: named but unopenable is fatal. Coming up
// with empty references would look configured and serve nothing, which is the
// worst of both.
func TestSeedVaultNeedsItsPassphrase(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	path := vaultFile(t, vault.PortableEntry{
		Name: "api-host", Kind: vault.KindValue, Scope: vault.ScopeInfra, Value: "x",
	})
	_, err := SeedVault(ctx, s, path, "", 1000)
	if err == nil || !strings.Contains(err.Error(), "MEERKAT_VAULT_PASSPHRASE") {
		t.Fatalf("a missing passphrase must name the variable, got %v", err)
	}
	if _, err := SeedVault(ctx, s, path, "wrong passphrase here", 1000); err == nil {
		t.Fatal("a wrong passphrase must be fatal")
	}
	// Nothing was written on the way out.
	var mark VaultSeedMark
	if err := s.GetSetting(ctx, store.SettingVaultSeed, &mark); err == nil {
		t.Fatal("a failed ingest must leave no mark")
	}
}

// TestPassphraseFromFile: orchestrators mount secrets as files rather than
// putting them in an environment that shows up in every ps.
func TestPassphraseFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pass")
	if err := os.WriteFile(path, []byte(pass+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := PassphraseFrom("ignored", path)
	if err != nil {
		t.Fatal(err)
	}
	if got != pass {
		t.Fatalf("passphrase = %q (the trailing newline an editor adds must go)", got)
	}
	if got, err := PassphraseFrom("plain", ""); err != nil || got != "plain" {
		t.Fatalf("PassphraseFrom = %q, %v", got, err)
	}
}
