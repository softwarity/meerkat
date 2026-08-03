package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/softwarity/meerkat/internal/store"
	"github.com/softwarity/meerkat/internal/vault"
)

const goodPass = "correct horse battery staple"

// seedVaultEntries fills a gateway's vault with one of each kind.
func seedVaultEntries(t *testing.T, f fixture) {
	t.Helper()
	ctx := context.Background()
	for _, e := range []vault.Entry{
		{Name: "api-host", Kind: vault.KindValue, Scope: vault.ScopeInfra, Value: "api.internal"},
		{Name: "smtp-password", Kind: vault.KindSecret, Scope: vault.ScopeApp, Value: "hunter2"},
	} {
		if err := f.api.st.SaveVaultEntry(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
}

// TestVaultFileRoundTrip: a vault leaves encrypted and lands whole in another
// gateway. This is the half a configuration export deliberately does not carry.
func TestVaultFileRoundTrip(t *testing.T) {
	from := setup(t)
	seedVaultEntries(t, from)

	code, file := from.call(t, "POST", "/api/vault/export",
		`{"passphrase":"`+goodPass+`"}`, from.rootC)
	if code != http.StatusOK {
		t.Fatalf("export: %d %s", code, file)
	}
	for _, secret := range []string{"hunter2", "api.internal", "smtp-password"} {
		if strings.Contains(file, secret) {
			t.Fatalf("%q is readable in the exported file:\n%s", secret, file)
		}
	}

	to := setup(t)
	code, out := to.call(t, "POST", "/api/vault/import",
		`{"passphrase":"`+goodPass+`","file":`+file+`}`, to.rootC)
	if code != http.StatusOK {
		t.Fatalf("import: %d %s", code, out)
	}
	ctx := context.Background()
	e, err := to.api.st.GetVaultEntry(ctx, vault.ScopeApp, "smtp-password")
	if err != nil || e.Value != "hunter2" {
		t.Fatalf("the secret did not travel: %+v %v", e, err)
	}
	if e.Kind != vault.KindSecret {
		t.Fatalf("a secret must land as a secret, got %q", e.Kind)
	}
}

// TestVaultImportFillsReservedEntriesAndLeavesTheRestAlone is the pairing that
// makes the two files work together: a configuration import reserves the names
// it expects, the vault file fills them. And an entry that already holds
// something is never overwritten behind the admin's back — importing a vault
// over a running gateway is exactly when one is least able to tell which of two
// values is the right one.
func TestVaultImportFillsReservedEntriesAndLeavesTheRestAlone(t *testing.T) {
	from := setup(t)
	seedVaultEntries(t, from)
	_, file := from.call(t, "POST", "/api/vault/export", `{"passphrase":"`+goodPass+`"}`, from.rootC)

	to := setup(t)
	ctx := context.Background()
	// One reserved (empty), one already holding a different value.
	if _, err := to.api.st.ReserveVaultEntry(ctx, vault.Entry{
		Name: "api-host", Kind: vault.KindValue, Scope: vault.ScopeInfra,
	}); err != nil {
		t.Fatal(err)
	}
	if err := to.api.st.SaveVaultEntry(ctx, vault.Entry{
		Name: "smtp-password", Kind: vault.KindSecret, Scope: vault.ScopeApp, Value: "mine",
	}); err != nil {
		t.Fatal(err)
	}

	code, out := to.call(t, "POST", "/api/vault/import",
		`{"passphrase":"`+goodPass+`","file":`+file+`}`, to.rootC)
	if code != http.StatusOK {
		t.Fatalf("import: %d %s", code, out)
	}
	var report struct {
		Filled, Conflicts, Created []string
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Filled) != 1 || report.Filled[0] != "api-host" {
		t.Fatalf("the reserved entry should have been filled: %s", out)
	}
	if len(report.Conflicts) != 1 {
		t.Fatalf("the entry already holding a value should be a conflict: %s", out)
	}
	if e, _ := to.api.st.GetVaultEntry(ctx, vault.ScopeApp, "smtp-password"); e.Value != "mine" {
		t.Fatalf("a conflicting entry must be left alone, got %q", e.Value)
	}
	// Asked explicitly, it does replace.
	code, out = to.call(t, "POST", "/api/vault/import",
		`{"passphrase":"`+goodPass+`","file":`+file+`,"overwrite":true}`, to.rootC)
	if code != http.StatusOK {
		t.Fatalf("import: %d %s", code, out)
	}
	if e, _ := to.api.st.GetVaultEntry(ctx, vault.ScopeApp, "smtp-password"); e.Value != "hunter2" {
		t.Fatalf("overwrite was asked for, got %q", e.Value)
	}
}

// TestVaultExportRefusesAWeakPassphrase: this one file holds every secret of
// the installation, so the floor is not negotiable.
func TestVaultExportRefusesAWeakPassphrase(t *testing.T) {
	f := setup(t)
	seedVaultEntries(t, f)
	code, out := f.call(t, "POST", "/api/vault/export", `{"passphrase":"meerkat"}`, f.rootC)
	if code != http.StatusUnprocessableEntity || !strings.Contains(out, "too short") {
		t.Fatalf("a weak passphrase must be refused: %d %s", code, out)
	}
}

// TestVaultImportRefusesTheWrongPassphrase, with the words an admin can act on.
func TestVaultImportRefusesTheWrongPassphrase(t *testing.T) {
	f := setup(t)
	seedVaultEntries(t, f)
	_, file := f.call(t, "POST", "/api/vault/export", `{"passphrase":"`+goodPass+`"}`, f.rootC)

	to := setup(t)
	code, out := to.call(t, "POST", "/api/vault/import",
		`{"passphrase":"something else entirely","file":`+file+`}`, to.rootC)
	if code != http.StatusUnprocessableEntity || !strings.Contains(out, "passphrase") {
		t.Fatalf("a wrong passphrase must be refused clearly: %d %s", code, out)
	}
}

// TestVaultFileStaysInTheCallersScopes: the vault is transverse, so an export
// carries what the caller administers and nothing else — a tenant admin moving
// their own entries cannot walk off with the infrastructure's.
func TestVaultFileStaysInTheCallersScopes(t *testing.T) {
	f := setup(t)
	seedVaultEntries(t, f)
	ctx := context.Background()
	if err := f.api.st.UpdateUser(ctx, store.User{
		ID: "bob", Username: "bob", Enabled: true, AppAdmin: true,
	}); err != nil {
		t.Fatal(err)
	}
	code, file := f.call(t, "POST", "/api/vault/export", `{"passphrase":"`+goodPass+`"}`, f.plainC)
	if code != http.StatusOK {
		t.Fatalf("export: %d %s", code, file)
	}
	var doc vault.PortableFile
	if err := json.Unmarshal([]byte(file), &doc); err != nil {
		t.Fatal(err)
	}
	entries, err := vault.OpenVault(&doc, goodPass)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Scope != vault.ScopeApp {
			t.Fatalf("an app admin exported a %s entry: %+v", e.Scope, e)
		}
	}
}
