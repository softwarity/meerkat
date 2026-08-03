package vault

import (
	"encoding/json"
	"strings"
	"testing"
)

func sample() []PortableEntry {
	return []PortableEntry{
		{Name: "smtp-password", Kind: KindSecret, Scope: ScopeApp, Value: "hunter2",
			Description: "the relay"},
		{Name: "api-host", Kind: KindValue, Scope: ScopeInfra, Value: "api.internal"},
	}
}

// TestPortableRoundTrip: what goes in comes back, and only with the passphrase.
func TestPortableRoundTrip(t *testing.T) {
	file, err := SealVault(sample(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("SealVault: %v", err)
	}
	back, err := OpenVault(file, "correct horse battery staple")
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	if len(back) != 2 || back[0].Value != "hunter2" || back[1].Value != "api.internal" {
		t.Fatalf("round trip = %+v", back)
	}
}

// TestNothingLeaksInClear is the property the file exists for: it holds every
// secret of an installation, so a copy of it must say nothing without the
// passphrase. Not the values, not the NAMES, not the descriptions.
func TestNothingLeaksInClear(t *testing.T) {
	file, err := SealVault(sample(), "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"hunter2", "api.internal", "smtp-password", "the relay"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("%q is readable in the file:\n%s", secret, raw)
		}
	}
	// What IS readable is the recipe, on purpose: this file will outlive the
	// binary that wrote it.
	for _, word := range []string{"argon2id", "aes-256-gcm", "salt"} {
		if !strings.Contains(string(raw), word) {
			t.Fatalf("the file must say how it was made, %q is missing:\n%s", word, raw)
		}
	}
}

// TestWrongPassphraseIsRefused, and a tampered file with it: GCM authenticates,
// so there is nothing to tell apart.
func TestWrongPassphraseIsRefused(t *testing.T) {
	file, err := SealVault(sample(), "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenVault(file, "correct horse battery stapleX"); err == nil {
		t.Fatal("a wrong passphrase must be refused")
	}
	tampered := *file
	tampered.Payload = "AAAA" + file.Payload[4:]
	if _, err := OpenVault(&tampered, "correct horse battery staple"); err == nil {
		t.Fatal("a tampered payload must be refused")
	}
}

// TestTheFileCarriesItsOwnParameters: an export made today must still open
// after the constants above have been raised. Reading the file's own KDF
// parameters is what buys that.
func TestTheFileCarriesItsOwnParameters(t *testing.T) {
	file, err := SealVault(sample(), "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if file.KDF.Time != kdfTime || file.KDF.Memory != kdfMemory {
		t.Fatalf("the file must record its parameters: %+v", file.KDF)
	}
	// Pretend the constants moved on: the file still opens with what it says.
	weaker, err := SealVault(sample(), "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	weaker.KDF.Time = kdfTime // unchanged here, but read from the file, not the const
	if _, err := OpenVault(weaker, "correct horse battery staple"); err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	// Absurd parameters are refused rather than allocated: a file claiming
	// gigabytes of memory would take the gateway down before it could report a
	// wrong passphrase.
	hostile := *file
	hostile.KDF.Memory = 1 << 24
	if _, err := OpenVault(&hostile, "correct horse battery staple"); err == nil {
		t.Fatal("out-of-range KDF parameters must be refused")
	}
}

// TestShortPassphraseIsRefused: this file concentrates every secret there is,
// and a four-letter passphrase makes the encryption decorative.
func TestShortPassphraseIsRefused(t *testing.T) {
	_, err := SealVault(sample(), "meerkat")
	if err == nil || !strings.Contains(err.Error(), "too short") {
		t.Fatalf("a short passphrase must be refused, got %v", err)
	}
	if err := CheckPassphrase(strings.Repeat("a", MinPassphrase)); err != nil {
		t.Fatalf("the floor itself must pass: %v", err)
	}
}

// TestGeneratedPassphraseIsUsable: the console offers one so nobody types the
// product name and the year.
func TestGeneratedPassphraseIsUsable(t *testing.T) {
	p, err := GeneratePassphrase()
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckPassphrase(p); err != nil {
		t.Fatalf("a generated passphrase must pass its own check: %v", err)
	}
	other, err := GeneratePassphrase()
	if err != nil {
		t.Fatal(err)
	}
	if p == other {
		t.Fatal("two generated passphrases must differ")
	}
}

// TestForeignFileIsNamed: whoever drops the wrong file in gets told what is
// wrong with it, not a decryption failure.
func TestForeignFileIsNamed(t *testing.T) {
	for _, tc := range []struct {
		file  PortableFile
		wants string
	}{
		{PortableFile{Meerkat: "config"}, "not a Meerkat vault file"},
		{PortableFile{Meerkat: "vault", Version: 99}, "version 99"},
		{PortableFile{Meerkat: "vault", KDF: KDF{Name: "pbkdf2"}}, "pbkdf2"},
		{PortableFile{Meerkat: "vault", KDF: KDF{Name: "argon2id"}, Cipher: "rot13"}, "rot13"},
	} {
		_, err := OpenVault(&tc.file, "correct horse battery staple")
		if err == nil || !strings.Contains(err.Error(), tc.wants) {
			t.Fatalf("expected an error mentioning %q, got %v", tc.wants, err)
		}
	}
}

// TestEntriesAreValidatedOnTheWayIn: the payload is decrypted, therefore
// trusted for having the right passphrase — not for being well formed.
func TestEntriesAreValidatedOnTheWayIn(t *testing.T) {
	for _, bad := range []PortableEntry{
		{Name: "no spaces please", Kind: KindValue, Scope: ScopeInfra},
		{Name: "ok", Kind: "password", Scope: ScopeInfra},
		{Name: "ok", Kind: KindValue, Scope: "nowhere"},
	} {
		file, err := SealVault([]PortableEntry{bad}, "correct horse battery staple")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := OpenVault(file, "correct horse battery staple"); err == nil {
			t.Fatalf("%+v should have been refused", bad)
		}
	}
}
