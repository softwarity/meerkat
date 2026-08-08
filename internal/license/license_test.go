package license

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

func testLicense() License {
	return License{
		Licensee:  "ACME Corp",
		Plan:      "enterprise",
		Features:  []string{"directories", "cluster"},
		IssuedAt:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

func TestParseValid(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	data, err := Sign(testLicense(), priv)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	lic, err := Parse(data, []ed25519.PublicKey{pub}, now)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if lic.Licensee != "ACME Corp" || len(lic.Features) != 2 {
		t.Fatalf("unexpected payload: %+v", lic)
	}
}

func TestParseRejectsWrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	data, _ := Sign(testLicense(), priv)
	_, err := Parse(data, []ed25519.PublicKey{otherPub}, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC))
	if !errors.Is(err, ErrSignature) {
		t.Fatalf("want ErrSignature, got %v", err)
	}
}

func TestParseRejectsTampering(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	data, _ := Sign(testLicense(), priv)
	data[20] ^= 0xff
	if _, err := Parse(data, []ed25519.PublicKey{pub}, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("tampered license accepted")
	}
}

// A license is perpetual: long past its expiry date it still validates and
// still carries its features. Whoever paid keeps what they paid for - cutting
// authentication over a lapsed subscription would make this undeployable in
// front of a production.
func TestParseStaysValidPastExpiry(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	data, _ := Sign(testLicense(), priv)
	lic, err := Parse(data, []ed25519.PublicKey{pub}, time.Date(2038, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("a perpetual license must survive its expiry date: %v", err)
	}
	if len(lic.Features) == 0 {
		t.Fatal("features must still be carried")
	}
	// What the date DOES say: how far updates were paid for. A build from
	// before it is covered, one from after is not - and that is only ever
	// reported, never enforced.
	if !lic.Covered(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("a build released during the term must be covered")
	}
	if lic.Covered(time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("a build released after the term must be reported as uncovered")
	}
}

func TestParseRejectsNotYetValid(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	data, _ := Sign(testLicense(), priv)
	_, err := Parse(data, []ed25519.PublicKey{pub}, time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))
	if !errors.Is(err, ErrNotYet) {
		t.Fatalf("want ErrNotYet, got %v", err)
	}
}

func TestParseRejectsNoKeys(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	data, _ := Sign(testLicense(), priv)
	if _, err := Parse(data, nil, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)); !errors.Is(err, ErrSignature) {
		t.Fatalf("want ErrSignature, got %v", err)
	}
}
