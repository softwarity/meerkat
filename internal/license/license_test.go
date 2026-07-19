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
		Features:  []string{"sso-oidc", "cluster"},
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

func TestParseRejectsExpired(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	data, _ := Sign(testLicense(), priv)
	_, err := Parse(data, []ed25519.PublicKey{pub}, time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC))
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("want ErrExpired, got %v", err)
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
