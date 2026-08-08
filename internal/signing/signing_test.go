package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

func d64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64url decode %q: %v", s, err)
	}
	return b
}

// verifyToken checks the signature with the raw public key and returns the
// decoded header and claims. It reproduces exactly what a backend does.
func verifyToken(t *testing.T, alg string, pub crypto.PublicKey, token string) (map[string]any, map[string]any) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("%s: token is not header.payload.signature: %q", alg, token)
	}
	input := []byte(parts[0] + "." + parts[1])
	sig := d64(t, parts[2])
	switch alg {
	case ES256:
		h := sha256.Sum256(input)
		if len(sig) != 64 {
			t.Fatalf("ES256 signature must be 64 bytes, got %d", len(sig))
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(pub.(*ecdsa.PublicKey), h[:], r, s) {
			t.Fatal("ES256 signature does not verify")
		}
	case EdDSA:
		if !ed25519.Verify(pub.(ed25519.PublicKey), input, sig) {
			t.Fatal("EdDSA signature does not verify")
		}
	case RS256:
		h := sha256.Sum256(input)
		if err := rsa.VerifyPKCS1v15(pub.(*rsa.PublicKey), crypto.SHA256, h[:], sig); err != nil {
			t.Fatalf("RS256 signature does not verify: %v", err)
		}
	default:
		t.Fatalf("unknown alg %q", alg)
	}
	var header, claims map[string]any
	if err := json.Unmarshal(d64(t, parts[0]), &header); err != nil {
		t.Fatalf("header not json: %v", err)
	}
	if err := json.Unmarshal(d64(t, parts[1]), &claims); err != nil {
		t.Fatalf("payload not json: %v", err)
	}
	return header, claims
}

// TestSignAndVerifyAllAlgorithms signs a token per algorithm and verifies it
// with the matching public key, and checks the header carries alg/typ/kid.
func TestSignAndVerifyAllAlgorithms(t *testing.T) {
	set, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, alg := range Algorithms {
		claims := map[string]any{"iss": "meerkat", "sub": "u1", "preferred_username": "neo"}
		token, err := set.SignJWT(alg, claims)
		if err != nil {
			t.Fatalf("%s SignJWT: %v", alg, err)
		}
		header, got := verifyToken(t, alg, set.PublicKey(alg), token)
		if header["alg"] != alg || header["typ"] != "JWT" {
			t.Fatalf("%s header wrong: %+v", alg, header)
		}
		if header["kid"] != set.Kid(alg) {
			t.Fatalf("%s header kid %v != set kid %q", alg, header["kid"], set.Kid(alg))
		}
		if got["sub"] != "u1" || got["preferred_username"] != "neo" {
			t.Fatalf("%s claims wrong: %+v", alg, got)
		}
	}
}

// TestJWKSVerifiesES256 rebuilds the EC public key from the published JWKS
// coordinates and verifies a token with it - proving the JWKS is usable, not
// just well-shaped.
func TestJWKSVerifiesES256(t *testing.T) {
	set, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	token, err := set.SignJWT(ES256, map[string]any{"sub": "u1"})
	if err != nil {
		t.Fatalf("SignJWT: %v", err)
	}

	raw, err := set.JWKS()
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(raw, &jwks); err != nil {
		t.Fatalf("JWKS not json: %v", err)
	}
	var ec *ecdsa.PublicKey
	for _, k := range jwks.Keys {
		if k["alg"] != ES256 {
			continue
		}
		if k["kty"] != "EC" || k["crv"] != "P-256" {
			t.Fatalf("ES256 JWK wrong kty/crv: %+v", k)
		}
		if k["kid"] != set.Kid(ES256) {
			t.Fatalf("ES256 JWK kid %q != %q", k["kid"], set.Kid(ES256))
		}
		ec = &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(d64(t, k["x"])),
			Y:     new(big.Int).SetBytes(d64(t, k["y"])),
		}
	}
	if ec == nil {
		t.Fatal("no ES256 key in JWKS")
	}
	verifyToken(t, ES256, ec, token)
}

// TestRenewRotatesAndKeepsGrace: a Renew changes every kid, keeps the old
// public keys in the JWKS during the grace window, and drops them after.
func TestRenewRotatesAndKeepsGrace(t *testing.T) {
	set, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	oldKids := map[string]string{}
	for _, alg := range Algorithms {
		oldKids[alg] = set.Kid(alg)
	}

	t0 := time.Unix(1_700_000_000, 0)
	if err := set.Renew(t0, DefaultGrace); err != nil {
		t.Fatalf("Renew: %v", err)
	}
	for _, alg := range Algorithms {
		if set.Kid(alg) == oldKids[alg] {
			t.Fatalf("%s kid did not change on renew", alg)
		}
	}
	// JWKS now holds the 3 fresh + 3 retired keys, old kids still present.
	present := jwksKids(t, set)
	if len(present) != 6 {
		t.Fatalf("want 6 JWKS keys during grace, got %d", len(present))
	}
	for _, alg := range Algorithms {
		if !present[oldKids[alg]] {
			t.Fatalf("retired %s kid %q missing from JWKS during grace", alg, oldKids[alg])
		}
	}

	// A second renew well past the grace window purges the first batch.
	if err := set.Renew(t0.Add(2*DefaultGrace), DefaultGrace); err != nil {
		t.Fatalf("Renew 2: %v", err)
	}
	present = jwksKids(t, set)
	for _, alg := range Algorithms {
		if present[oldKids[alg]] {
			t.Fatalf("grace-expired %s kid %q should be purged", alg, oldKids[alg])
		}
	}
}

func jwksKids(t *testing.T, set *Set) map[string]bool {
	t.Helper()
	raw, err := set.JWKS()
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(raw, &jwks); err != nil {
		t.Fatalf("JWKS not json: %v", err)
	}
	out := map[string]bool{}
	for _, k := range jwks.Keys {
		out[k["kid"]] = true
	}
	return out
}

// TestMarshalLoadRoundTrip: a loaded Set signs tokens that verify against its
// (recomputed) public keys, with stable kids, and keeps retired keys.
func TestMarshalLoadRoundTrip(t *testing.T) {
	set, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := set.Renew(time.Unix(1_700_000_000, 0), DefaultGrace); err != nil {
		t.Fatalf("Renew: %v", err)
	}
	blob, err := set.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	loaded, err := Load(blob)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, alg := range Algorithms {
		if loaded.Kid(alg) != set.Kid(alg) {
			t.Fatalf("%s kid not stable across marshal: %q vs %q", alg, loaded.Kid(alg), set.Kid(alg))
		}
		token, err := loaded.SignJWT(alg, map[string]any{"sub": "u1"})
		if err != nil {
			t.Fatalf("%s SignJWT after load: %v", alg, err)
		}
		verifyToken(t, alg, loaded.PublicKey(alg), token)
	}
	if len(jwksKids(t, loaded)) != 6 {
		t.Fatal("loaded set lost its retired keys")
	}
}
