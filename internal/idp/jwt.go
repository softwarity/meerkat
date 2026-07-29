package idp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

// Verifying an ID token, on crypto/* alone. An authority's answer is only
// worth what its signature is worth, so this is deliberately strict: the
// algorithm must be one we asked for, the key must come from the published
// JWKS, and "none" is never a signature.

// jwk is one key of a JWKS document (RFC 7517).
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Crv string `json:"crv"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

// publicKey turns one JWK into a usable key.
func (k jwk) publicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err := b64uint(k.N)
		if err != nil {
			return nil, fmt.Errorf("jwks: bad RSA modulus: %w", err)
		}
		eb, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("jwks: bad RSA exponent: %w", err)
		}
		// The exponent is a big-endian byte string, usually 3 bytes (65537).
		var e uint64
		for _, b := range eb {
			e = e<<8 | uint64(b)
		}
		if e == 0 || e > 1<<31 {
			return nil, fmt.Errorf("jwks: RSA exponent out of range")
		}
		return &rsa.PublicKey{N: n, E: int(e)}, nil
	case "EC":
		x, err := b64uint(k.X)
		if err != nil {
			return nil, fmt.Errorf("jwks: bad EC x: %w", err)
		}
		y, err := b64uint(k.Y)
		if err != nil {
			return nil, fmt.Errorf("jwks: bad EC y: %w", err)
		}
		curve, err := curveFor(k.Crv)
		if err != nil {
			return nil, err
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, fmt.Errorf("jwks: unsupported OKP curve %q", k.Crv)
		}
		raw, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("jwks: bad Ed25519 key")
		}
		return ed25519.PublicKey(raw), nil
	default:
		return nil, fmt.Errorf("jwks: unsupported key type %q", k.Kty)
	}
}

// verifyJWT checks the signature and returns the raw claims. It does NOT judge
// the content: issuer, audience, nonce and expiry are the caller's business,
// and keeping them there makes each check visible at its call site.
func verifyJWT(token string, keys []jwk) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("id token: expected three dot-separated parts, got %d", len(parts))
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("id token: unreadable header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return nil, fmt.Errorf("id token: malformed header: %w", err)
	}
	if header.Alg == "" || strings.EqualFold(header.Alg, "none") {
		return nil, fmt.Errorf("id token: refused algorithm %q", header.Alg)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("id token: unreadable signature: %w", err)
	}
	signed := []byte(parts[0] + "." + parts[1])

	// A kid picks its key; without one, every key of the matching type is
	// tried, which is what an authority publishing a single key expects.
	var tried int
	for _, k := range keys {
		if header.Kid != "" && k.Kid != "" && k.Kid != header.Kid {
			continue
		}
		pub, err := k.publicKey()
		if err != nil {
			continue
		}
		tried++
		if err := verifySignature(header.Alg, pub, signed, sig); err == nil {
			payload, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				return nil, fmt.Errorf("id token: unreadable payload: %w", err)
			}
			var claims map[string]any
			if err := json.Unmarshal(payload, &claims); err != nil {
				return nil, fmt.Errorf("id token: malformed payload: %w", err)
			}
			return claims, nil
		}
	}
	if tried == 0 {
		return nil, fmt.Errorf("id token: no published key matches kid %q", header.Kid)
	}
	return nil, fmt.Errorf("id token: signature does not verify")
}

func verifySignature(alg string, pub crypto.PublicKey, signed, sig []byte) error {
	switch alg {
	case "RS256", "RS384", "RS512":
		key, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("key is not RSA")
		}
		h, hash := digest(alg, signed)
		return rsa.VerifyPKCS1v15(key, hash, h, sig)
	case "PS256", "PS384", "PS512":
		key, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("key is not RSA")
		}
		h, hash := digest(alg, signed)
		return rsa.VerifyPSS(key, hash, h, sig, nil)
	case "ES256", "ES384", "ES512":
		key, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("key is not EC")
		}
		h, _ := digest(alg, signed)
		// JWS carries R||S, fixed width, not the ASN.1 form.
		n := (key.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*n {
			return fmt.Errorf("bad ECDSA signature length")
		}
		r := new(big.Int).SetBytes(sig[:n])
		s := new(big.Int).SetBytes(sig[n:])
		if !ecdsa.Verify(key, h, r, s) {
			return fmt.Errorf("ECDSA signature does not verify")
		}
		return nil
	case "EdDSA":
		key, ok := pub.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("key is not Ed25519")
		}
		if !ed25519.Verify(key, signed, sig) {
			return fmt.Errorf("Ed25519 signature does not verify")
		}
		return nil
	default:
		return fmt.Errorf("unsupported algorithm %q", alg)
	}
}

func digest(alg string, b []byte) ([]byte, crypto.Hash) {
	switch {
	case strings.HasSuffix(alg, "384"):
		sum := sha512.Sum384(b)
		return sum[:], crypto.SHA384
	case strings.HasSuffix(alg, "512"):
		sum := sha512.Sum512(b)
		return sum[:], crypto.SHA512
	default:
		sum := sha256.Sum256(b)
		return sum[:], crypto.SHA256
	}
}

func curveFor(crv string) (elliptic.Curve, error) {
	switch crv {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("jwks: unsupported EC curve %q", crv)
	}
}

func b64uint(s string) (*big.Int, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty value")
	}
	return new(big.Int).SetBytes(raw), nil
}

// claimString reads a string claim, tolerating the numbers some authorities
// send for ids.
func claimString(claims map[string]any, key string) string {
	switch v := claims[key].(type) {
	case string:
		return v
	case float64:
		return fmt.Sprintf("%.0f", v)
	case json.Number:
		return v.String()
	}
	return ""
}

// claimStrings reads a list claim (groups, roles), tolerating a single string
// and the space-separated form some authorities use.
func claimStrings(claims map[string]any, key string) []string {
	switch v := claims[key].(type) {
	case string:
		return strings.Fields(v)
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// claimBool reads a boolean claim, tolerating the "true"/"false" strings that
// some authorities send for email_verified.
func claimBool(claims map[string]any, key string) bool {
	switch v := claims[key].(type) {
	case bool:
		return v
	case string:
		return v == "true"
	}
	return false
}

// audienceHas reports whether the "aud" claim, string or list, names us.
func audienceHas(claims map[string]any, clientID string) bool {
	switch v := claims["aud"].(type) {
	case string:
		return v == clientID
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == clientID {
				return true
			}
		}
	}
	return false
}

// claimTime reads a numeric date claim (RFC 7519 §2).
func claimTime(claims map[string]any, key string) (int64, bool) {
	switch v := claims[key].(type) {
	case float64:
		return int64(v), true
	case int64:
		return v, true
	}
	return 0, false
}
