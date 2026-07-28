// Package signing holds the gateway-wide identity signing keys: one active key
// pair per algorithm (ES256, EdDSA, RS256), used to sign the identity JWTs a
// route forwards under the "signed-jwt" mechanism. Upstreams verify a token by
// its "kid" against the gateway's public JWKS, so a rotation (Renew) is
// transparent: the previous public keys linger in the JWKS for a grace window
// while backends refetch. Private keys never leave this package's marshalled
// blob; only the public halves are ever exposed (JWKS, PEM).
//
// The JWT wire format is hand-rolled on crypto/* (no third-party JWT library):
// base64url(header).base64url(payload).base64url(signature), the signature per
// RFC 7518 (ES256 = R||S, EdDSA = Ed25519, RS256 = RSASSA-PKCS1v15 over SHA-256).
package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// The signature algorithms a route may pick for a signed identity token.
const (
	ES256 = "ES256"
	EdDSA = "EdDSA"
	RS256 = "RS256"
)

// Algorithms is the fixed catalogue, in a stable display order.
var Algorithms = []string{ES256, EdDSA, RS256}

// DefaultGrace is how long a rotated-out public key stays in the JWKS so tokens
// signed just before a Renew keep verifying while backends refetch.
const DefaultGrace = 10 * time.Minute

// Valid reports whether alg is a supported signature algorithm.
func Valid(alg string) bool {
	return alg == ES256 || alg == EdDSA || alg == RS256
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// leftPad returns b in a fixed-width big-endian field of size bytes (JWK/JWS
// coordinates are fixed-length, unlike big.Int.Bytes()).
func leftPad(b []byte, size int) []byte {
	if len(b) >= size {
		return b[len(b)-size:]
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

// key is one active pair: its algorithm, its kid, and both halves.
type key struct {
	alg  string
	kid  string
	priv crypto.PrivateKey
	pub  crypto.PublicKey
}

// retired is a public key kept in the JWKS through its grace window.
type retired struct {
	alg       string
	kid       string
	pub       crypto.PublicKey
	retiredAt time.Time
}

// Set is the gateway's signing material: an active key per algorithm plus the
// recently rotated-out public keys still inside their grace window.
type Set struct {
	active  map[string]*key
	retired []retired
}

// Generate builds a fresh Set: one new key pair per algorithm.
func Generate() (*Set, error) {
	s := &Set{active: make(map[string]*key, len(Algorithms))}
	for _, alg := range Algorithms {
		k, err := genKey(alg)
		if err != nil {
			return nil, err
		}
		s.active[alg] = k
	}
	return s, nil
}

// Renew rotates every algorithm: the current public keys move to the grace
// list (stamped now), fresh pairs take their place, and grace-expired keys are
// dropped. now is passed in so callers control the clock (and tests are stable).
func (s *Set) Renew(now time.Time, grace time.Duration) error {
	for _, alg := range Algorithms {
		if cur := s.active[alg]; cur != nil {
			s.retired = append(s.retired, retired{alg: cur.alg, kid: cur.kid, pub: cur.pub, retiredAt: now})
		}
		k, err := genKey(alg)
		if err != nil {
			return err
		}
		s.active[alg] = k
	}
	s.purge(now, grace)
	return nil
}

// purge drops grace-expired retired keys.
func (s *Set) purge(now time.Time, grace time.Duration) {
	kept := s.retired[:0]
	for _, r := range s.retired {
		if now.Sub(r.retiredAt) < grace {
			kept = append(kept, r)
		}
	}
	s.retired = kept
}

// Kid returns the active key id for alg (empty when unknown).
func (s *Set) Kid(alg string) string {
	if k := s.active[alg]; k != nil {
		return k.kid
	}
	return ""
}

// PublicKey returns the active public key for alg (nil when unknown). Exposed
// mainly so callers and tests can verify a token they just signed.
func (s *Set) PublicKey(alg string) crypto.PublicKey {
	if k := s.active[alg]; k != nil {
		return k.pub
	}
	return nil
}

// SignJWT builds and signs a compact JWT for alg: the header carries alg/typ/kid,
// the payload is claims, the signature is over the two base64url segments.
func (s *Set) SignJWT(alg string, claims map[string]any) (string, error) {
	k := s.active[alg]
	if k == nil {
		return "", fmt.Errorf("signing: no active key for algorithm %q: allowed algorithms are %s", alg, ES256+", "+EdDSA+", "+RS256)
	}
	hb, err := json.Marshal(map[string]string{"alg": alg, "typ": "JWT", "kid": k.kid})
	if err != nil {
		return "", err
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := b64(hb) + "." + b64(cb)
	sig, err := sign(k, []byte(signingInput))
	if err != nil {
		return "", err
	}
	return signingInput + "." + b64(sig), nil
}

// PublicPEM returns the active public key for alg as an SPKI PEM block, the
// paste-into-a-backend format.
func (s *Set) PublicPEM(alg string) (string, error) {
	k := s.active[alg]
	if k == nil {
		return "", fmt.Errorf("signing: no active key for algorithm %q", alg)
	}
	der, err := x509.MarshalPKIXPublicKey(k.pub)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

// JWKS renders the public JWK Set: every active key, then the retired ones
// still inside their grace window. This is the /.well-known/jwks.json body.
func (s *Set) JWKS() ([]byte, error) {
	keys := make([]map[string]any, 0, len(Algorithms)+len(s.retired))
	for _, alg := range Algorithms {
		if k := s.active[alg]; k != nil {
			jwk, err := jwkOf(alg, k.kid, k.pub)
			if err != nil {
				return nil, err
			}
			keys = append(keys, jwk)
		}
	}
	for _, r := range s.retired {
		jwk, err := jwkOf(r.alg, r.kid, r.pub)
		if err != nil {
			return nil, err
		}
		keys = append(keys, jwk)
	}
	return json.Marshal(map[string]any{"keys": keys})
}

// ── crypto primitives ────────────────────────────────────────────────────────

func genKey(alg string) (*key, error) {
	switch alg {
	case ES256:
		p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("signing: generate ES256: %w", err)
		}
		return newKey(alg, p, p.Public())
	case EdDSA:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("signing: generate EdDSA: %w", err)
		}
		return newKey(alg, priv, pub)
	case RS256:
		p, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("signing: generate RS256: %w", err)
		}
		return newKey(alg, p, p.Public())
	}
	return nil, fmt.Errorf("signing: unknown algorithm %q", alg)
}

func newKey(alg string, priv crypto.PrivateKey, pub crypto.PublicKey) (*key, error) {
	kid, err := computeKid(pub)
	if err != nil {
		return nil, err
	}
	return &key{alg: alg, kid: kid, priv: priv, pub: pub}, nil
}

// computeKid is a stable id for a public key: the base64url head of the SHA-256
// of its PKIX DER. Deterministic, so the same key always advertises the same kid.
func computeKid(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return b64(sum[:])[:16], nil
}

func sign(k *key, input []byte) ([]byte, error) {
	switch k.alg {
	case ES256:
		h := sha256.Sum256(input)
		r, s, err := ecdsa.Sign(rand.Reader, k.priv.(*ecdsa.PrivateKey), h[:])
		if err != nil {
			return nil, err
		}
		return append(leftPad(r.Bytes(), 32), leftPad(s.Bytes(), 32)...), nil
	case EdDSA:
		return ed25519.Sign(k.priv.(ed25519.PrivateKey), input), nil
	case RS256:
		h := sha256.Sum256(input)
		return rsa.SignPKCS1v15(rand.Reader, k.priv.(*rsa.PrivateKey), crypto.SHA256, h[:])
	}
	return nil, fmt.Errorf("signing: unknown algorithm %q", k.alg)
}

// ── persistence ──────────────────────────────────────────────────────────────

type persistedKey struct {
	Alg  string `json:"alg"`
	Priv []byte `json:"priv"` // PKCS#8 DER
}

type persistedRetired struct {
	Alg       string `json:"alg"`
	Pub       []byte `json:"pub"` // PKIX DER
	RetiredAt int64  `json:"retiredAt"`
}

type persisted struct {
	Active  []persistedKey     `json:"active"`
	Retired []persistedRetired `json:"retired"`
}

// Marshal serialises the Set for the store: active keys as PKCS#8 private DER,
// retired keys as their public PKIX DER plus the retirement instant. The blob
// holds private material and must be treated as a secret (never returned by an
// API, never logged).
func (s *Set) Marshal() ([]byte, error) {
	var p persisted
	for _, alg := range Algorithms {
		k := s.active[alg]
		if k == nil {
			continue
		}
		der, err := x509.MarshalPKCS8PrivateKey(k.priv)
		if err != nil {
			return nil, fmt.Errorf("signing: marshal %s private key: %w", alg, err)
		}
		p.Active = append(p.Active, persistedKey{Alg: alg, Priv: der})
	}
	for _, r := range s.retired {
		der, err := x509.MarshalPKIXPublicKey(r.pub)
		if err != nil {
			return nil, fmt.Errorf("signing: marshal retired %s public key: %w", r.alg, err)
		}
		p.Retired = append(p.Retired, persistedRetired{Alg: r.alg, Pub: der, RetiredAt: r.retiredAt.Unix()})
	}
	return json.Marshal(p)
}

// Load rebuilds a Set from Marshal's output; kids are recomputed (deterministic).
func Load(data []byte) (*Set, error) {
	var p persisted
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("signing: load: %w", err)
	}
	s := &Set{active: make(map[string]*key, len(p.Active))}
	for _, pk := range p.Active {
		priv, err := x509.ParsePKCS8PrivateKey(pk.Priv)
		if err != nil {
			return nil, fmt.Errorf("signing: parse %s private key: %w", pk.Alg, err)
		}
		signer, ok := priv.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("signing: loaded %s key is not a signer", pk.Alg)
		}
		k, err := newKey(pk.Alg, priv, signer.Public())
		if err != nil {
			return nil, err
		}
		s.active[pk.Alg] = k
	}
	for _, pr := range p.Retired {
		pub, err := x509.ParsePKIXPublicKey(pr.Pub)
		if err != nil {
			return nil, fmt.Errorf("signing: parse retired %s public key: %w", pr.Alg, err)
		}
		kid, err := computeKid(pub)
		if err != nil {
			return nil, err
		}
		s.retired = append(s.retired, retired{alg: pr.Alg, kid: kid, pub: pub, retiredAt: time.Unix(pr.RetiredAt, 0)})
	}
	return s, nil
}

func jwkOf(alg, kid string, pub crypto.PublicKey) (map[string]any, error) {
	m := map[string]any{"use": "sig", "alg": alg, "kid": kid}
	switch p := pub.(type) {
	case *ecdsa.PublicKey:
		// Go 1.26 deprecates reading X/Y directly; the ECDH view exposes the
		// uncompressed point (0x04 || X || Y), 32 bytes each for P-256.
		ep, err := p.ECDH()
		if err != nil {
			return nil, fmt.Errorf("signing: EC public key to JWK: %w", err)
		}
		raw := ep.Bytes()
		m["kty"] = "EC"
		m["crv"] = "P-256"
		m["x"] = b64(raw[1:33])
		m["y"] = b64(raw[33:65])
	case ed25519.PublicKey:
		m["kty"] = "OKP"
		m["crv"] = "Ed25519"
		m["x"] = b64(p)
	case *rsa.PublicKey:
		m["kty"] = "RSA"
		m["n"] = b64(p.N.Bytes())
		m["e"] = b64(big.NewInt(int64(p.E)).Bytes())
	default:
		return nil, fmt.Errorf("signing: cannot render %T as a JWK", pub)
	}
	return m, nil
}
