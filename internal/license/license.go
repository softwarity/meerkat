// Package license validates Softwarity-issued license files offline.
//
// A license file is a JSON envelope carrying a payload and its ed25519
// signature. Validation never makes a network call: the signing public keys
// ship with the binary. A valid, unexpired license unlocks the Enterprise
// features listed in its payload (see internal/features and the ee/ tree).
package license

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// Errors returned by Parse.
var (
	ErrSignature = errors.New("license: invalid signature")
	ErrNotYet    = errors.New("license: not valid yet")
)

// productionKeys holds the Softwarity signing public keys embedded in
// released binaries. Empty until the first commercial release; keeping
// several entries allows key rotation without invalidating older licenses.
var productionKeys []ed25519.PublicKey

// License is the signed payload of a license file.
type License struct {
	Licensee  string    `json:"licensee"`
	Plan      string    `json:"plan"`
	Features  []string  `json:"features"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// envelope is the on-disk representation of a license file.
type envelope struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

// Load reads and validates a license file against the embedded production
// keys, using the current time.
func Load(path string) (*License, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("license: %w", err)
	}
	return Parse(data, productionKeys, time.Now())
}

// Parse validates a license file against the given public keys at the given
// instant. It is the testable core of Load.
//
// A license is PERPETUAL: whoever paid keeps the right to run what they paid
// for, and an expiry date never turns anything off. It says how far updates
// are covered - a build released after it is outside the deal - which Covered
// reports so the console and the log can say so without anyone being locked
// out of their own gateway. Cutting authentication over a late invoice would
// make this unusable in front of a production, and nobody serious would
// deploy it.
func Parse(data []byte, keys []ed25519.PublicKey, now time.Time) (*License, error) {
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("license: malformed file: %w", err)
	}
	if !verify(env, keys) {
		return nil, ErrSignature
	}
	var lic License
	if err := json.Unmarshal(env.Payload, &lic); err != nil {
		return nil, fmt.Errorf("license: malformed payload: %w", err)
	}
	// Not-yet-valid is refused: that is a minting mistake, not a customer.
	if now.Before(lic.IssuedAt) {
		return nil, ErrNotYet
	}
	return &lic, nil
}

// Covered reports whether a build dated buildDate falls within what this
// license paid for. False does NOT disable anything - it is what the log and
// the Licence screen say to explain that an update went past the coverage.
func (l *License) Covered(buildDate time.Time) bool {
	return !buildDate.After(l.ExpiresAt)
}

func verify(env envelope, keys []ed25519.PublicKey) bool {
	for _, key := range keys {
		if ed25519.Verify(key, env.Payload, env.Signature) {
			return true
		}
	}
	return false
}

// Sign produces a license file for the given payload. It lives here so the
// (private) issuing tool and the validator can never drift apart.
func Sign(lic License, key ed25519.PrivateKey) ([]byte, error) {
	payload, err := json.Marshal(lic)
	if err != nil {
		return nil, fmt.Errorf("license: %w", err)
	}
	env := envelope{Payload: payload, Signature: ed25519.Sign(key, payload)}
	return json.MarshalIndent(env, "", "  ")
}
