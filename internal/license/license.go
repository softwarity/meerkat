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
	ErrExpired   = errors.New("license: expired")
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
	if now.Before(lic.IssuedAt) {
		return nil, ErrNotYet
	}
	if now.After(lic.ExpiresAt) {
		return nil, ErrExpired
	}
	return &lic, nil
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
