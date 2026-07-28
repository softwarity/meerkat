package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/softwarity/meerkat/internal/signing"
)

// SettingSigningKeys holds the gateway-wide identity signing material (private
// keys included) as a settings blob. It is a SECRET: never returned by an API,
// never logged. Only the public halves leave, through the JWKS and PEM views.
const SettingSigningKeys = "identity_signing_keys"

// GetSigningSet loads the identity signing material; ok is false when none was
// ever generated (a fresh install that never used signed-jwt).
func (s *Store) GetSigningSet(ctx context.Context) (set *signing.Set, ok bool, err error) {
	var raw json.RawMessage
	if e := s.GetSetting(ctx, SettingSigningKeys, &raw); e != nil {
		if errors.Is(e, ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, e
	}
	set, err = signing.Load(raw)
	if err != nil {
		return nil, false, err
	}
	return set, true, nil
}

// EnsureSigningSet returns the signing material, generating and persisting a
// fresh set the first time it is needed.
func (s *Store) EnsureSigningSet(ctx context.Context) (*signing.Set, error) {
	set, ok, err := s.GetSigningSet(ctx)
	if err != nil {
		return nil, err
	}
	if ok {
		return set, nil
	}
	set, err = signing.Generate()
	if err != nil {
		return nil, err
	}
	if err := s.saveSigningSet(ctx, set); err != nil {
		return nil, err
	}
	return set, nil
}

// RenewSigningKeys rotates every algorithm (the previous public keys linger in
// the JWKS for the grace window) and persists the result.
func (s *Store) RenewSigningKeys(ctx context.Context) (*signing.Set, error) {
	set, err := s.EnsureSigningSet(ctx)
	if err != nil {
		return nil, err
	}
	if err := set.Renew(time.Now(), signing.DefaultGrace); err != nil {
		return nil, err
	}
	if err := s.saveSigningSet(ctx, set); err != nil {
		return nil, err
	}
	return set, nil
}

func (s *Store) saveSigningSet(ctx context.Context, set *signing.Set) error {
	blob, err := set.Marshal()
	if err != nil {
		return err
	}
	return s.SetSetting(ctx, SettingSigningKeys, json.RawMessage(blob))
}
