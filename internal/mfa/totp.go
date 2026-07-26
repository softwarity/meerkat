// Package mfa implements the second factor Meerkat offers on the auth flow
// (MFA-01): time-based one-time passwords (TOTP, RFC 6238) plus single-use
// scratch codes. It is deliberately self-contained and offline — the whole
// gateway must run without reaching the internet, so the algorithm is pure
// standard library and the enrolment QR code is rendered locally (see qr.go).
package mfa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// The RFC 6238 parameters authenticator apps default to: SHA-1, 6 digits, a
// 30-second step. Changing any of these would break already-enrolled apps, so
// they are fixed.
const (
	digits = 6
	period = 30 // seconds per step
	mod    = 1_000_000
)

// secretEnc is the base32 alphabet (no padding) authenticator apps expect in
// the otpauth:// secret parameter.
var secretEnc = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret returns a fresh random TOTP secret as a base32 string (160 bits,
// the RFC 4226 recommendation).
func NewSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("mfa: generate secret: %w", err)
	}
	return secretEnc.EncodeToString(b), nil
}

// Code returns the TOTP for secret at time t (mainly for tests and for showing
// nothing to the user — the server only ever validates).
func Code(secret string, t time.Time) (string, error) {
	return hotp(secret, uint64(t.Unix())/period)
}

// Validate reports whether code is the TOTP for secret around now, tolerating
// one step of clock skew on either side (the usual ±30s window). The digit
// comparison is constant-time.
func Validate(secret, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != digits {
		return false
	}
	counter := now.Unix() / period
	for _, skew := range []int64{0, -1, 1} {
		want, err := hotp(secret, uint64(counter+skew))
		if err != nil {
			return false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

// hotp is the RFC 4226 HMAC-based one-time password for a counter, which TOTP
// derives from the current time.
func hotp(secret string, counter uint64) (string, error) {
	key, err := secretEnc.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", fmt.Errorf("mfa: invalid secret: %w", err)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := uint32(sum[off]&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	return fmt.Sprintf("%0*d", digits, bin%mod), nil
}

// ProvisioningURI builds the otpauth:// URI an authenticator app scans (or the
// user types by hand). issuer/account label the entry in the app.
func ProvisioningURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", strconv.Itoa(digits))
	q.Set("period", strconv.Itoa(period))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// scratchAlphabet excludes visually ambiguous characters (0/O, 1/l/I) so a
// backup code read off paper is entered correctly.
const scratchAlphabet = "23456789abcdefghjkmnpqrstuvwxyz"

// NewScratchCodes returns n single-use backup codes and their storage hashes.
// The plaintext is shown to the user exactly once; only the hashes persist, so
// a stolen database cannot be used to authenticate.
func NewScratchCodes(n int) (plain, hashed []string, err error) {
	for i := 0; i < n; i++ {
		code, err := randomScratch()
		if err != nil {
			return nil, nil, err
		}
		plain = append(plain, code)
		hashed = append(hashed, HashScratch(code))
	}
	return plain, hashed, nil
}

// HashScratch normalises a scratch code (lower-case, dashes stripped) and
// returns its SHA-256 hex digest — the form stored and compared. Codes are
// high-entropy random strings, so a fast hash is adequate (no bcrypt needed).
func HashScratch(code string) string {
	norm := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
	sum := sha256.Sum256([]byte(norm))
	return hex.EncodeToString(sum[:])
}

// randomScratch draws a "xxxxx-xxxxx" code from the unambiguous alphabet.
func randomScratch() (string, error) {
	const groups, per = 2, 5
	b := make([]byte, groups*per)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("mfa: generate scratch code: %w", err)
	}
	var sb strings.Builder
	for i, c := range b {
		if i > 0 && i%per == 0 {
			sb.WriteByte('-')
		}
		sb.WriteByte(scratchAlphabet[int(c)%len(scratchAlphabet)])
	}
	return sb.String(), nil
}
