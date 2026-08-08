package mfa

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"strings"
	"testing"
	"time"
)

// rfcSecret is the RFC 6238 Appendix B test seed ("12345678901234567890")
// encoded as base32 - the well-known "GEZDGNBVGY3TQOJQ..." secret.
var rfcSecret = secretEnc.EncodeToString([]byte("12345678901234567890"))

// TestCodeRFC6238Vectors checks our TOTP against the RFC 6238 Appendix B
// vectors, truncated to the 6 digits Meerkat uses (the RFC prints 8).
func TestCodeRFC6238Vectors(t *testing.T) {
	cases := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	}
	for _, c := range cases {
		got, err := Code(rfcSecret, time.Unix(c.unix, 0))
		if err != nil {
			t.Fatalf("Code at %d: %v", c.unix, err)
		}
		if got != c.want {
			t.Errorf("Code at %d = %s, want %s", c.unix, got, c.want)
		}
	}
}

func TestValidateAcceptsSkew(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	code, err := Code(rfcSecret, now)
	if err != nil {
		t.Fatal(err)
	}
	// The exact step and the two neighbours are accepted (±30s skew).
	for _, skew := range []time.Duration{0, -30 * time.Second, 30 * time.Second} {
		if !Validate(rfcSecret, code, now.Add(skew)) {
			t.Errorf("code rejected at skew %s, want accepted", skew)
		}
	}
	// Two steps away is outside the window.
	if Validate(rfcSecret, code, now.Add(90*time.Second)) {
		t.Error("code accepted 90s away, want rejected")
	}
	// A code from a distant step is not valid now.
	far, _ := Code(rfcSecret, now.Add(10*time.Minute))
	if far != code && Validate(rfcSecret, far, now) {
		t.Error("a code from a distant step was accepted")
	}
}

func TestValidateRejectsMalformed(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	for _, bad := range []string{"", "12345", "1234567", "abcdef"} {
		if Validate(rfcSecret, bad, now) {
			t.Errorf("Validate accepted malformed code %q", bad)
		}
	}
}

func TestProvisioningURI(t *testing.T) {
	uri := ProvisioningURI("Meerkat", "alice@example.com", rfcSecret)
	for _, want := range []string{"otpauth://totp/", "secret=" + rfcSecret, "issuer=Meerkat", "period=30", "digits=6"} {
		if !strings.Contains(uri, want) {
			t.Errorf("provisioning URI %q missing %q", uri, want)
		}
	}
}

func TestScratchCodesHashRoundTrip(t *testing.T) {
	plain, hashed, err := NewScratchCodes(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(plain) != 10 || len(hashed) != 10 {
		t.Fatalf("got %d plain / %d hashed, want 10 each", len(plain), len(hashed))
	}
	seen := map[string]bool{}
	for i, code := range plain {
		if seen[code] {
			t.Errorf("duplicate scratch code %q", code)
		}
		seen[code] = true
		if HashScratch(code) != hashed[i] {
			t.Errorf("hash mismatch for %q", code)
		}
		// Normalisation: case and dashes are ignored on entry.
		if HashScratch(strings.ToUpper(strings.ReplaceAll(code, "-", ""))) != hashed[i] {
			t.Errorf("normalisation failed for %q", code)
		}
	}
	if HashScratch("not-a-real-code") == hashed[0] {
		t.Error("unrelated code hashed to a stored value")
	}
}

func TestNewSecretDecodable(t *testing.T) {
	s, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Code(s, time.Now()); err != nil {
		t.Errorf("fresh secret not usable: %v", err)
	}
}

func TestQRDataURI(t *testing.T) {
	uri, err := QRDataURI(ProvisioningURI("Meerkat", "alice", rfcSecret))
	if err != nil {
		t.Fatal(err)
	}
	const prefix = "data:image/png;base64,"
	if !strings.HasPrefix(uri, prefix) {
		t.Fatalf("QR data URI has wrong prefix: %.30s", uri)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(uri, prefix))
	if err != nil {
		t.Fatalf("QR is not valid base64: %v", err)
	}
	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("QR is not a valid PNG: %v", err)
	}
	b := img.Bounds()
	if b.Dx() != b.Dy() || b.Dx() < 200 {
		t.Fatalf("QR image is %dx%d, want a square ≥200px", b.Dx(), b.Dy())
	}
	// The QR must fill the canvas, not sit tiny in a corner: check for black
	// pixels in the right half AND the bottom half.
	rightHalf, bottomHalf := false, false
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			g, _, _, _ := img.At(x, y).RGBA()
			if g < 0x8000 {
				if x > b.Min.X+b.Dx()/2 {
					rightHalf = true
				}
				if y > b.Min.Y+b.Dy()/2 {
					bottomHalf = true
				}
			}
		}
	}
	if !rightHalf || !bottomHalf {
		t.Fatalf("QR modules only in a corner (right=%v bottom=%v) - Scale not applied", rightHalf, bottomHalf)
	}
}
