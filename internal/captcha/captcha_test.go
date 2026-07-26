package captcha

import (
	"bytes"
	"image/png"
	"strings"
	"testing"
)

func TestGenerate(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		code, img, err := Generate()
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if len(code) != length || strings.Trim(code, alphabet) != "" {
			t.Fatalf("bad code %q", code)
		}
		m, err := png.Decode(bytes.NewReader(img))
		if err != nil {
			t.Fatalf("not a PNG: %v", err)
		}
		if m.Bounds().Dx() != width || m.Bounds().Dy() != height {
			t.Fatalf("bounds %v", m.Bounds())
		}
		seen[code] = true
	}
	if len(seen) < 2 {
		t.Fatalf("codes never vary")
	}
}
