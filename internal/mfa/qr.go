package mfa

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image"
	"image/color"
	"image/png"

	"rsc.io/qr"
)

// QRDataURI renders text (an otpauth:// URI) as a PNG QR code and returns it as
// a data: URI ready to drop into an <img src>. Everything is computed in-process
// - no external QR service - so enrolment works on an air-gapped gateway.
//
// The bitmap is drawn by hand from code.Black(): rsc.io/qr's own Image() ignores
// its Scale field (it maps image pixels 1:1 to modules, leaving the QR tiny in a
// corner), so we scale each module up ourselves and add a quiet zone.
func QRDataURI(text string) (string, error) {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", fmt.Errorf("mfa: encode QR: %w", err)
	}
	const scale, quiet = 6, 4 // pixels per module, and the mandatory 4-module margin
	size := code.Size
	dim := (size + 2*quiet) * scale
	img := image.NewGray(image.Rect(0, 0, dim, dim))
	// White field first.
	for i := range img.Pix {
		img.Pix[i] = 0xff
	}
	black := color.Gray{Y: 0x00}
	for my := 0; my < size; my++ {
		for mx := 0; mx < size; mx++ {
			if !code.Black(mx, my) {
				continue
			}
			x0, y0 := (mx+quiet)*scale, (my+quiet)*scale
			for dy := 0; dy < scale; dy++ {
				for dx := 0; dx < scale; dx++ {
					img.SetGray(x0+dx, y0+dy, black)
				}
			}
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", fmt.Errorf("mfa: render QR: %w", err)
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}
