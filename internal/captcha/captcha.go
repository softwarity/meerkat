// Package captcha is Meerkat's home-grown anti-robot check (AUTH-20): a PNG
// of distorted digits rendered with the standard library only — no font
// files, no external service, offline like the rest of the gateway. It slows
// naive sign-up bots; the rate limit and the e-mail confirmation do the rest.
package captcha

import (
	"bytes"
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"math/rand/v2"
)

// The alphabet avoids ambiguous glyphs (0/O, 1/7 confusion stays possible on
// purpose-built fonts; ours only draws these eight).
const alphabet = "23456789"
const length = 5

// glyphs is a 5x7 bitmap font, one row per byte (5 low bits used).
var glyphs = map[byte][7]uint8{
	'2': {0b01110, 0b10001, 0b00001, 0b00010, 0b00100, 0b01000, 0b11111},
	'3': {0b11110, 0b00001, 0b00001, 0b01110, 0b00001, 0b00001, 0b11110},
	'4': {0b00010, 0b00110, 0b01010, 0b10010, 0b11111, 0b00010, 0b00010},
	'5': {0b11111, 0b10000, 0b11110, 0b00001, 0b00001, 0b10001, 0b01110},
	'6': {0b00110, 0b01000, 0b10000, 0b11110, 0b10001, 0b10001, 0b01110},
	'7': {0b11111, 0b00001, 0b00010, 0b00100, 0b01000, 0b01000, 0b01000},
	'8': {0b01110, 0b10001, 0b10001, 0b01110, 0b10001, 0b10001, 0b01110},
	'9': {0b01110, 0b10001, 0b10001, 0b01111, 0b00001, 0b00010, 0b01100},
}

// Generate mints a fresh code and its PNG. The code comes from crypto/rand;
// the visual noise may use a fast PRNG (it protects nothing).
func Generate() (code string, pngBytes []byte, err error) {
	raw := make([]byte, length+8)
	if _, err := crand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("captcha: entropy unavailable: %w", err)
	}
	b := make([]byte, length)
	for i := 0; i < length; i++ {
		b[i] = alphabet[int(raw[i])%len(alphabet)]
	}
	code = string(b)
	rng := rand.New(rand.NewPCG(binary.LittleEndian.Uint64(raw[length:]), 0))

	img, err := render(code, rng)
	if err != nil {
		return "", nil, err
	}
	return code, img, nil
}

const (
	scale  = 7                   // one font pixel -> scale x scale block
	width  = length*6*scale + 40 // 5 columns + 1 spacing, side margins
	height = 7*scale + 44        // 7 rows + room for the wave
)

func render(code string, rng *rand.Rand) ([]byte, error) {
	bg := color.NRGBA{0x14, 0x1b, 0x26, 0xff}  // sentinel night
	fg := color.NRGBA{0xc9, 0xd6, 0xe4, 0xff}  // moonlit sand
	dim := color.NRGBA{0x3c, 0x4d, 0x63, 0xff} // noise

	// Pass 1: the glyphs on a flat buffer, each with its own vertical jitter.
	flat := image.NewNRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			flat.SetNRGBA(x, y, bg)
		}
	}
	for i := 0; i < len(code); i++ {
		g := glyphs[code[i]]
		ox := 20 + i*6*scale + rng.IntN(7) - 3
		oy := 22 + rng.IntN(9) - 4
		for row := 0; row < 7; row++ {
			for col := 0; col < 5; col++ {
				if g[row]&(1<<(4-col)) == 0 {
					continue
				}
				for dy := 0; dy < scale; dy++ {
					for dx := 0; dx < scale; dx++ {
						flat.SetNRGBA(ox+col*scale+dx, oy+row*scale+dy, fg)
					}
				}
			}
		}
	}

	// Pass 2: sine-shear every column, add noise curves and speckles.
	out := image.NewNRGBA(image.Rect(0, 0, width, height))
	amp := 4.0 + rng.Float64()*3.0
	freq := 0.035 + rng.Float64()*0.02
	phase := rng.Float64() * 2 * math.Pi
	for x := 0; x < width; x++ {
		shift := int(amp * math.Sin(freq*float64(x)+phase))
		for y := 0; y < height; y++ {
			sy := y + shift
			if sy < 0 || sy >= height {
				out.SetNRGBA(x, y, bg)
				continue
			}
			out.SetNRGBA(x, y, flat.NRGBAAt(x, sy))
		}
	}
	for c := 0; c < 3; c++ {
		a := 6.0 + rng.Float64()*10.0
		f := 0.02 + rng.Float64()*0.05
		p := rng.Float64() * 2 * math.Pi
		base := 10 + rng.IntN(height-20)
		for x := 0; x < width; x++ {
			y := base + int(a*math.Sin(f*float64(x)+p))
			if y >= 0 && y < height {
				out.SetNRGBA(x, y, dim)
				if y+1 < height {
					out.SetNRGBA(x, y+1, dim)
				}
			}
		}
	}
	for i := 0; i < 220; i++ {
		out.SetNRGBA(rng.IntN(width), rng.IntN(height), dim)
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, out); err != nil {
		return nil, fmt.Errorf("captcha: encode: %w", err)
	}
	return buf.Bytes(), nil
}
