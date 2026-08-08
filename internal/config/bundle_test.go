package config

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/softwarity/meerkat/internal/store"
)

// a 1x1 png, small enough to read in a test and real enough to decode.
const onePixel = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="

func withLogoSeeded(t *testing.T, s *store.Store) {
	t.Helper()
	var branding map[string]any
	if err := s.GetSetting(context.Background(), store.SettingBranding, &branding); err != nil {
		branding = map[string]any{}
	}
	branding["logo"] = onePixel
	if err := s.SetSetting(context.Background(), store.SettingBranding, branding); err != nil {
		t.Fatal(err)
	}
}

// TestBundleTakesTheImageOutOfTheYAML: one base64 line of up to 300 000
// characters in the middle of a file people read is the surest way to make them
// stop opening it.
func TestBundleTakesTheImageOutOfTheYAML(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	seed(t, s)
	withLogoSeeded(t, s)

	doc, _, err := Export(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	if !HasImage(doc) {
		t.Fatal("the logo should be seen")
	}
	pkg, err := MarshalBundle(doc)
	if err != nil {
		t.Fatalf("MarshalBundle: %v", err)
	}
	if !IsBundle(pkg) {
		t.Fatal("a package must be recognisable by its bytes")
	}
	if strings.Contains(string(pkg), "iVBORw0KGgo") {
		t.Fatal("the base64 should not be in the package's yaml")
	}

	// The caller's own document is untouched: it still holds its image.
	if !HasImage(doc) {
		t.Fatal("packaging must not empty the document it was given")
	}

	back, err := UnmarshalBundle(pkg)
	if err != nil {
		t.Fatalf("UnmarshalBundle: %v", err)
	}
	var branding struct {
		Logo string `json:"logo"`
	}
	if err := json.Unmarshal(back.Settings[store.SettingBranding], &branding); err != nil {
		t.Fatal(err)
	}
	if branding.Logo != onePixel {
		t.Fatalf("the logo did not come back whole: %.40q", branding.Logo)
	}
}

// TestPlainYAMLStaysSelfContained: the two forms are each complete on their
// own, so neither can produce a dangling reference.
func TestPlainYAMLStaysSelfContained(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	seed(t, s)
	withLogoSeeded(t, s)
	doc, _, err := Export(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	file, err := Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(file), "data:image/png") {
		t.Fatalf("a plain export must carry its image inline:\n%.400s", file)
	}
}

// TestBundleRefusesAMissingPicture: a document naming a file the package does
// not hold is refused, not quietly stripped - an import that loses the logo in
// silence is one nobody notices until a user does.
func TestBundleRefusesAMissingPicture(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	seed(t, s)
	withLogoSeeded(t, s)
	doc, _, err := Export(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := MarshalBundle(doc)
	if err != nil {
		t.Fatal(err)
	}
	// Rebuild the package without its picture.
	stripped := dropEntry(t, pkg, "assets/logo.png")
	if _, err := UnmarshalBundle(stripped); err == nil ||
		!strings.Contains(err.Error(), "not in the package") {
		t.Fatalf("a missing picture must be named, got %v", err)
	}
}

// TestBundleRefusesAnEscapingPath: nothing legitimate produces one, and the
// tidied version of a hostile path is still a hostile intent.
func TestBundleRefusesAnEscapingPath(t *testing.T) {
	pkg := buildZip(t, map[string][]byte{
		BundleName:         []byte("version: 1\nroles: []\n"),
		"../../etc/passwd": []byte("nope"),
	})
	if _, err := UnmarshalBundle(pkg); err == nil || !strings.Contains(err.Error(), "unusable path") {
		t.Fatalf("an escaping path must be refused, got %v", err)
	}
}

// TestNotAPackage: what an admin uploads has been through a browser and a
// download folder, so the format is decided by the bytes, not the name.
func TestNotAPackage(t *testing.T) {
	if IsBundle([]byte("version: 1\n")) {
		t.Fatal("yaml is not a package")
	}
	if _, err := UnmarshalBundle([]byte("not a zip at all")); err == nil {
		t.Fatal("a broken package must be refused")
	}
	if _, err := base64.StdEncoding.DecodeString("!"); err == nil {
		t.Fatal("sanity")
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func buildZip(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func dropEntry(t *testing.T, pkg []byte, drop string) []byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(pkg), int64(len(pkg)))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, f := range zr.File {
		if f.Name == drop {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		files[f.Name] = body
	}
	return buildZip(t, files)
}
