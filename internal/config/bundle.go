package config

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/softwarity/meerkat/internal/store"
)

// A configuration with its images (CFG-05).
//
// The application logo lives in the branding setting as a data URI, and it is
// the only binary a configuration carries. Left inline it is one base64 line of
// up to 300 000 characters in the middle of a file people read and diff - the
// surest way to make them stop opening it.
//
// So a document with an image travels as a ZIP: the YAML, and the picture next
// to it. What matters is that BOTH forms stay self-contained - the plain YAML
// keeps its data URI, and the assets/ path only ever exists inside a package
// that carries the file it names. A dangling reference cannot be produced by
// either. Someone who unzips and imports the YAML alone gets the rule that
// governs everything else here: what the file does not carry, it does not
// destroy - the logo in place stays, and the import says so.

// BundleName is the document's name inside a package.
const BundleName = "meerkat.yaml"

// assetDir holds the pictures a package carries.
const assetDir = "assets"

// dataURIPrefixes are the image forms the branding accepts, mapped to the file
// extension they get inside a package.
var dataURIPrefixes = map[string]string{
	"data:image/png;base64,":     ".png",
	"data:image/jpeg;base64,":    ".jpg",
	"data:image/webp;base64,":    ".webp",
	"data:image/svg+xml;base64,": ".svg",
}

// HasImage reports whether doc carries a picture, which is what decides between
// a plain file and a package: a ZIP holding nothing but one YAML would be a
// wrapper nobody asked for.
func HasImage(doc *Document) bool { return logoBytes(doc) > 0 }

// MarshalBundle renders doc as a ZIP: the YAML with its logo replaced by a
// relative path, and the picture as a file beside it.
func MarshalBundle(doc *Document) ([]byte, error) {
	logo, ext := splitLogo(doc)
	if logo == nil {
		// Nothing to extract: a package would add a layer for no reason.
		return nil, fmt.Errorf("config: this configuration carries no image")
	}
	name := path.Join(assetDir, "logo"+ext)
	// The document is copied before being rewritten: the caller's own document
	// must not come back with a path where its image used to be.
	rewritten, err := withLogo(doc, name)
	if err != nil {
		return nil, err
	}
	body, err := Marshal(rewritten)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, entry := range []struct {
		name string
		body []byte
	}{{BundleName, body}, {name, logo}} {
		w, err := zw.Create(entry.name)
		if err != nil {
			return nil, fmt.Errorf("config: package %s: %w", entry.name, err)
		}
		if _, err := w.Write(entry.body); err != nil {
			return nil, fmt.Errorf("config: package %s: %w", entry.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("config: package: %w", err)
	}
	return buf.Bytes(), nil
}

// IsBundle reports whether body is a ZIP, by its magic number rather than by
// its name: what an admin uploads has been through a browser, a chat and a
// download folder, and the extension is the first thing to be lost.
func IsBundle(body []byte) bool {
	return len(body) > 4 && body[0] == 'P' && body[1] == 'K' &&
		(body[2] == 3 || body[2] == 5 || body[2] == 7)
}

// UnmarshalBundle reads a package: the document, with the pictures it references
// put back inline.
func UnmarshalBundle(body []byte) (*Document, error) {
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, fmt.Errorf("config: this package cannot be opened: %w", err)
	}
	files := map[string][]byte{}
	var doc []byte
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		// A name climbing out of the archive is refused rather than cleaned:
		// nothing legitimate produces one, and the tidy version of a hostile
		// path is still a hostile intent.
		name := f.Name
		if path.IsAbs(name) || strings.Contains(name, "..") {
			return nil, fmt.Errorf("config: the package holds an unusable path %q", name)
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("config: package %s: %w", name, err)
		}
		content, err := io.ReadAll(io.LimitReader(rc, maxAsset))
		_ = rc.Close()
		if err != nil {
			return nil, fmt.Errorf("config: package %s: %w", name, err)
		}
		if path.Base(name) == BundleName && path.Dir(name) == "." {
			doc = content
			continue
		}
		files[name] = content
	}
	if doc == nil {
		return nil, fmt.Errorf("config: this package holds no %s", BundleName)
	}
	parsed, err := Unmarshal(doc)
	if err != nil {
		return nil, err
	}
	return inlineAssets(parsed, files)
}

// maxAsset bounds one file inside a package. The branding refuses a logo over
// ~300 000 characters anyway; this stops a package from being read into memory
// before that refusal can happen.
const maxAsset = 1 << 20

// inlineAssets puts the pictures back where the document points at them.
func inlineAssets(doc *Document, files map[string][]byte) (*Document, error) {
	raw, ok := doc.Settings[store.SettingBranding]
	if !ok {
		return doc, nil
	}
	var branding map[string]any
	if err := json.Unmarshal(raw, &branding); err != nil {
		return nil, fmt.Errorf("config: branding: %w", err)
	}
	logo, _ := branding["logo"].(string)
	if logo == "" || strings.HasPrefix(logo, "data:") {
		return doc, nil // inline already, or no logo
	}
	content, ok := files[logo]
	if !ok {
		// The document names a picture the package does not hold. Refused
		// rather than dropped: an import that silently loses the logo is one
		// nobody notices until a user does.
		return nil, fmt.Errorf("config: the configuration points at %s, which is not in the package", logo)
	}
	prefix := ""
	for p, ext := range dataURIPrefixes {
		if strings.EqualFold(path.Ext(logo), ext) {
			prefix = p
			break
		}
	}
	if prefix == "" {
		return nil, fmt.Errorf("config: %s is not an image Meerkat can wear (png, jpeg, webp, svg)", logo)
	}
	branding["logo"] = prefix + base64.StdEncoding.EncodeToString(content)
	encoded, err := json.Marshal(branding)
	if err != nil {
		return nil, fmt.Errorf("config: branding: %w", err)
	}
	doc.Settings[store.SettingBranding] = encoded
	return doc, nil
}

// splitLogo returns the decoded logo and the extension it takes in a package.
func splitLogo(doc *Document) ([]byte, string) {
	raw, ok := doc.Settings[store.SettingBranding]
	if !ok {
		return nil, ""
	}
	var b struct {
		Logo string `json:"logo"`
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, ""
	}
	for prefix, ext := range dataURIPrefixes {
		if !strings.HasPrefix(b.Logo, prefix) {
			continue
		}
		content, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(b.Logo, prefix))
		if err != nil {
			return nil, ""
		}
		return content, ext
	}
	return nil, ""
}

// withLogo copies doc with the branding logo replaced by a path.
func withLogo(doc *Document, name string) (*Document, error) {
	raw := doc.Settings[store.SettingBranding]
	var branding map[string]any
	if err := json.Unmarshal(raw, &branding); err != nil {
		return nil, fmt.Errorf("config: branding: %w", err)
	}
	branding["logo"] = name
	encoded, err := json.Marshal(branding)
	if err != nil {
		return nil, fmt.Errorf("config: branding: %w", err)
	}
	// A shallow copy is enough: only the settings map is rewritten, and it gets
	// a fresh one.
	out := *doc
	out.Settings = make(map[string]json.RawMessage, len(doc.Settings))
	for k, v := range doc.Settings {
		out.Settings[k] = v
	}
	out.Settings[store.SettingBranding] = encoded
	return &out, nil
}
