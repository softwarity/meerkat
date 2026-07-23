// Package ui carries the production build of the admin console, embedded in
// the binary by `make ui` (one directory per locale under dist/: en/, fr/…).
// A dist/ holding only its .gitkeep means "this binary ships no console" —
// plain `go build` keeps working without Node — and the admin port then
// answers with its JSON status page instead.
package ui

import (
	"embed"
	"io/fs"
	"slices"
)

//go:embed all:dist
var embedded embed.FS

// Build returns the embedded console rooted at the locale directories, and
// the locales it contains — a top-level directory counts as a locale when it
// holds an index.html. ok is false when the binary was built without `make ui`.
func Build() (fsys fs.FS, locales []string, ok bool) {
	fsys, err := fs.Sub(embedded, "dist")
	if err != nil {
		return nil, nil, false
	}
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, nil, false
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := fs.Stat(fsys, e.Name()+"/index.html"); err == nil {
			locales = append(locales, e.Name())
		}
	}
	slices.Sort(locales)
	return fsys, locales, len(locales) > 0
}
