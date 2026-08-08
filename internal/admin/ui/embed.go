// Package ui carries the production build of the admin console, embedded in
// the binary by `make ui`. A dist/ holding only its .gitkeep means "this binary
// ships no console" — plain `go build` keeps working without Node — and the
// admin port then answers with its JSON status page instead.
//
// The console is served in ENGLISH only, and that is a decision rather than a
// gap: it is an operator's tool, and twenty-one copies of the same SPA weighed
// 120 MB in the binary for an audience that reads the API's vocabulary anyway.
// The DATA plane — the pages the application's own users see — stays
// translated, and that is where the languages matter.
package ui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var embedded embed.FS

// Build returns the embedded console. ok is false when the binary was built
// without `make ui`, which is exactly the case where dist/ holds no index.html.
func Build() (fsys fs.FS, ok bool) {
	fsys, err := fs.Sub(embedded, "dist")
	if err != nil {
		return nil, false
	}
	if _, err := fs.Stat(fsys, "index.html"); err != nil {
		return nil, false
	}
	return fsys, true
}
