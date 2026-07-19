// Package version exposes build metadata injected at link time.
package version

// Set via -ldflags at build time; see Makefile.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)
