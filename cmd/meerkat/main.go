// Command meerkat is the Meerkat app-gateway.
//
// The gateway itself is not implemented yet — this entry point anchors the
// build, versioning and release pipeline while the specification
// (requirements.md) is being finalized.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/softwarity/meerkat/internal/version"
)

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("meerkat %s (commit %s, built %s)\n", version.Version, version.Commit, version.Date)
		return
	}

	fmt.Fprintln(os.Stderr, "meerkat: the gateway is not implemented yet — see requirements.md")
	os.Exit(1)
}
