// Package version carries build metadata, injected at link time via -ldflags.
package version

import (
	"fmt"
	"runtime"
)

// These are overridden at build time (see Makefile).
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// String returns a human-readable version line.
func String() string {
	return fmt.Sprintf("draugr %s (commit %s, built %s, %s)",
		Version, Commit, Date, runtime.Version())
}
