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

// Info is the build metadata in structured form, for machine consumers.
type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Built   string `json:"built"`
	Go      string `json:"go"`
}

// Current returns the build metadata this binary was stamped with.
func Current() Info {
	return Info{Version: Version, Commit: Commit, Built: Date, Go: runtime.Version()}
}
