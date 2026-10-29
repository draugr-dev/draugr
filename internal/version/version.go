// Package version carries build metadata, injected at link time via -ldflags.
package version

import (
	"fmt"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
)

// These are overridden at build time (see Makefile).
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

func init() {
	if info, ok := debug.ReadBuildInfo(); ok {
		Version, Commit, Date = fromBuildInfo(info, Version, Commit, Date)
	}
}

// releaseTag matches a module version that names a release tag. A pseudo-version
// (v0.154.2-0.20261018…-abcdef) or "(devel)" names no release, so neither does.
var releaseTag = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

// shortCommit is the length of the commit a release binary is stamped with.
const shortCommit = 8

// fromBuildInfo fills whatever the linker left at its default from what the Go toolchain recorded.
//
// `go install …@v0.154.1` sets no -ldflags, so without this the binary calls itself "dev". The
// module version arrives with a leading "v", which is trimmed to match what the release stamps.
// The VCS settings are present only when the build ran inside a checkout.
func fromBuildInfo(info *debug.BuildInfo, version, commit, date string) (string, string, string) {
	if version == "dev" && releaseTag.MatchString(info.Main.Version) {
		version = strings.TrimPrefix(info.Main.Version, "v")
	}
	for _, s := range info.Settings {
		switch {
		case s.Key == "vcs.revision" && commit == "none" && s.Value != "":
			commit = s.Value[:min(len(s.Value), shortCommit)]
		case s.Key == "vcs.time" && date == "unknown" && s.Value != "":
			date = s.Value
		}
	}
	return version, commit, date
}

// String returns a human-readable version line.
func String() string {
	return fmt.Sprintf("draugr %s (commit %s, built %s, %s)",
		Version, Commit, Date, runtime.Version())
}

// Build names this binary for keying cached scan results: the version and the commit, as
// `0.158.1+abcdef12`.
//
// A release names itself by its version alone. A development build is "dev" whatever it
// contains, so the commit is what tells two of them apart: the linker's stamp under `make build`,
// or the VCS revision the Go toolchain recorded under `go build` in a checkout. A build with
// neither, such as a test binary, is `dev+none`.
func Build() string { return Version + "+" + Commit }

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
