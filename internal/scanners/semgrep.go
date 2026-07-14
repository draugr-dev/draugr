package scanners

import "github.com/draugr-dev/draugr/pkg/plugin"

// NewSemgrep returns a Scanner that runs Semgrep over a checked-out repository for static
// application security testing (SAST). It serves the "sast" control.
func NewSemgrep() plugin.Scanner {
	return newRepoScanner(
		plugin.ScannerInfo{
			Name:        "semgrep",
			Binary:      "semgrep",
			Controls:    []string{"sast"},
			TargetKinds: []plugin.TargetKind{plugin.TargetRepository},
		},
		semgrepArgs,
	)
}

// semgrepArgs builds `semgrep scan --sarif ... <dir>`.
//
//   - --no-error keeps the process successful when findings exist (findings live in the
//     SARIF report, not the exit code; the controller judges severity).
//   - --metrics=off avoids sending scan telemetry to the Semgrep registry.
//   - --config p/default is the OSS default rule pack. (Semgrep's "auto" config is
//     deliberately not used: it refuses to run with metrics disabled.) Users can point this
//     at their own rules in a later iteration.
func semgrepArgs(dir string, _ plugin.Config) []string {
	return []string{
		"semgrep", "scan",
		"--sarif",
		"--quiet",
		"--no-error",
		"--metrics=off",
		"--config", "p/default",
		dir,
	}
}
