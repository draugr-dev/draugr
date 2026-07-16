package scanners

import "github.com/draugr-dev/draugr/pkg/plugin"

// NewGosec returns a Scanner that runs gosec, a Go-specialized static analyzer, over a
// checked-out repository. It is an optional second scanner for the "sast" control (alongside
// Semgrep); it only makes sense on Go components, so it is opt-in via
// controllers.sast.scanners.
func NewGosec() plugin.Scanner {
	return newRepoScanner(
		plugin.ScannerInfo{
			Name:        "gosec",
			Binary:      "gosec",
			Controls:    []string{"sast"},
			TargetKinds: []plugin.TargetKind{plugin.TargetRepository},
		},
		gosecArgs,
	)
}

// gosecArgs builds `gosec -fmt sarif -no-fail ./...`. gosec loads Go packages relative to the
// working directory, so the repoScanner runs it with the checkout as the cwd and the target is
// the relative `./...` pattern (the dir argument is unused here).
//
//   - -no-fail keeps the process successful when findings exist (findings live in the SARIF
//     report, not the exit code; the sast controller judges severity).
//   - no -quiet: gosec's -quiet suppresses all output on a clean scan, which would leave no
//     SARIF to parse.
func gosecArgs(_ string, _ plugin.Config) []string {
	return []string{"gosec", "-fmt", "sarif", "-no-fail", "./..."}
}
