package scanners

import "github.com/draugr-dev/draugr/pkg/plugin"

// NewGitleaks returns a Scanner that runs Gitleaks over a checked-out repository to detect
// leaked secrets (credentials, tokens, keys). It serves the "secrets" control.
func NewGitleaks() plugin.Scanner {
	return newRepoScanner(
		plugin.ScannerInfo{
			Name:        "gitleaks",
			Controls:    []string{"secrets"},
			TargetKinds: []plugin.TargetKind{plugin.TargetRepository},
		},
		gitleaksArgs,
	)
}

// gitleaksArgs scans the working tree, writing SARIF to stdout. --exit-code 0 keeps the
// process successful even when secrets are found (findings are in the report, not the exit
// code); the secrets controller decides severity.
func gitleaksArgs(dir string, _ plugin.Config) []string {
	return []string{
		"gitleaks", "dir", dir,
		"--report-format", "sarif",
		"--report-path", "/dev/stdout",
		"--exit-code", "0",
		"--no-banner",
	}
}
