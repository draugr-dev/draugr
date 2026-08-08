package scanners

import (
	"encoding/json"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

// NewGitleaks returns a Scanner that runs Gitleaks over a checked-out repository to detect
// leaked secrets (credentials, tokens, keys). It serves the "secrets" control.
func NewGitleaks() plugin.Scanner {
	s := newRepoScanner(
		plugin.ScannerInfo{
			Name:         "gitleaks",
			Origin:       "gitleaks",
			Binary:       "gitleaks",
			Controls:     []string{"secrets"},
			TargetKinds:  []plugin.TargetKind{plugin.TargetRepository},
			ConfigSchema: json.RawMessage(noScannerOptions),
		},
		gitleaksArgs,
	)
	s.cacheVersion = sharedGitleaksVersion.version
	return s
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
