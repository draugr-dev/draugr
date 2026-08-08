package scanners

import (
	"encoding/json"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

// gitleaksConfigSchema is the JSON Schema for Gitleaks' Saga config
// (controllers.secrets.gitleaks). additionalProperties:false rejects mistyped keys.
//
// One option, and it is the case the repository cannot cover on its own: Gitleaks already reads a
// `.gitleaks.toml` sitting in the scanned tree, so a rule or allowlist that belongs to one
// repository needs nothing here. A ruleset shared across an organisation lives outside every
// repository that uses it, and that is what this points at.
const gitleaksConfigSchema = `{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "config": {
      "type": "string",
      "description": "Path to a Gitleaks TOML rules file, relative to where Draugr runs. Use it for a ruleset shared across repositories; a .gitleaks.toml committed in the scanned repository is already picked up without this."
    }
  }
}`

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
			ConfigSchema: json.RawMessage(gitleaksConfigSchema),
		},
		gitleaksArgs,
	)
	s.cacheVersion = sharedGitleaksVersion.version
	return s
}

// gitleaksArgs scans the working tree, writing SARIF to stdout. --exit-code 0 keeps the
// process successful even when secrets are found (findings are in the report, not the exit
// code); the secrets controller decides severity.
func gitleaksArgs(dir string, cfg plugin.Config) []string {
	argv := []string{
		"gitleaks", "dir", dir,
		"--report-format", "sarif",
		"--report-path", "/dev/stdout",
		"--exit-code", "0",
		"--no-banner",
	}
	if path := configPath(cfg, "config"); path != "" {
		argv = append(argv, "--config", path)
	}
	return argv
}
