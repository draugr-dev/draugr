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
// repository needs nothing here. A ruleset shared across an organization lives outside every
// repository that uses it, and that is what this points at.
const gitleaksConfigSchema = `{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "config": {
      "type": "string",
      "description": "Path to a Gitleaks TOML rules file, relative to where Draugr runs. Use it for a ruleset shared across repositories; a .gitleaks.toml committed in the scanned repository is already picked up without this."
    },
    "history": {
      "type": "boolean",
      "description": "Also scan the repository's commit history, in addition to the working tree. Off by default: it needs a full clone rather than a shallow one, so it is slower on a large repository. A secret committed and later removed is still fetchable by anyone who can clone, so it is still compromised — this is what finds it. History findings are marked as such, because they name the path the secret had when it was introduced."
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
	s.wantsHistory = gitleaksWantsHistory
	s.historyArgs = gitleaksHistoryArgs
	return s
}

// gitleaksArgs scans the working tree, writing SARIF to stdout. --exit-code 0 keeps the
// process successful even when secrets are found (findings are in the report, not the exit
// code); the secrets controller decides severity.
// gitleaksWantsHistory reports whether this scan needs a full clone.
func gitleaksWantsHistory(cfg plugin.Config) bool {
	v, _ := cfg["history"].(bool)
	return v
}

// gitleaksArgs scans the working tree — always, whatever `history` says.
//
// The tree pass is what reports a live secret at the path it actually lives at. History alone
// cannot: `gitleaks git` reports the path a secret had in the commit that introduced it, so a
// file since renamed is reported under a directory that no longer exists.
func gitleaksArgs(dir string, cfg plugin.Config) []string {
	return gitleaksCommand("dir", dir, cfg)
}

// gitleaksHistoryArgs walks the commit history, or returns nothing when history was not asked
// for. Its findings are marked Historical by the caller.
func gitleaksHistoryArgs(dir string, cfg plugin.Config) []string {
	if !gitleaksWantsHistory(cfg) {
		return nil
	}
	return gitleaksCommand("git", dir, cfg)
}

// gitleaksCommand builds the argv for one mode. `--exit-code 0` keeps the process successful when
// secrets are found: findings live in the report, not the exit code, and the controller decides
// severity.
func gitleaksCommand(mode, dir string, cfg plugin.Config) []string {
	argv := []string{
		"gitleaks", mode, dir,
		"--report-format", "sarif",
		// Not /dev/stdout: gitleaks opens this path, and opening a process's own fd 1 is not the
		// same as writing to it. See ReportPathToken.
		"--report-path", ReportPathToken,
		"--exit-code", "0",
		"--no-banner",
	}
	if path := configPath(cfg, "config"); path != "" {
		argv = append(argv, "--config", path)
	}
	return argv
}
