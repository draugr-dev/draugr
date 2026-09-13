package scanners

import (
	"context"
	"encoding/json"

	"github.com/draugr-dev/draugr/internal/toolexec"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

// semgrepDefaultRuleset is the OSS default rule pack, used when no ruleset is configured.
const semgrepDefaultRuleset = "p/default"

// semgrepConfigSchema is the JSON Schema for Semgrep's Saga config (controllers.sast.semgrep).
// Today it exposes one option, the ruleset; additionalProperties:false rejects mistyped keys.
const semgrepConfigSchema = `{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "config": {
      "type": "string",
      "description": "Ruleset to run: a Semgrep registry ref (e.g. p/owasp-top-ten) or a path/URL to a rules file. Defaults to p/default."
    }
  }
}`

// NewSemgrep returns a Scanner that runs Semgrep over a checked-out repository for static
// application security testing (SAST). It serves the "sast" control.
func NewSemgrep() plugin.Scanner {
	s := newRepoScanner(
		plugin.ScannerInfo{
			Name:         "semgrep",
			Origin:       "semgrep",
			Data:         semgrepData,
			Binary:       "semgrep",
			Controls:     []string{"sast"},
			TargetKinds:  []plugin.TargetKind{plugin.TargetRepository},
			ConfigSchema: json.RawMessage(semgrepConfigSchema),
		},
		semgrepArgs,
	)
	s.cacheVersion = sharedSemgrepVersion.version
	// The scan asks semgrep.dev whether a newer Semgrep exists, separately from --metrics=off and
	// separately from the rule pack it fetches. A version check is not part of scanning, and a run
	// that has said it has no network should not make one.
	s.run = runSemgrepInDir
	return s
}

// runSemgrepInDir runs Semgrep with its update check off.
func runSemgrepInDir(ctx context.Context, dir string, argv []string) ([]byte, error) {
	return toolexec.RunWithEnv(ctx, dir, argv, []string{"SEMGREP_ENABLE_VERSION_CHECK=0"})
}

// semgrepArgs builds `semgrep scan --sarif ... <dir>`.
//
//   - --no-error keeps the process successful when findings exist (findings live in the
//     SARIF report, not the exit code; the controller judges severity).
//   - --metrics=off avoids sending scan telemetry to the Semgrep registry.
//   - --config selects the ruleset: the "config" option (a registry ref or a path/URL to the
//     team's own rules) when set, else p/default, the OSS default rule pack. (Semgrep's "auto"
//     config is deliberately not used: it refuses to run with metrics disabled.)
func semgrepArgs(dir string, cfg plugin.Config) []string {
	ruleset := semgrepDefaultRuleset
	if v, ok := cfg["config"].(string); ok && v != "" {
		ruleset = v
	}
	return []string{
		"semgrep", "scan",
		"--sarif",
		"--quiet",
		"--no-error",
		"--metrics=off",
		"--config", ruleset,
		dir,
	}
}
