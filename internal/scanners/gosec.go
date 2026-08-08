package scanners

import (
	"encoding/json"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

// gosecConfigSchema is the JSON Schema for gosec's Saga config (controllers.sast.gosec).
// additionalProperties:false rejects mistyped keys.
//
// Rule selection is here; the severity and confidence floors gosec also offers are not. A floor
// drops findings inside the tool, where Draugr cannot mark them suppressed or record who accepted
// them — use `exclusions` in the Saga for a finding you have judged, and the gate thresholds for
// what should fail a build. Selecting rules is a different statement: that a check does not apply
// to this codebase at all.
const gosecConfigSchema = `{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "include": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Run only these gosec rules, by ID, e.g. [\"G101\", \"G204\"]. Everything else is skipped."
    },
    "exclude": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Skip these gosec rules, by ID, e.g. [\"G104\"]. For rules that do not apply to the codebase — a finding you have judged and accepted belongs in exclusions, where it stays in the report marked suppressed."
    },
    "tags": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Go build tags to compile with, e.g. [\"integration\"]. Code behind a tag gosec does not build is code it does not analyse."
    }
  }
}`

// NewGosec returns a Scanner that runs gosec, a Go-specialized static analyzer, over a
// checked-out repository. It is an optional second scanner for the "sast" control (alongside
// Semgrep); it only makes sense on Go components, so it is opt-in via
// controllers.sast.scanners.
func NewGosec() plugin.Scanner {
	s := newRepoScanner(
		plugin.ScannerInfo{
			Name:         "gosec",
			Origin:       "securego",
			Binary:       "gosec",
			Controls:     []string{"sast"},
			TargetKinds:  []plugin.TargetKind{plugin.TargetRepository},
			ConfigSchema: json.RawMessage(gosecConfigSchema),
		},
		gosecArgs,
	)
	s.cacheVersion = sharedGosecVersion.version
	return s
}

// gosecArgs builds `gosec -fmt sarif -no-fail ./...`. gosec loads Go packages relative to the
// working directory, so the repoScanner runs it with the checkout as the cwd and the target is
// the relative `./...` pattern (the dir argument is unused here).
//
//   - -no-fail keeps the process successful when findings exist (findings live in the SARIF
//     report, not the exit code; the sast controller judges severity).
//   - no -quiet: gosec's -quiet suppresses all output on a clean scan, which would leave no
//     SARIF to parse.
func gosecArgs(_ string, cfg plugin.Config) []string {
	argv := []string{"gosec", "-fmt", "sarif", "-no-fail"}
	if v := commaList(cfg, "include"); v != "" {
		argv = append(argv, "-include="+v)
	}
	if v := commaList(cfg, "exclude"); v != "" {
		argv = append(argv, "-exclude="+v)
	}
	if v := commaList(cfg, "tags"); v != "" {
		argv = append(argv, "-tags="+v)
	}
	// The package pattern stays last: gosec reads flags before it, and appending an option after
	// it would make the option part of the pattern.
	return append(argv, "./...")
}
