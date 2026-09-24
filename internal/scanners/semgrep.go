package scanners

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/draugr-dev/draugr/internal/toolexec"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
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
	s.parse = parseSemgrep
	return s
}

// parseSemgrep reads Semgrep's SARIF and reports each rule from a local config under the id its
// rules file declares.
//
// Semgrep prefixes the id of a rule loaded from disk with the directory of the file it came from,
// as written in --config, dots for slashes: `/home/alice/rules/x.yaml` declaring `no-eval` reports
// `home.alice.rules.no-eval`. The same rule then has a different id on every machine, so an
// exclusion written on one misses on another and a baseline taken in CI reads a local run's
// findings as all new. The part of the prefix that comes from the configured path is removed; for
// a configured directory, the part that comes from a subdirectory inside it is kept, which keeps
// two rules declaring one id in different subdirectories apart.
func parseSemgrep(out []byte, dir string, cfg plugin.Config) (sarif.Report, error) {
	report, err := sarif.FromSARIF(out)
	if err != nil {
		return sarif.Report{}, err
	}
	config, _ := cfg["config"].(string)
	for _, prefix := range semgrepRulePrefixes(dir, config) {
		renameSemgrepRules(&report, prefix)
	}
	return report, nil
}

// semgrepRulePrefixes are the prefixes Semgrep may have put on the ids of rules loaded from
// config, or none when config is not a path on disk (a registry ref such as p/default, or a URL).
//
// Semgrep resolves a relative config against its working directory, the checkout, and builds the
// prefix from the path as given, leaving out "/", "." and "..".
func semgrepRulePrefixes(dir, config string) []string {
	if config == "" {
		return nil
	}
	path := config
	if !filepath.IsAbs(path) {
		path = filepath.Join(dir, path)
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil
	}
	given := config
	if !info.IsDir() {
		given = filepath.Dir(config)
	}
	var out []string
	if p := dottedPrefix(given); p != "" {
		out = append(out, p)
	}
	// An absolute path may reach Semgrep through a symlink, /tmp on macOS for one, and a Semgrep
	// that resolves it prefixes with the target.
	if filepath.IsAbs(config) {
		if resolved, err := filepath.EvalSymlinks(path); err == nil {
			if !info.IsDir() {
				resolved = filepath.Dir(resolved)
			}
			if p := dottedPrefix(resolved); p != "" && (len(out) == 0 || p != out[0]) {
				out = append(out, p)
			}
		}
	}
	return out
}

// dottedPrefix is a directory path in the form Semgrep prefixes rule ids with, "" for none.
func dottedPrefix(path string) string {
	var parts []string
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if part != "" && part != "." && part != ".." {
			parts = append(parts, part)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, ".") + "."
}

// renameSemgrepRules removes prefix from every rule id that carries it, in the results and in the
// rule metadata, where Semgrep also writes the id into the name and the short description.
func renameSemgrepRules(report *sarif.Report, prefix string) {
	renamed := map[string]string{}
	for id := range report.Rules {
		if short, ok := strings.CutPrefix(id, prefix); ok && short != "" {
			renamed[id] = short
		}
	}
	for i := range report.Results {
		id := report.Results[i].RuleID
		if short, ok := strings.CutPrefix(id, prefix); ok && short != "" {
			renamed[id] = short
			report.Results[i].RuleID = short
		}
	}
	for old, short := range renamed {
		rule, ok := report.Rules[old]
		if !ok {
			continue
		}
		delete(report.Rules, old)
		if rule.Name == old {
			rule.Name = short
		}
		rule.ShortDescription = strings.ReplaceAll(rule.ShortDescription, old, short)
		report.Rules[short] = rule
	}
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
