package scanners

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/draugr-dev/draugr/internal/netpolicy"
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
      "description": "Ruleset to run: a Semgrep registry ref (e.g. p/owasp-top-ten), a URL, or a rules file or directory on disk, resolved relative to where Draugr runs. Defaults to p/default."
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
	s.preflight = semgrepPreflight
	return s
}

// semgrepConfigSetting is where a descriptor sets the ruleset, for an error to name.
const semgrepConfigSetting = "config.controls.sast.semgrep.config"

// semgrepPreflight refuses an offline scan whose ruleset Semgrep would fetch.
//
// Semgrep downloads a registry ruleset on every invocation and keeps no copy, so there is nothing
// to warm and nothing to fall back on. Left to run, it reaches the registry on a machine that has
// said it has no network, or fails on the fetch with an error about a download rather than about
// the setting that caused it.
func semgrepPreflight(_ context.Context, cfg plugin.Config) error {
	if !netpolicy.Offline() {
		return nil
	}
	config, _ := cfg["config"].(string)
	if config == "" {
		return fmt.Errorf("cannot run offline: %s is unset, and Semgrep fetches its default, %s, from %s; "+
			"set it to a rules file or directory on disk",
			semgrepConfigSetting, semgrepDefaultRuleset, semgrepRegistryHost())
	}
	host, remote := semgrepRemoteHost(config)
	if !remote {
		return nil
	}
	return fmt.Errorf("cannot run offline: %s is %s, which Semgrep fetches from %s; "+
		"set it to a rules file or directory on disk", semgrepConfigSetting, config, host)
}

// semgrepRemoteHost reports whether Semgrep fetches config rather than reading it from disk, and
// the host it fetches from.
//
// The classification is Semgrep's own, from its config resolver: "r2c", a URL, the product names
// (code, policy, secrets, supply-chain, comma-joined), a registry id starting r/, p/ or s/, and
// "auto" are remote, and anything else is a path. Matching it exactly matters in both directions:
// a remote config treated as a path fetches under --offline, and a path treated as remote refuses
// a scan that would have run.
func semgrepRemoteHost(config string) (string, bool) {
	if u, err := url.Parse(config); err == nil && u.Scheme != "" && u.Host != "" {
		return u.Host, true
	}
	if config == "r2c" {
		return "semgrep.dev", true
	}
	if config == "auto" || semgrepProductNames(config) {
		return semgrepRegistryHost(), true
	}
	switch {
	case strings.HasPrefix(config, "r/"), strings.HasPrefix(config, "p/"), strings.HasPrefix(config, "s/"):
		return semgrepRegistryHost(), true
	}
	return "", false
}

// semgrepProductNames reports whether config is a comma-joined list of Semgrep product names, each
// of which Semgrep resolves against its AppSec Platform.
func semgrepProductNames(config string) bool {
	for name := range strings.SplitSeq(config, ",") {
		switch name {
		case "code", "policy", "secrets", "supply-chain":
		default:
			return false
		}
	}
	return true
}

// semgrepRegistryHost is the host Semgrep resolves registry ids against: SEMGREP_URL's when it is
// set, semgrep.dev otherwise.
func semgrepRegistryHost() string {
	if u, err := url.Parse(os.Getenv("SEMGREP_URL")); err == nil && u.Host != "" {
		return u.Host
	}
	return "semgrep.dev"
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
func parseSemgrep(out []byte, _ string, cfg plugin.Config) (sarif.Report, error) {
	report, err := sarif.FromSARIF(out)
	if err != nil {
		return sarif.Report{}, err
	}
	for _, prefix := range semgrepRulePrefixes(semgrepConfig(cfg)) {
		renameSemgrepRules(&report, prefix)
	}
	return report, nil
}

// semgrepRulePrefixes are the prefixes Semgrep may have put on the ids of rules loaded from
// config, the value passed to --config, or none when config is not a path on disk (a registry ref
// such as p/default, or a URL).
//
// Semgrep builds the prefix from the path as given, leaving out "/", "." and "..".
func semgrepRulePrefixes(config string) []string {
	if _, remote := semgrepRemoteHost(config); remote || !filepath.IsAbs(config) {
		return nil
	}
	path := config
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
	// The path may reach Semgrep through a symlink, /tmp on macOS for one, and a Semgrep that
	// resolves it prefixes with the target.
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		if !info.IsDir() {
			resolved = filepath.Dir(resolved)
		}
		if p := dottedPrefix(resolved); p != "" && (len(out) == 0 || p != out[0]) {
			out = append(out, p)
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

// semgrepConfig is the value passed to --config: the default ruleset when none is configured, a
// ruleset Semgrep fetches as given, and a path on disk made absolute against Draugr's working
// directory, where the reference says a path in scanner options resolves.
//
// Semgrep runs in the scan directory, so a relative path handed to it as written resolves inside
// the clone, or inside the component's directory for a repository scoped by paths, and names a
// file that is not there.
func semgrepConfig(cfg plugin.Config) string {
	config, _ := cfg["config"].(string)
	if config == "" {
		return semgrepDefaultRuleset
	}
	if _, remote := semgrepRemoteHost(config); remote {
		return config
	}
	if abs, err := filepath.Abs(config); err == nil {
		return abs
	}
	return config
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
	ruleset := semgrepConfig(cfg)
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
