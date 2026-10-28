package scanners

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
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
	s.run = withSemgrepJSON(runSemgrepInDir)
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

// semgrepReports is what one Semgrep run writes: the SARIF it prints, which the findings are read
// from, and the JSON report it writes beside it, which keeps each rule's metadata and lists the
// files Semgrep did not finish.
//
// Bytes rather than raw JSON, so output that is not JSON reaches the SARIF parser as Semgrep wrote
// it and fails there with the error every SARIF scanner gives.
type semgrepReports struct {
	SARIF []byte `json:"sarif"`
	JSON  []byte `json:"json"`
}

// semgrepJSONPath marks the argv slot for the file Semgrep writes its JSON report to, which
// withSemgrepJSON creates for each run.
const semgrepJSONPath = "{{draugr:semgrep-json-path}}"

// withSemgrepJSON runs Semgrep through run, and returns both reports the run writes as one
// semgrepReports document.
//
// One run in two formats. The SARIF is what the findings, their locations, fingerprints and
// suppressions are read from, and it drops every rule's metadata except a confidence tag. The JSON
// keeps the metadata and lists the files Semgrep skipped or did not finish, and is read for those
// alone.
func withSemgrepJSON(run func(ctx context.Context, dir string, argv []string) ([]byte, error)) func(context.Context, string, []string) ([]byte, error) {
	return func(ctx context.Context, dir string, argv []string) ([]byte, error) {
		slot := slices.Index(argv, semgrepJSONPath)
		if slot < 0 {
			return nil, errors.New("the semgrep command has no slot for its JSON report")
		}
		f, err := os.CreateTemp("", "draugr-semgrep-*.json")
		if err != nil {
			return nil, err
		}
		path := f.Name()
		if err := f.Close(); err != nil {
			return nil, err
		}
		defer func() { _ = os.Remove(path) }()

		argv = slices.Clone(argv)
		argv[slot] = path
		out, err := run(ctx, dir, argv)
		if err != nil {
			return nil, err
		}
		doc, err := os.ReadFile(path) // #nosec G304 -- a path this function just created
		if err != nil {
			return nil, err
		}
		// A run that printed its findings and wrote no metadata would rank every one of them on its
		// level, and the report would not say so.
		if len(bytes.TrimSpace(doc)) == 0 {
			return nil, errors.New("semgrep wrote no JSON report beside its SARIF, so its rules' ratings cannot be read")
		}
		return json.Marshal(semgrepReports{SARIF: out, JSON: doc})
	}
}

// parseSemgrep reads the reports one Semgrep run wrote, rates each result from its rule's
// metadata, reports each rule from a local config under the id its rules file declares, and lists
// each file Semgrep skipped for its size or did not finish as an unread input (see semgrepUnread).
//
// Semgrep prefixes the id of a rule loaded from disk with the directory of the file it came from,
// as written in --config, dots for slashes: `/home/alice/rules/x.yaml` declaring `no-eval` reports
// `home.alice.rules.no-eval`. The same rule then has a different id on every machine, so an
// exclusion written on one misses on another and a baseline taken in CI reads a local run's
// findings as all new. The part of the prefix that comes from the configured path is removed; for
// a configured directory, the part that comes from a subdirectory inside it is kept, which keeps
// two rules declaring one id in different subdirectories apart.
func parseSemgrep(out []byte, dir string, cfg plugin.Config) (sarif.Report, error) {
	var reports semgrepReports
	if err := json.Unmarshal(out, &reports); err != nil {
		return sarif.Report{}, fmt.Errorf("read Semgrep's reports: %w", err)
	}
	report, err := sarif.FromSARIF(reports.SARIF)
	if err != nil {
		return sarif.Report{}, err
	}
	// Before the ids are shortened: the JSON names each rule by the id Semgrep reported.
	if err := rateSemgrep(&report, reports.JSON); err != nil {
		return sarif.Report{}, err
	}
	config := semgrepConfig(cfg)
	prefixes := semgrepRulePrefixes(config)
	report.Inputs, err = semgrepUnread(reports.JSON, dir, semgrepRuleLanguages(config), prefixes)
	if err != nil {
		return sarif.Report{}, err
	}
	for _, prefix := range prefixes {
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

// semgrepArgs builds `semgrep scan --sarif --json-output <file> ... <dir>`.
//
//   - --json-output writes the same results as JSON to a file beside the SARIF, for the rule
//     metadata the SARIF leaves out (see withSemgrepJSON).
//   - --verbose has the JSON list the files Semgrep skipped, with the reason, under
//     paths.skipped, which it leaves out otherwise (see semgrepUnread). What it adds to stderr is
//     not read; the SARIF is the same.
//   - --max-target-bytes and --timeout-threshold restate Semgrep's defaults, so the reason an
//     unread file is given states the limit the run applied.
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
		"--json-output", semgrepJSONPath,
		"--verbose",
		"--max-target-bytes", strconv.Itoa(semgrepMaxTargetBytes),
		"--timeout-threshold", strconv.Itoa(semgrepTimeoutThreshold),
		"--no-error",
		"--metrics=off",
		"--config", ruleset,
		dir,
	}
}
