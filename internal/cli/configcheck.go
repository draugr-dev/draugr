package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/feeds"
	"github.com/draugr-dev/draugr/internal/observability"
	"github.com/draugr-dev/draugr/internal/tools"
	"github.com/draugr-dev/draugr/pkg/config"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/report"
)

// loadConfig reads the configuration in effect for a command run from wd, refusing a file that
// names a control, scanner or tool this build does not have, or holds a value no command accepts.
//
// Refused rather than warned about, as `draugr validate` refuses the same mistake in a descriptor.
// A misspelled key in this file is a default somebody believes every scan on the machine applies,
// and a scan that runs anyway applies none of it.
func loadConfig(wd string) (config.Resolved, error) {
	reg := builtins.Registry()
	var sources []config.Source
	var errs []error
	for _, path := range config.Files(rootConfigPath, wd) {
		data, err := os.ReadFile(path) // #nosec G304 G703 -- operator-provided config path
		if err != nil {
			errs = append(errs, fmt.Errorf("read %s: %w", path, err))
			continue
		}
		f, err := parseConfig(reg, path, data)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		sources = append(sources, config.Source{Path: path, File: f, Digest: config.Digest(data)})
	}
	if len(errs) > 0 {
		return config.Resolved{}, errors.Join(errs...)
	}
	return config.Resolve(sources), nil
}

// startupConfig is the configuration a command starts under, read before the logger is built so
// that log.* and offline hold for the whole run.
//
// Lenient where loadConfig refuses, because it runs before any command can report a problem, the
// commands that mend a broken file included. Each file contributes what decodes from it, and a log
// value the logger would refuse is left out, so a mistyped log.level cannot stop `draugr config
// unset` from removing it. Every command that reads the configuration, `scan`, `doctor`, `diff`,
// `tools install` and `config` among them, still refuses the file and names each problem.
func startupConfig(flag string) config.Resolved {
	wd, err := os.Getwd()
	if err != nil {
		return config.Resolved{}
	}
	var sources []config.Source
	for _, path := range config.Files(flag, wd) {
		data, err := os.ReadFile(path) // #nosec G304 G703 -- operator-provided config path
		if err != nil {
			continue
		}
		// What decoded, without the problems: loadConfig reports those, in the command's own words.
		f, _ := config.Parse(data, path)
		if !observability.ValidLevel(f.Log.Level) {
			f.Log.Level = ""
		}
		if !observability.ValidFormat(f.Log.Format) {
			f.Log.Format = ""
		}
		sources = append(sources, config.Source{Path: path, File: f})
	}
	return config.Resolve(sources)
}

// logOptions is the logger a command starts with: --log-level and --log-format as typed, then
// log.level and log.format, then the flags' defaults.
func logOptions(opts *globalOptions, cfg config.LogSettings, typed map[string]bool) observability.LogOptions {
	out := observability.LogOptions{Level: opts.logLevel, Format: opts.logFormat, File: opts.logFile}
	if cfg.Level != "" && !typed["log-level"] {
		out.Level = cfg.Level
	}
	if cfg.Format != "" && !typed["log-format"] {
		out.Format = cfg.Format
	}
	return out
}

// checkConfig holds one parsed file to what this build provides: the controls and scanners under
// controls, by the descriptor's own checks; tool names, against the catalog `tools install`
// reads; and the values of output, cache, scan and log, against what their flags accept.
//
// The result is a *config.Problems naming the file, every problem in it, and one hint.
func checkConfig(reg *engine.Registry, path string, f config.File) error {
	ck := newControlChecker(reg)
	ck.controls("controls", f.Controls)
	problems := ck.problems
	// The hint points at where the keys are listed, so it closes a report that names a key the
	// file cannot hold. A report of values alone already says what each one accepts.
	var hint string
	if len(problems) > 0 {
		hint = ck.hint()
	}
	tools := toolProblems(f.Tools)
	if len(tools) > 0 && hint == "" {
		hint = config.KeysHint
	}
	problems = append(problems, tools...)
	problems = append(problems, valueProblems(f)...)
	if len(problems) == 0 {
		return nil
	}
	return &config.Problems{Path: path, List: problems, Hint: hint}
}

// parseConfig parses one file and checks it in one pass, so a key the file cannot hold and a
// control this build does not provide are reported together rather than one per attempt.
func parseConfig(reg *engine.Registry, path string, data []byte) (config.File, error) {
	f, perr := config.Parse(data, path) // a parse error is always a *config.Problems
	cerr := checkConfig(reg, path, f)
	var parsed, checked *config.Problems
	if !errors.As(perr, &parsed) {
		return f, cerr
	}
	if !errors.As(cerr, &checked) {
		return f, perr
	}
	merged := &config.Problems{Path: path, List: append(parsed.List, checked.List...), Hint: parsed.Hint}
	if checked.Hint != parsed.Hint {
		merged.Hint = checked.Hint + "\n" + parsed.Hint
	}
	return f, merged
}

// toolProblems reports a pin for a tool `tools install` does not provision, which it would skip.
func toolProblems(pins map[string]config.ToolSettings) []string {
	known := map[string]bool{}
	for _, name := range tools.Installable() {
		known[name] = true
	}
	var out []string
	for _, name := range sortedKeys(pins) {
		if known[name] {
			continue
		}
		msg := fmt.Sprintf("tools: %q is not a tool this build of Draugr installs", name)
		if near := nearestName(name, known); near != "" {
			msg += fmt.Sprintf(", did you mean %q?", near)
		} else {
			msg += " (`draugr tools list` names them)"
		}
		out = append(out, msg)
	}
	return out
}

// valueProblems reports a value a command would refuse, here rather than when the command runs,
// where the refusal names a flag nobody typed.
func valueProblems(f config.File) []string {
	var out []string
	switch v := report.View(f.Output.View); v {
	case "", report.ViewFindings, report.ViewActions, report.ViewCompact:
	default:
		out = append(out, notOneOf("output.view", string(v), []string{
			string(report.ViewFindings), string(report.ViewActions), string(report.ViewCompact),
		}))
	}
	if f.Output.Top < 0 {
		out = append(out, fmt.Sprintf("output.top: expected a whole number of 0 or more, got %d", f.Output.Top))
	}
	if ttl := f.Cache.TTL; ttl != nil && *ttl < 0 {
		out = append(out, fmt.Sprintf("cache.ttl: expected a duration of 0s or more, got %s", feeds.ShortDuration(*ttl)))
	}
	if j := f.Scan.Jobs; j != nil && *j < 0 {
		out = append(out, fmt.Sprintf("scan.jobs: expected a whole number of 0 or more, got %d", *j))
	}
	if l := f.Log.Level; l != "" && !observability.ValidLevel(l) {
		out = append(out, notOneOf("log.level", l, observability.Levels))
	}
	if fm := f.Log.Format; fm != "" && !observability.ValidFormat(fm) {
		out = append(out, notOneOf("log.format", fm, observability.Formats))
	}
	return out
}

// notOneOf is the problem with a value outside a closed vocabulary: the key, the value, every value
// it may take, and the nearest of them.
func notOneOf(key, value string, valid []string) string {
	msg := fmt.Sprintf("%s: %q is not %s", key, value, list(valid))
	known := make(map[string]bool, len(valid))
	for _, v := range valid {
		known[v] = true
	}
	if near := nearestName(value, known); near != "" {
		msg += fmt.Sprintf(", did you mean %q?", near)
	}
	return msg
}
