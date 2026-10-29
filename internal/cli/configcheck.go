package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/draugr-dev/draugr/internal/builtins"
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
		sources = append(sources, config.Source{Path: path, File: f})
	}
	if len(errs) > 0 {
		return config.Resolved{}, errors.Join(errs...)
	}
	return config.Resolve(sources), nil
}

// checkConfig holds one parsed file to what this build provides: the controls and scanners under
// controllers, by the descriptor's own checks; tool names, against the catalog `tools install`
// reads; and the values of output and cache, against what a scan accepts.
//
// The result is a *config.Problems naming the file, every problem in it, and one hint.
func checkConfig(reg *engine.Registry, path string, f config.File) error {
	ck := newControlChecker(reg)
	ck.controls("controllers", f.Controllers)
	problems := ck.problems
	hint := config.KeysHint
	if len(problems) > 0 {
		hint = ck.hint()
	}
	problems = append(problems, toolProblems(f.Tools)...)
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

// valueProblems reports an output or cache value a scan would refuse, here rather than at scan time,
// where the refusal names a flag nobody typed.
func valueProblems(f config.File) []string {
	var out []string
	switch v := report.View(f.Output.View); v {
	case "", report.ViewFindings, report.ViewActions, report.ViewCompact:
	default:
		views := map[string]bool{
			string(report.ViewFindings): true, string(report.ViewActions): true, string(report.ViewCompact): true,
		}
		msg := fmt.Sprintf("output.view: %q is not %s, %s or %s", v,
			report.ViewFindings, report.ViewActions, report.ViewCompact)
		if near := nearestName(string(v), views); near != "" {
			msg += fmt.Sprintf(", did you mean %q?", near)
		}
		out = append(out, msg)
	}
	if f.Output.Top < 0 {
		out = append(out, fmt.Sprintf("output.top: expected a whole number of 0 or more, got %d", f.Output.Top))
	}
	if ttl := f.Cache.TTL; ttl != nil && *ttl < 0 {
		out = append(out, fmt.Sprintf("cache.ttl: expected a duration of 0s or more, got %s", *ttl))
	}
	return out
}
