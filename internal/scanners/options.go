package scanners

import (
	"path/filepath"
	"strings"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

// What a curated option is allowed to do, and it is one line: change what the tool examines and
// with which rules. It may not decide which findings survive.
//
// That is not a stylistic preference. A scanner flag that filters by severity or reads an ignore
// file removes findings before Draugr ever sees them, and a finding Draugr never saw cannot be
// reported as suppressed, cannot carry the reason someone gave, and cannot be told apart from one
// that was never made. Draugr already answers that question — `exclusions` in the Saga keeps the
// finding in the report marked suppressed, and the gate thresholds decide what fails — so routing
// it through a tool flag would replace an auditable answer with a silent one.
//
// So `--severity`, `--ignorefile`, `-severity` and `-confidence` are deliberately absent, and the
// options below are the ones that decide what gets looked at.

// configPath resolves an operator-supplied path to an absolute one.
//
// Repository scanners run with the checkout as their working directory, so a relative path in a
// descriptor would resolve inside a temporary clone — where the operator's file is not. Resolving
// against the process's own directory makes `config: ./security/gitleaks.toml` mean what it says
// beside the descriptor it was written in.
func configPath(cfg plugin.Config, key string) string {
	v, _ := cfg[key].(string)
	return absPath(v)
}

// absPath is configPath for a value already in hand, such as one item of a list.
func absPath(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	abs, err := filepath.Abs(v)
	if err != nil {
		// Report the path as written rather than dropping the option: the tool's own error names
		// the file, which is more use than anything Draugr could say about a path it cannot
		// resolve.
		return v
	}
	return abs
}

// commaList renders a config list as one comma-separated value, for tools that take their lists
// that way. Empty when the option is absent, so a caller can skip the flag entirely.
func commaList(cfg plugin.Config, key string) string {
	items := stringList(cfg, key)
	out := make([]string, 0, len(items))
	for _, s := range items {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return strings.Join(out, ",")
}
