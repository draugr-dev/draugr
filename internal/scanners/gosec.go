package scanners

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// gosecConfigSchema is the JSON Schema for gosec's Saga config (controllers.sast.gosec).
// additionalProperties:false rejects mistyped keys.
//
// Rule selection is here; the severity and confidence floors gosec also offers are not. A floor
// drops findings inside the tool, where Draugr cannot mark them suppressed or record who accepted
// them. Use `exclusions` in the Saga for a finding you have judged, and the gate thresholds for
// what should fail a build. Selecting rules is a different statement: that a check does not apply
// to this codebase at all.
const gosecConfigSchema = `{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "include": {
      "type": "array",
      "items": { "type": "string", "pattern": "^(.*\\$\\{\\{.*\\}\\}.*|G[0-9]{3})$" },
      "description": "Run only these gosec rules, by ID, e.g. [\"G101\", \"G204\"]. Everything else is skipped."
    },
    "exclude": {
      "type": "array",
      "items": { "type": "string", "pattern": "^(.*\\$\\{\\{.*\\}\\}.*|G[0-9]{3})$" },
      "description": "Skip these gosec rules, by ID, e.g. [\"G104\"]. For rules that do not apply to the codebase, a finding you have judged and accepted belongs in exclusions, where it stays in the report marked suppressed."
    },
    "tags": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Go build tags to compile with, e.g. [\"integration\"]. Code behind a tag gosec does not build is code it does not analyze."
    }
  }
}`

// NewGosec returns a Scanner that runs gosec, a Go-specialized static analyzer, over a
// checked-out repository. It is an optional second scanner for the "sast" control (alongside
// Semgrep); it only makes sense on Go components, so it is opt-in via
// controls.sast.gosec.enabled.
func NewGosec() plugin.Scanner {
	s := newRepoScannerPerModule(
		plugin.ScannerInfo{
			Name:         "gosec",
			Origin:       "securego",
			Binary:       "gosec",
			Controls:     []string{"sast"},
			TargetKinds:  []plugin.TargetKind{plugin.TargetRepository},
			ConfigSchema: json.RawMessage(gosecConfigSchema),
		},
		gosecArgs,
		parseGosec,
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
//   - -track-suppressions keeps a `#nosec` result in the report, marked, with the text after the
//     `--` as its justification. Without it gosec removes the result, and a finding somebody
//     excluded is indistinguishable from one nobody ever made: the report reads clean, and the
//     question asked of an exclusion later, who decided this was acceptable, has nothing to
//     answer from.
func gosecArgs(dir string, cfg plugin.Config) [][]string {
	base := []string{"gosec", "-fmt", "sarif", "-no-fail", "-track-suppressions"}
	if v := commaList(cfg, "include"); v != "" {
		base = append(base, "-include="+v)
	}
	if v := commaList(cfg, "exclude"); v != "" {
		base = append(base, "-exclude="+v)
	}
	if v := commaList(cfg, "tags"); v != "" {
		base = append(base, "-tags="+v)
	}
	// One run per module, by absolute path. gosec loads packages from the working directory's
	// module, so `./...` from a root with no go.mod analyzes nothing and writes nothing, and a
	// module nested inside another is outside the outer one's `./...`.
	var out [][]string
	for _, mod := range goModuleDirs(dir) {
		argv := append([]string{}, base...)
		out = append(out, append(argv, filepath.Join(mod, "...")))
	}
	return out
}

// parseGosec reads the SARIF documents the per-module runs wrote, one after another, in the order
// gosecArgs ran them.
//
// gosec names a file relative to the module it analyzed, so each document's locations are put back
// under that module's directory: `main.go` in the module at service/ is service/main.go.
//
// No output means no module was found, and the report says so rather than passing: a tree gosec
// could not analyze must not read like one it analyzed and found clean.
func parseGosec(out []byte, dir string, cfg plugin.Config) (sarif.Report, error) {
	if len(bytes.TrimSpace(out)) == 0 {
		return sarif.Report{
			Tool: "gosec",
			Provenance: []sarif.Provenance{{
				Tool:   "gosec",
				Fields: []sarif.Field{{Key: "coverage", Value: "no go.mod found, so gosec analyzed nothing here"}},
			}},
		}, nil
	}
	modules := goModuleDirs(dir)
	selected := commaList(cfg, "include") != "" || commaList(cfg, "exclude") != ""
	dec := json.NewDecoder(bytes.NewReader(out))
	var reports []sarif.Report
	for {
		var doc json.RawMessage
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return sarif.Report{}, fmt.Errorf("read gosec SARIF: %w", err)
		}
		rep, err := sarif.FromSARIF(doc)
		if err != nil {
			return sarif.Report{}, err
		}
		if i := len(reports); dir != "" && i < len(modules) {
			underModule(&rep, dir, modules[i])
		}
		if selected {
			rep.Results = slices.DeleteFunc(rep.Results, outOfSelection)
		}
		reports = append(reports, rep)
	}
	if dir != "" && len(reports) != len(modules) {
		return sarif.Report{}, fmt.Errorf("gosec wrote %d reports for %d modules", len(reports), len(modules))
	}
	return sarif.Merge(reports...), nil
}

// outOfSelection reports whether a result is one of the rules -include or -exclude left out.
//
// Under -track-suppressions gosec still runs those rules and reports each result as a suppression
// of kind external, justified "Globally suppressed.", where a #nosec is kind inSource. Kept, the
// result reads as a finding somebody accepted, when the descriptor said the rule does not apply to
// this codebase at all.
func outOfSelection(r sarif.Result) bool {
	return r.Suppression != nil && r.Suppression.Kind == "external"
}

// underModule prefixes each relative location in rep with module's directory relative to root.
func underModule(rep *sarif.Report, root, module string) {
	rel, err := filepath.Rel(root, module)
	if err != nil || rel == "." {
		return
	}
	for i := range rep.Results {
		uri := rep.Results[i].Location.URI
		if uri != "" && !filepath.IsAbs(uri) {
			rep.Results[i].Location.URI = filepath.ToSlash(filepath.Join(rel, uri))
		}
	}
}
