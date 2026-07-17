// Package report renders a scan result in a chosen format. Each format is a Reporter over a
// common Data value, so the CLI (and, later, the branch diff) can emit console/markdown/HTML
// for humans, JUnit for CI test panels, and JSON/SARIF for machines through one interface.
package report

import (
	"fmt"
	"io"
	"sort"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/prioritization"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/skald"
)

// Data is everything a reporter needs to render a scan.
type Data struct {
	Release     saga.Release
	Run         engine.Result
	Verdict     norn.Result
	MinPriority string
}

// Reporter renders Data in one format.
type Reporter interface {
	Format() string
	Render(w io.Writer, d Data) error
}

// reporters is the built-in format registry.
var reporters = map[string]Reporter{
	"console":  consoleReporter{},
	"markdown": markdownReporter{},
	"html":     htmlReporter{},
	"junit":    junitReporter{},
	"json":     jsonReporter{},
	"sarif":    sarifReporter{},
}

// For returns the reporter for a format name.
func For(format string) (Reporter, error) {
	r, ok := reporters[format]
	if !ok {
		return nil, fmt.Errorf("unknown report format %q (available: %v)", format, Formats())
	}
	return r, nil
}

// Formats lists the available format names, sorted.
func Formats() []string {
	out := make([]string, 0, len(reporters))
	for f := range reporters {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// jsonReporter and sarifReporter delegate to the existing skald renderers so all formats share
// one interface.
type jsonReporter struct{}

func (jsonReporter) Format() string { return "json" }
func (jsonReporter) Render(w io.Writer, d Data) error {
	return skald.RenderJSON(w, d.Release, d.Run, d.Verdict, d.MinPriority)
}

type sarifReporter struct{}

func (sarifReporter) Format() string { return "sarif" }
func (sarifReporter) Render(w io.Writer, d Data) error {
	return skald.WriteSARIF(w, d.Run)
}

// --- shared summary used by the human reporters ---

type finding struct {
	control, ruleID, tool, priority, location, message string
	level                                              sarif.Level
	score                                              float64
	hasScore                                           bool
}

type summary struct {
	verdict        norn.Verdict
	prioritized    bool
	p1, p2, p3, p4 int
	findings       []finding // sorted most-urgent first
}

// summarize collects priority counts and a ranked finding list from a run.
func summarize(d Data) summary {
	s := summary{verdict: d.Verdict.Verdict}
	names := make([]string, 0, len(d.Run.Controls))
	for name := range d.Run.Controls {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		for _, res := range d.Run.Controls[name].Report.Results {
			if res.Priority != "" {
				s.prioritized = true
				switch prioritization.Priority(res.Priority) {
				case prioritization.P1:
					s.p1++
				case prioritization.P2:
					s.p2++
				case prioritization.P3:
					s.p3++
				case prioritization.P4:
					s.p4++
				}
			}
			loc := res.Location.URI
			if loc != "" && res.Location.StartLine > 0 {
				loc = fmt.Sprintf("%s:%d", loc, res.Location.StartLine)
			}
			s.findings = append(s.findings, finding{
				control: name, ruleID: res.RuleID, tool: res.Tool, priority: res.Priority,
				location: loc, message: res.Message, level: res.Level,
				score: res.Score, hasScore: res.HasScore,
			})
		}
	}
	sortFindings(s.findings)
	return s
}

// sortFindings orders most-urgent first: by priority, then numeric score, then SARIF level.
func sortFindings(fs []finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if ra, rb := prioritization.Priority(a.priority).Rank(), prioritization.Priority(b.priority).Rank(); ra != rb {
			return ra > rb
		}
		if a.score != b.score {
			return a.score > b.score
		}
		return levelRank(a.level) > levelRank(b.level)
	})
}

func levelRank(l sarif.Level) int {
	switch l {
	case sarif.LevelError:
		return 3
	case sarif.LevelWarning:
		return 2
	case sarif.LevelNote:
		return 1
	default:
		return 0
	}
}
