// Package report renders a scan result in a chosen format. Each format is a Reporter over a
// common Data value, so the CLI (and, later, the branch diff) can emit console/markdown/HTML
// for humans, JUnit for CI test panels, and JSON/SARIF for machines through one interface.
package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
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
	// TopN caps how many findings the console "Fix first" table shows: 0 uses the default,
	// a negative value shows all, and a positive value shows that many. Ignored by other formats.
	TopN int
	// Compact strips what only a human reads — indentation and relayed rule prose — from the
	// machine formats (json, sarif), for a consumer that acts on the report rather than reads
	// it. The human formats ignore it: making those harder to read is the opposite of the point.
	Compact bool
	// Generated and Version stamp a report with when it ran and what produced it. A report
	// offered as evidence has to answer both; a reader who cannot tell whether they are looking
	// at today's scan or last quarter's has nothing they can rely on. Zero values are omitted,
	// so a caller that does not set them still renders a valid report.
	Generated time.Time
	Version   string
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
	return skald.RenderJSONWith(w, d.Release, d.Run, d.Verdict, d.MinPriority, d.marshalOptions())
}

type sarifReporter struct{}

func (sarifReporter) Format() string { return "sarif" }
func (sarifReporter) Render(w io.Writer, d Data) error {
	return skald.WriteSARIFWith(w, filterByPriority(d.Run, d.MinPriority), d.marshalOptions())
}

// filterByPriority drops findings below the requested band, returning a copy so the caller's
// run is untouched — the same Data is rendered in several formats and delivered to publishers.
//
// Findings the scanner never prioritized are kept. An empty Priority means prioritization did
// not run for that finding, not that it ranked low, and silently dropping it would be the worst
// reading of an unset field.
//
// Only the results need filtering: the emitted rules[] is derived from the results that remain,
// so a rule nobody matched leaves with them. That is where most of the size saving comes from —
// on Draugr's demo repository, filtering to P1 takes the compact SARIF from 82 KB to 32 KB.
func filterByPriority(run engine.Result, minPriority string) engine.Result {
	if minPriority == "" {
		return run
	}
	out := run
	out.Controls = make(map[string]plugin.ControlResult, len(run.Controls))
	for name, cr := range run.Controls {
		kept := make([]sarif.Result, 0, len(cr.Report.Results))
		for _, res := range cr.Report.Results {
			if res.Priority == "" || atOrAbove(res.Priority, minPriority) {
				kept = append(kept, res)
			}
		}
		cr.Report.Results = kept
		out.Controls[name] = cr
	}
	return out
}

// locationOf renders a finding's location as path:line, or just the path when the scanner gave
// no line.
func locationOf(res sarif.Result) string {
	if res.Location.URI != "" && res.Location.StartLine > 0 {
		return fmt.Sprintf("%s:%d", res.Location.URI, res.Location.StartLine)
	}
	return res.Location.URI
}

// erroredControls names controls that failed without producing any report at all, so they have
// no verdict entry to hang an ERROR on. Sorted, so a report is reproducible.
func erroredControls(d Data) []string {
	seen := make(map[string]bool, len(d.Verdict.Controls))
	for _, c := range d.Verdict.Controls {
		seen[c.Control] = true
	}
	var out []string
	for name := range d.Run.ScanErrors {
		if !seen[name] {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func (d Data) marshalOptions() sarif.MarshalOptions {
	return sarif.MarshalOptions{Compact: d.Compact}
}

// --- shared summary used by the human reporters ---

type finding struct {
	control, ruleID, tool, priority, location, message string
	// helpURI is where the rule is documented: what the scanner published, or a URL derived
	// from a well-known identifier. Empty when we have nowhere honest to point.
	helpURI string
	// justification is why a suppressed finding was set aside. Empty for an active finding.
	justification string
	level         sarif.Level
	severity      sarif.Severity
	score         float64
	hasScore      bool
}

// sevCounts tallies findings by normalized severity band.
type sevCounts struct{ critical, high, medium, low int }

func (c *sevCounts) add(s sarif.Severity) {
	switch s {
	case sarif.SeverityCritical:
		c.critical++
	case sarif.SeverityHigh:
		c.high++
	case sarif.SeverityMedium:
		c.medium++
	default:
		c.low++
	}
}

type summary struct {
	// minPriority is the band the listing was filtered to, and hidden how many findings that
	// removed — reported so a short list next to large counts isn't mystifying.
	minPriority    string
	hidden         int
	verdict        norn.Verdict
	prioritized    bool
	p1, p2, p3, p4 int
	bands          map[string]sevCounts // per-control severity counts
	findings       []finding            // sorted most-urgent first

	// What the run could not do, and what it set aside. A report that omits these describes a
	// thinner run rather than a broken one — and a reader cannot tell the difference, which is
	// the reading that matters: a control whose scanner never ran found nothing because it
	// looked at nothing.
	scanErrors map[string][]string // per control, what stopped it completing
	errored    []string            // controls that produced no report at all, so have no verdict row
	// effects are what the run did to its targets beyond reading them. Recorded because a scan
	// that sent traffic to a live endpoint is a thing that happened, and a report is where you
	// look to find out what happened.
	effects    []plugin.Effect
	suppressed int // findings a config.exclude rule matched
	// excluded lists those findings with the reason each was set aside. The count alone answers
	// "was anything hidden"; an auditor's question is "who decided this was acceptable, and
	// when", which needs the reason next to the finding.
	excluded   []finding
	sboms      int // SBOM documents produced
	sbomFormat string
}

// summarize collects priority counts and a ranked finding list from a run.
func summarize(d Data) summary {
	s := summary{
		verdict:    d.Verdict.Verdict,
		bands:      map[string]sevCounts{},
		scanErrors: d.Run.ScanErrors,
		effects:    d.Run.Effects,
		errored:    erroredControls(d),
		suppressed: d.Run.Suppressed,
		sboms:      len(d.Run.SBOMs),
	}
	if s.sboms > 0 {
		s.sbomFormat = string(d.Run.SBOMs[0].Format)
	}
	names := make([]string, 0, len(d.Run.Controls))
	for name := range d.Run.Controls {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		rep := d.Run.Controls[name].Report
		for _, res := range rep.Results {
			// Suppressed by a Saga exclusion: still in the report, deliberately not in the
			// list of things to fix. The count is reported separately so the reader knows
			// findings were set aside rather than never found.
			if res.Suppressed() {
				s.excluded = append(s.excluded, finding{
					control: name, ruleID: res.RuleID, tool: res.Tool, priority: res.Priority,
					location: locationOf(res), message: res.Message,
					severity:      res.Severity(""),
					justification: res.Suppression.Justification,
					helpURI:       rep.HelpURI(res.RuleID),
				})
				continue
			}
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
			loc := locationOf(res)
			sev := res.Severity("")
			b := s.bands[name]
			b.add(sev)
			s.bands[name] = b
			s.findings = append(s.findings, finding{
				control: name, ruleID: res.RuleID, tool: res.Tool, priority: res.Priority,
				location: loc, message: res.Message,
				level: res.Level, severity: sev,
				helpURI: rep.HelpURI(res.RuleID),
				score:   res.Score, hasScore: res.HasScore,
			})
		}
	}
	sortFindings(s.findings)
	// --min-priority narrows the listing, not the counts: you still see that 13 P3s exist while
	// working on the P1s. This matches the JSON report, so every format answers alike.
	if d.MinPriority != "" {
		s.minPriority = d.MinPriority
		kept := s.findings[:0]
		for _, f := range s.findings {
			if atOrAbove(f.priority, d.MinPriority) {
				kept = append(kept, f)
			}
		}
		s.hidden = len(s.findings) - len(kept)
		s.findings = kept
	}
	return s
}

// atOrAbove reports whether a finding's priority is at least the requested band. An unprioritized
// finding has no band to compare, so a priority filter excludes it rather than guessing.
func atOrAbove(got, want string) bool {
	order := map[string]int{"P1": 4, "P2": 3, "P3": 2, "P4": 1}
	g, ok := order[strings.ToUpper(got)]
	if !ok {
		return false
	}
	return g >= order[strings.ToUpper(want)]
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
