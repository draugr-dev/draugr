// Package report renders a scan result in a chosen format. Each format is a Reporter over a
// common Data value, so the CLI (and, later, the branch diff) can emit console/markdown/HTML
// for humans, JUnit for CI test panels, and JSON/SARIF for machines through one interface.
package report

import (
	"fmt"
	"io"
	"slices"
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
	// Components breaks the verdict down by the part of the application it belongs to, when
	// there is more than one. Optional: a caller that does not compute it renders as before.
	Components []ComponentVerdict
	// Exploitability describes the feeds that enriched this run's severities, if any. Empty
	// when no enrichment was configured, in which case nothing about it is rendered.
	//
	// A report that raised a finding to critical has to be able to say on what data, obtained
	// when. "KEV said so" is not reproducible; "on KEV as of 2026-08-01" is.
	Exploitability []FeedProvenance
	// Tools records the build of each external scanner the run used, and whether Draugr can
	// vouch for it. Empty when nothing external ran.
	//
	// A scan runs whatever is on PATH, which is right — an operator may have an experimental
	// build or a fork, and blocking them would be Draugr mistaking "I cannot verify this" for
	// "this is wrong". But a report that cannot say which build produced its findings cannot be
	// reproduced, so the answer is to record it.
	Tools []ToolBuild
	// UnattributedFindings counts findings that belong to no component — a project-scoped
	// control like `infrastructure` produces them. Reported alongside the component breakdown,
	// because a breakdown that silently omits them makes the parts look like the whole.
	UnattributedFindings int
}

// ToolBuild is the build of one external scanner, as this run found it.
type ToolBuild struct {
	// Name is the executable, e.g. "trivy".
	Name string
	// Version is what it reports, or what Draugr recorded when it installed it.
	Version string
	// Attested means Draugr installed this exact binary and it is unchanged since.
	Attested bool
	// Reason says why not. Empty when attested.
	Reason string
}

// FeedProvenance is one exploitability dataset as this run saw it.
type FeedProvenance struct {
	// Name is the signal: "kev" or "epss".
	Name string
	// URL is where the copy came from. Empty for a file the operator supplied, which is its own
	// useful statement — the data was brought in by hand.
	URL string
	// FetchedAt is when it was obtained. Zero for a file path, which has no fetch to record.
	FetchedAt time.Time
	// SHA256 is the digest of the bytes that were read.
	SHA256 string
	// Stale reports that the copy was older than the run's configured maxAge. Recorded here and
	// not only warned about in the logs, because the logs of the run that produced a report are
	// exactly where nobody looks six weeks later.
	Stale bool
}

// ComponentVerdict is one component's outcome, judged by the same policy as the run.
//
// The unit a team owns, and the unit exposure and criticality are declared on — so the unit
// someone is actually deciding about. The controls table answers "is the project shippable",
// which is a different and usually less useful question than "is my service".
type ComponentVerdict struct {
	Name string
	// Verdict is the run's policy applied to this component's findings alone. Computed by
	// running the same norn.Policy rather than re-deciding, so the parts cannot disagree with
	// the whole about what failing means.
	Verdict norn.Verdict
	// Controls names the controls that failed for this component, in order.
	Controls []string
	// Priorities counts this component's findings by band, highest first (P1…P4).
	Priorities [4]int
	// Findings is the total, suppressed ones excluded — the same rule the counts follow.
	Findings int
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

// StreamFormats are the formats `--format` accepts: the ones whose natural destination is a
// stream, so a terminal, a pipe or a redirect all make sense.
//
// html and junit are deliberately absent. An HTML report is a styled document with its CSS
// inlined, and printing four thousand lines of it because someone typed a plausible-looking flag
// is not a thing to explain away — a JUnit file is read by a CI runner from a path, never by a
// person. Both are produced with --report into an output directory, which is the only place they
// were ever useful.
//
// Narrow on purpose. Every format offered here is one a reader has to rule out.
var StreamFormats = []string{"console", "markdown", "json", "sarif", "template"}

// documentFormats are produced as files rather than printed. Named so the error for
// `--format html` can say where the format did go rather than only that it is not here.
var documentFormats = map[string]bool{"html": true, "junit": true}

// StreamFormat reports whether a format may be written to stdout, and if not, why.
func StreamFormat(format string) error {
	if slices.Contains(StreamFormats, format) {
		return nil
	}
	if documentFormats[format] {
		return fmt.Errorf(
			"%s is a document, not something to print: use `--report %s` with `-o <dir>`", format, format)
	}
	return fmt.Errorf("unknown format %q for --format (available: %s)",
		format, strings.Join(StreamFormats, ", "))
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
	return skald.RenderJSONWithFeeds(w, d.Release, d.Run, d.Verdict, d.MinPriority,
		skaldFeeds(d.Exploitability), d.marshalOptions())
}

// skaldFeeds converts the report's feed provenance into the JSON document's shape.
func skaldFeeds(feeds []FeedProvenance) []skald.FeedProvenance {
	if len(feeds) == 0 {
		return nil
	}
	out := make([]skald.FeedProvenance, 0, len(feeds))
	for _, f := range feeds {
		e := skald.FeedProvenance{Name: f.Name, URL: f.URL, SHA256: f.SHA256, Stale: f.Stale}
		if !f.FetchedAt.IsZero() {
			t := f.FetchedAt.UTC()
			e.FetchedAt = &t
		}
		out = append(out, e)
	}
	return out
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
	// component is which part of the application the finding belongs to, empty for a
	// project-scoped control. A location alone is ambiguous once a descriptor has more than one.
	component string
	// helpURI is where the rule is documented: what the scanner published, or a URL derived
	// from a well-known identifier. Empty when we have nowhere honest to point.
	helpURI string
	// justification is why a suppressed finding was set aside. Empty for an active finding.
	justification string
	// escalation is why this finding's severity was raised, if it was.
	escalation *sarif.Escalation
	level      sarif.Level
	severity   sarif.Severity
	score      float64
	hasScore   bool
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
					component: res.Component,
					location:  locationOf(res), message: res.Message,
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
				escalation: res.Escalation,
				component:  res.Component,
				location:   loc, message: res.Message,
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

// provenanceLine is one scanner's account of one control's run, ready to render.
type provenanceLine struct {
	Control string
	Tool    string
	Version string
	Detail  string
}

// provenanceLines collects what each scanner said about the run, in control order.
//
// A finding answers "what is wrong". Evidence also has to answer "what was measured, and against
// what" — and for a compliance control that second question is the one an auditor asks first. The
// benchmark is chosen from the cluster rather than stated in the descriptor, so without this the
// report gives no way to know which standard produced it.
func provenanceLines(d Data) []provenanceLine {
	names := make([]string, 0, len(d.Run.Controls))
	for name := range d.Run.Controls {
		names = append(names, name)
	}
	sort.Strings(names)

	var out []provenanceLine
	for _, name := range names {
		for _, p := range d.Run.Controls[name].Report.Provenance {
			detail := p.Describe()
			if detail == "" && p.Version == "" {
				continue
			}
			out = append(out, provenanceLine{
				Control: name, Tool: p.Tool, Version: p.Version, Detail: detail,
			})
		}
	}
	return out
}

// Label renders the tool and version as one string, the version omitted when unknown.
func (p provenanceLine) Label() string {
	if p.Version == "" {
		return p.Tool
	}
	return p.Tool + " " + p.Version
}

// dedupeMessages collapses identical failures, noting how many jobs hit each.
//
// The engine records one entry per job, which is right: each belongs to a real job and the SARIF
// and the JSON report should keep them. In a summary it reads differently — two components whose
// scanner binary is missing produce the same sentence twice, and two identical lines invite the
// reader to look for the difference between them. There isn't one: the message is the same
// missing binary either way, and the duplicate carries nothing about which job it came from.
func dedupeMessages(msgs []string) []string {
	seen := map[string]int{}
	order := make([]string, 0, len(msgs))
	for _, m := range msgs {
		if _, ok := seen[m]; !ok {
			order = append(order, m)
		}
		seen[m]++
	}
	out := make([]string, 0, len(order))
	for _, m := range order {
		if n := seen[m]; n > 1 {
			m = fmt.Sprintf("%s (%d jobs)", m, n)
		}
		out = append(out, m)
	}
	return out
}

// suppressionAttribution summarises who accepted the suppressed findings.
//
// Returns the acceptors in a stable order with their counts, and how many nobody claimed.
//
// The name is the point of recording it. A count of unattributed suppressions says *that* there
// is a gap; it does not say who to ask about the rest, which is the question an auditor actually
// arrives with — and until this, the name reached no report at all: not the console, not the
// markdown, not even SARIF.
func suppressionAttribution(d Data) (acceptors []string, counts map[string]int, unattributed int) {
	counts = map[string]int{}
	for _, cr := range d.Run.Controls {
		for _, res := range cr.Report.Results {
			if !res.Suppressed() {
				continue
			}
			if by := res.Suppression.AcceptedBy; by != "" {
				if _, seen := counts[by]; !seen {
					acceptors = append(acceptors, by)
				}
				counts[by]++
				continue
			}
			unattributed++
		}
	}
	sort.Strings(acceptors)
	return acceptors, counts, unattributed
}

// suppressionLine renders the one-line account of what was set aside and by whom.
func suppressionLine(d Data) string {
	n := d.Run.Suppressed
	if n == 0 {
		return ""
	}
	line := fmt.Sprintf("%s suppressed by config.exclude", plural(n, "finding"))
	acceptors, counts, unattributed := suppressionAttribution(d)

	var parts []string
	for _, who := range acceptors {
		parts = append(parts, fmt.Sprintf("%d accepted by %s", counts[who], who))
	}
	if unattributed > 0 {
		// A blank is an answer worth seeing: an exclusion nobody signed is one nobody can be
		// asked about.
		parts = append(parts, fmt.Sprintf("%d unattributed", unattributed))
	}
	if len(parts) > 0 {
		line += " — " + strings.Join(parts, ", ")
	}
	return line
}
