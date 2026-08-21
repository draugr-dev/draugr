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

// Scope is what a run was narrowed to, and what it therefore did not cover.
//
// A scoped run is a real verdict about a real subset, which is why it still gates. It is only
// dangerous when it is indistinguishable from a whole one — so this travels into every artifact
// the run produces, and every rendering says what was left out.
type Scope struct {
	// Components and Controls are what the caller asked for; an empty list means that axis was
	// not restricted.
	Components []string `json:"components,omitempty"`
	Controls   []string `json:"controls,omitempty"`
	// SkippedComponents are declared components this run did not scan.
	//
	// Named rather than counted: "10 not scanned" tells a reader they are missing something and
	// not which thing, and the answer is one they already have.
	SkippedComponents []string `json:"skippedComponents,omitempty"`
}

// Data is everything a reporter needs to render a scan.
type Data struct {
	Release     saga.Release
	Run         engine.Result
	Verdict     norn.Result
	MinPriority string
	// Scope describes what the run was narrowed to, and is nil when it was not narrowed at all.
	//
	// A pointer so that every unscoped report — which is nearly all of them — renders and
	// serializes exactly as it did before. Its presence is the signal: an artifact carrying a
	// scope is a partial answer, and a consumer that finds one has been told so rather than
	// having to infer it from a component list that looks complete.
	Scope *Scope
	// TopN caps how many findings the console "Fix first" table shows: 0 uses the default,
	// a negative value shows all, and a positive value shows that many. Ignored by other formats.
	TopN int
	// GroupActions renders the fix list as actions rather than findings: one row per thing to do,
	// each saying how many findings it clears.
	//
	// A reader deciding what to spend an afternoon on is choosing between actions, and a list of
	// findings makes them do that grouping in their head. Off gives the finding-per-row listing,
	// which is what somebody auditing a specific finding wants.
	GroupActions bool
	// UndeliveredReports names formats the descriptor declared that this run had nowhere to put.
	//
	// A descriptor can reasonably declare reports for a pipeline that has publishers, and be run
	// locally by somebody who passes no -o. That is not an error, and it is not nothing either:
	// two formats were named, both were skipped, and without this the run looks exactly like one
	// that wrote them.
	UndeliveredReports []string
	// Evidence restores the blocks that make a run defensible — tool provenance, what each
	// control measured against, declared effects, the scanned revision, job and cache counts.
	//
	// Off by default. A developer at a terminal is asking what to fix, and answers to questions
	// they have not asked push the answer to the one they have off the screen. An auditor is a
	// real reader, just not the default one, and asks for this.
	Evidence bool
	// Gate records the policy the verdict was produced under.
	//
	// A verdict is only as meaningful as the gate behind it, and a gate can be narrowed or turned
	// off entirely from the command line. Without this the report shows a verdict and no way to
	// tell what it was measured against — the same gap that suppression closes for findings,
	// where the question is never "did the scanner run" but "who decided this was acceptable".
	Gate GateSettings

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
	// VEX names the author and product for the "vex" format. Nil falls back to the release,
	// which is enough for a valid document and not enough for a publishable one.
	VEX *saga.VEXConfig
	// Components breaks the verdict down by the part of the application it belongs to, when
	// there is more than one. Optional: a caller that does not compute it renders as before.
	Components []ComponentVerdict
	// Exploitability describes the feeds that enriched this run's severities, if any. Empty
	// when no enrichment was configured, in which case nothing about it is rendered.
	//
	// A report that raised a finding to critical has to be able to say on what data, obtained
	// when. "KEV said so" is not reproducible; "on KEV as of 2026-08-01" is.
	Exploitability []FeedProvenance
	// Repositories is which repository each scan read, and at which commit. Derived from what the
	// scanners recorded rather than from the descriptor, because the descriptor usually names no
	// revision at all — and "the default branch" is not something a reader can check out.
	Repositories []RepositoryProvenance
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
	// Level is how strongly Draugr can vouch for this build: pinned, signed, checksum,
	// unverified, or external. Not a boolean, because those are genuinely different claims — an
	// unsigned checksum proves the download was not corrupted without proving upstream published
	// it, and collapsing that into "unattested" discards a difference a reader may care about.
	Level string
	// Reason renders the level for someone who has not read its definition.
	Reason string
}

// RepositoryProvenance is one repository as this run read it.
//
// An alias rather than a copy: the JSON report is rendered by pkg/skald, which cannot import this
// package, and two structs that must agree eventually will not.
type RepositoryProvenance = sarif.RepositoryRef

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
	// Declared counts what the descriptor gave this component, by target kind. It is the
	// denominator: "3 images not scanned" does not say whether that is all of them or three of
	// thirty, and those are different situations — one is a component nobody looked at, the
	// other is a gap in one that was mostly covered.
	Declared map[string]int
	// Unscanned is what this component has that no scanner managed to look at.
	//
	// A component whose every image failed to pull has had nothing examined, and without this it
	// renders as passing with no findings — which is the report asserting something no scanner
	// established. The same reasoning already keeps a component the scope excluded out of the
	// pass list; a component the scan could not reach is the same situation arrived at later.
	Unscanned []engine.Unscanned
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
	"vex":      vexReporter{},

	// GitLab's own schemas. Delivered as build artifacts the runner collects, which is why they
	// are reporters and not a publisher — GitLab has no endpoint to upload to.
	"gitlab-sast": gitlabSecurityReporter{
		format: "gitlab-sast", scanType: "sast",
		// GitLab files infrastructure-as-code scanning under SAST, as Draugr's `iac` control is.
		controls: []string{"sast", "iac"},
	},
	"gitlab-dependency-scanning": gitlabSecurityReporter{
		format: "gitlab-dependency-scanning", scanType: "dependency_scanning",
		controls: []string{"sca"}, needsPackage: true,
	},
	"gitlab-secret-detection": gitlabSecurityReporter{
		format: "gitlab-secret-detection", scanType: "secret_detection",
		controls: []string{"secrets"}, needsCommit: true,
	},
	// What stands behind the verdict, as a document. Read from a path by somebody keeping it,
	// which is why it is a document format rather than one --format prints.
	"evidence": evidenceReporter{},

	"gitlab-container-scanning": gitlabSecurityReporter{
		format: "gitlab-container-scanning", scanType: "container_scanning",
		controls: []string{"images"}, needsPackage: true, needsImage: true,
	},
	"gitlab-codequality": gitlabCodeQualityReporter{},
	"gitlab-cyclonedx":   gitlabSBOMReporter{},
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
var StreamFormats = []string{"console", "markdown", "json", "sarif", "vex", "template"}

// documentFormats are produced as files rather than printed. Named so the error for
// `--format html` can say where the format did go rather than only that it is not here.
var documentFormats = map[string]bool{
	"html": true, "junit": true,
	// A GitLab runner reads these from a path declared in `artifacts: reports:`. Nobody reads one,
	// so printing several thousand lines of JSON at somebody is not the answer to typing the name.
	"gitlab-sast": true, "gitlab-secret-detection": true, "gitlab-codequality": true,
	"gitlab-dependency-scanning": true,
	"gitlab-container-scanning":  true,
	"evidence":                   true,
	"gitlab-cyclonedx":           true,
}

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
	return skald.WriteSARIFNarrowed(w, FilterByPriority(d.Run, d.MinPriority), d.MinPriority, d.marshalOptions())
}

// FilterByPriority drops findings below the requested band, returning a copy so the caller's
// run is untouched — the same Data is rendered in several formats and delivered to publishers.
//
// Findings the scanner never prioritized are kept. An empty Priority means prioritization did
// not run for that finding, not that it ranked low, and silently dropping it would be the worst
// reading of an unset field.
//
// Only the results need filtering: the emitted rules[] is derived from the results that remain,
// so a rule nobody matched leaves with them. That is where most of the size saving comes from —
// on Draugr's demo repository, filtering to P1 takes the compact SARIF from 82 KB to 32 KB.
func FilterByPriority(run engine.Result, minPriority string) engine.Result {
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
	// repository is which repository it was found in, for a component that has more than one.
	// Paths are repository-relative, so two of them produce identical-looking rows.
	repository string
	// helpURI is where the rule is documented: what the scanner published, or a URL derived
	// from a well-known identifier. Empty when we have nowhere honest to point.
	helpURI string
	// justification is why a suppressed finding was set aside. Empty for an active finding.
	justification string
	// escalation is why this finding's severity was raised, if it was.
	escalation *sarif.Escalation
	// priorityFloor is why this finding outranks what the component's classification alone would
	// give it. Empty when the classification accounts for the band.
	priorityFloor string
	// historical marks a finding that describes a commit rather than the current tree, so its
	// location is a path that may no longer exist.
	historical bool
	// remediation is what kind of action would resolve this, which decides whether it belongs in
	// a list of things to fix at all.
	remediation sarif.Remediation
	// pkg is the dependency the finding is about, when it is about one. Carried because an
	// upgrade is one action however many findings it clears, and the package plus the version
	// that fixes it is what says two findings share that action.
	pkg *sarif.Package
	// imageBuiltUpstream marks a finding in an image somebody else publishes, which changes what
	// the reader can do about it and therefore how it groups.
	imageBuiltUpstream bool
	// operatingSystem is the release an image finding came from, for the same reason: moving off
	// a release past end of service life is one action for everything in that layer.
	operatingSystem string
	level           sarif.Level
	severity        sarif.Severity
	score           float64
	hasScore        bool
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
	// escalated is how many findings a feed moved up a band. Counted over every finding, not
	// only the ones shown: --top and --min-priority narrow the listing, and "nothing raised"
	// has to mean nothing in the run rather than nothing on this page.
	escalated int

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
					component:  res.Component,
					repository: res.Repository,
					location:   locationOf(res), message: res.Message,
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
			if res.Escalation != nil {
				s.escalated++
			}
			s.findings = append(s.findings, finding{
				control: name, ruleID: res.RuleID, tool: res.Tool, priority: res.Priority,
				escalation:    res.Escalation,
				priorityFloor: res.PriorityFloor,
				historical:    res.Historical,
				component:     res.Component,
				repository:    res.Repository,
				location:      loc, message: res.Message,
				level: res.Level, severity: sev,
				helpURI: rep.HelpURI(res.RuleID),
				score:   res.Score, hasScore: res.HasScore,
				remediation:        res.Remediation(),
				imageBuiltUpstream: res.ImageBuiltUpstream,
				pkg:                res.Package,
				operatingSystem:    res.OperatingSystem,
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
		// Within a band, what somebody can act on comes first.
		//
		// Not by changing the band. Priority feeds the gate, and demoting a finding because
		// nobody here can fix it would weaken a build gate as a side effect of annotating a
		// descriptor — a policy change arriving as metadata, where the mechanism for "we accept
		// this" already exists and records who decided. The risk is also unchanged: a vulnerable
		// control plane is exactly as dangerous whether or not the fix is yours to apply.
		//
		// Ordering is the honest half of it. Two findings that matter equally, and one of them
		// has somewhere for the reader to start.
		if ao, bo := actionableRank(a), actionableRank(b); ao != bo {
			return ao > bo
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
			// The repository and revision are reported once for the run, not once per control:
			// five controls reading one checkout is one fact, and repeating it five times in a
			// block headed "measured against" is how a useful section becomes wallpaper.
			p.Fields = withoutRepositoryFields(p.Fields)
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

// suppressionAttribution summarizes who accepted the suppressed findings.
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
			if !res.Suppressed() || res.Imported() {
				// An imported claim has no acceptedBy and is not unattributed either — a named
				// supplier asserted it. Counting it here would report somebody else's signed
				// analysis as a decision nobody signed, which is the opposite of true.
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
	// Only named when there is more than one, so a descriptor that is a single file reads exactly
	// as it did before fragments existed. The breakdown answers a question that only arises once
	// the exclusions live somewhere other than the file you opened.
	if sources := suppressionSources(d); len(sources) > 1 {
		var where []string
		for _, s := range sources {
			where = append(where, fmt.Sprintf("%d from %s", s.n, s.name))
		}
		line = fmt.Sprintf("%s suppressed — %s", plural(n, "finding"), strings.Join(where, ", "))
	}
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

// importedLine renders the one-line account of what a supplier's own analysis excused.
//
// Its own line rather than folded into the suppression count, because the two answer the
// auditor's question differently. "We accepted this" and "our supplier states it does not apply"
// are different sentences with different people at the end of them, and a total that merges them
// can only support the weaker one.
func importedLine(d Data) string {
	n := d.Run.Imported
	if n == 0 {
		return ""
	}
	authors, counts := importedAttribution(d)
	line := fmt.Sprintf("%s excused by a supplier's VEX", plural(n, "finding"))
	var parts []string
	for _, who := range authors {
		parts = append(parts, fmt.Sprintf("%d asserted by %s", counts[who], who))
	}
	if len(parts) > 0 {
		line += " — " + strings.Join(parts, ", ")
	}
	return line
}

// reachabilityLine reports what reachability analysis concluded, in one line.
//
// One line rather than a marker on every row. A reader scanning forty findings is deciding what
// to do first, and forty repetitions of the same word does not help them choose — the useful
// facts are how many were ranked down and how much of the answer is missing. Per-finding detail
// is in the JSON and the SARIF, where something is reading rather than skimming.
//
// Unknown is named whenever there is any, because it is the honest qualifier on the rest of the
// sentence: an analyzer that could not cover half the dependencies has said much less than the
// unreachable count on its own suggests.
func reachabilityLine(d Data) string {
	r := d.Run.Reachability
	if r.Analyzer == "" {
		return ""
	}
	line := fmt.Sprintf("%s: %d reachable, %d not", r.Analyzer, r.Reachable, r.Unreachable)
	if r.Unknown > 0 {
		line += fmt.Sprintf(", %d undetermined", r.Unknown)
	}
	return line + " — findings nothing can reach are ranked down, not removed"
}

// importedAttribution counts imported suppressions by the author who asserted them.
//
// A document with no author is reported as such rather than skipped. A claim nobody signed is
// still a claim somebody chose to accept, and its anonymity is the most interesting thing about it.
func importedAttribution(d Data) (authors []string, counts map[string]int) {
	counts = map[string]int{}
	for _, cr := range d.Run.Controls {
		for _, res := range cr.Report.Results {
			if !res.Imported() {
				continue
			}
			who := res.Suppression.Author
			if who == "" {
				who = "an unnamed author"
			}
			if _, seen := counts[who]; !seen {
				authors = append(authors, who)
			}
			counts[who]++
		}
	}
	sort.Strings(authors)
	return authors, counts
}

// sourceCount is one file's contribution to the suppressions in a run.
type sourceCount struct {
	name string
	n    int
}

// suppressionSources counts suppressions per originating file, most first, then by name so a
// report is reproducible.
func suppressionSources(d Data) []sourceCount {
	counts := map[string]int{}
	for _, cr := range d.Run.Controls {
		for _, res := range cr.Report.Results {
			if res.Suppression == nil || res.Suppression.Source == "" {
				continue
			}
			counts[res.Suppression.Source]++
		}
	}
	out := make([]sourceCount, 0, len(counts))
	for name, n := range counts {
		out = append(out, sourceCount{name: name, n: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].n != out[j].n {
			return out[i].n > out[j].n
		}
		return out[i].name < out[j].name
	})
	return out
}

// RepositoriesFrom collects which repository each scan read, and at which commit.
func RepositoriesFrom(run engine.Result) []RepositoryProvenance {
	names := make([]string, 0, len(run.Controls))
	for name := range run.Controls {
		names = append(names, name)
	}
	sort.Strings(names)
	reports := make([]sarif.Report, 0, len(names))
	for _, name := range names {
		reports = append(reports, run.Controls[name].Report)
	}
	return sarif.RepositoriesIn(reports)
}

// withoutRepositoryFields drops the fields that belong to the report-level repository line.
func withoutRepositoryFields(fields []sarif.Field) []sarif.Field {
	out := make([]sarif.Field, 0, len(fields))
	for _, f := range fields {
		switch f.Key {
		case "repository", "revision", "uncommitted":
		default:
			out = append(out, f)
		}
	}
	return out
}

// actionableRank orders findings of equal priority by whether the reader can do something.
//
// Three steps rather than a boolean, because "upgrade this" and "move the release underneath you"
// are both actions and the first is smaller. Nothing here changes what a finding is worth — only
// which of two equally urgent ones is worth reading first.
func actionableRank(f finding) int {
	switch f.remediation {
	case sarif.RemediationUpgrade:
		return 3
	case sarif.RemediationUpstream:
		return 2
	case sarif.RemediationNone:
		return 1
	case sarif.RemediationExternal:
		// Still reported, still counted, still failing the gate if policy says so — last within
		// its band because the reader cannot start here.
		return 0
	default:
		return 1
	}
}

// GateSettings is the policy a verdict was produced under, as the report states it.
//
// Held here rather than recomputed from the Saga: the effective gate is the descriptor, the
// configuration and the flags resolved together, and a reporter deriving it a second time is how
// the report and the verdict come to disagree about the run they describe.
type GateSettings struct {
	// Threshold is the severity band that fails a control by default.
	Threshold sarif.Severity
	// PerControl overrides Threshold for named controls.
	PerControl map[string]sarif.Severity
	// FailOnPriority additionally fails on a priority band, when set.
	FailOnPriority string
	// Disabled is --no-gate: the verdict is reported and the command still exits 0.
	Disabled bool
}

// weakened reports whether the gate lets through something the default gate would have caught.
//
// Only a weakening is worth interrupting the default view for. A stricter gate can only fail more
// than a reader expects, which is visible in the verdict itself; a looser one produces a pass that
// looks like every other pass.
func (g GateSettings) weakened() bool {
	if g.Disabled {
		return true
	}
	if g.Threshold != "" && g.Threshold.Rank() > sarif.SeverityHigh.Rank() {
		return true
	}
	effective := g.Threshold
	if effective == "" {
		effective = sarif.SeverityHigh
	}
	for _, band := range g.PerControl {
		if band != "" && band.Rank() > effective.Rank() {
			return true
		}
	}
	return false
}
