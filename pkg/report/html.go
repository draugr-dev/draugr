package report

import (
	"fmt"
	"html/template"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/internal/english"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// htmlReporter renders a self-contained HTML report, a single file with inline CSS, viewable in
// any browser and shareable as a build artifact. Leads with the verdict, priority counts,
// per-control severity, and the full ranked finding list.
type htmlReporter struct{}

func (htmlReporter) Format() string { return "html" }

// htmlView is the template model: a summary plus display-ready strings.
type htmlView struct {
	Verdict        string // "PASS" | "FAIL"
	Pass           bool
	Release        string
	Prioritized    bool
	P1, P2, P3, P4 int
	Controls       []htmlControl
	// Components breaks the verdict down by the part of the application it belongs to.
	//
	// The controls table answers whether the project is shippable. A component is the unit a team
	// owns and the unit exposure and criticality are declared on, so with several of them a failing
	// control says the project has a problem and stops short of saying whose.
	//
	// Unattributed is how many findings belong to no component, because project-wide controls
	// produce those and a table that omits them makes the parts look like the whole.
	Components   []htmlComponent
	Unattributed int
	Findings     []htmlFinding
	// Provenance is what each scanner said about its own run, the standard applied, how much of it
	// was decided, what it was scoped to. A shared HTML report is the copy that reaches someone who
	// did not run the scan, so it is the one that most needs to say what was measured rather than
	// only what was found.
	Provenance []provenanceLine
	// Repositories is which repository was read and at which commit. The thing that makes the
	// report reproducible, and the answer to "does this describe my change or the last release".
	Repositories []RepositoryProvenance
	// Actions is the fix list: one row per thing to do, and how many findings it clears.
	//
	// Always the whole run, never what the menus narrowed. The band chips in the strip are never
	// filtered either, and these two have to agree: a work list that shrank because somebody
	// ticked P1 reads as "less to do" rather than "less shown", and it disagrees with the counts
	// two lines above it with nothing on screen to say why.
	Actions  []htmlAction
	External int

	// Scanned is Repositories as a reader meets them. A report travels, so a repository has to be
	// named by something that means the same thing wherever it is opened.
	Scanned []htmlRepo
	// Exploitability names the datasets that raised severities, with the date each was obtained. A
	// shared report claiming a finding is critical has to be able to say on what data. And this is
	// the copy most likely to be read by someone who cannot re-run the scan.
	Exploitability []htmlFeed
	// Errors, Suppressed and SBOM describe what the run couldn't do and what it set aside. A
	// shared report that omits them describes a thinner run rather than a broken one, and the
	// reader has no way to tell which they are looking at.
	Errors []htmlError
	// Suppressed, Imported and Silenced are the three authorities that can set a finding aside, and
	// they are counted apart because they answer an auditor differently: this project decided, a
	// supplier asserts, or whoever was editing the file wrote a comment the scanner honored. One
	// total can only report the weakest of the three, and a note that names `config.exclude` over a
	// list holding all three claims we accepted things nobody here ever saw.
	Suppressed  int
	Imported    int
	Silenced    int
	SBOMCount   int
	SBOMFormat  string
	MinPriority string // set when the listing was filtered, so the page can say so
	Hidden      int
	// Signals is what argued with the ranking: an exploitation catalog, a prediction, a control's
	// own floor, a reachability verdict. Absent from this format entirely, which made the rendered
	// report the one place a reader could not find out why a finding outranked its severity.
	Signals []htmlSignal
	// Decisions is one row per acceptance. This is the copy somebody keeps, so it carries the
	// account rather than the count: who, why, and until when.
	Decisions []htmlDecision
	// Unmatched are the rules that suppressed nothing. In a report read apart from the descriptor,
	// nothing else would say the line was dead.
	Unmatched []htmlUnmatched
	// Gate is the rule the verdict was produced under. A verdict nobody can check is a claim.
	Gate string
	// Excluded are the findings that were set aside, each with the reason given and the authority
	// that gave it. The count alone answers "was anything hidden"; an auditor asks who decided it
	// was acceptable, which needs both the reason and the name next to the finding.
	Excluded []htmlFinding
	// Facets are the distinct values the filter controls offer, so the toolbar only ever shows
	// options that match something.
	// The menus above the findings. Priority and severity are the product's own vocabulary, so
	// every value is offered with a zero where this run has none; a reader cannot tell "no P1s
	// here" from "this filter does not exist" when the option is simply absent. Control and
	// component are the project's, so they offer what appears.
	Priorities, Severities       []htmlFacet
	ControlNames, ComponentNames []htmlFacet
	// Fixes and Scanners are the project's too: which kinds of work this run needs, and which
	// tools reported anything.
	Fixes, Scanners []htmlFacet
	// SARIFHref and TSVHref are data: URIs. Downloads that work with no JavaScript and under any
	// content-security policy.
	SARIFHref, TSVHref template.URL
	SARIFTooBig        bool
	Generated, Version string
	Duration           string
	// Slowest names the controls that took longest, worst first. A job count says nothing about
	// where the time went; with concurrency the parts do not sum to the whole, and the control
	// worth looking at is the slow one.
	Slowest   []htmlTiming
	CacheHits int
}

type htmlTiming struct {
	Control, Duration string
	Pct               int // share of the summed control time, for the bar
}

type htmlError struct{ Control, Message string }

// htmlComponent is one component's row: what it was declared to be, how its own findings ranked,
// and what nothing was able to look at.
type htmlComponent struct {
	Name string
	// Class is the exposure and criticality the descriptor declared, as one string, and empty
	// where it declared neither. Half of why two components with the same finding hold different
	// bands, and without it the difference between two rows has no visible cause.
	Class   string
	Verdict string // "PASS" | "FAIL" | "ERROR" | "not scanned"
	Fail    bool
	// Errored marks a component whose scans failed and which therefore found nothing in the sense
	// that nothing was possible. Distinct from a pass, which this row must not be read as.
	Errored bool
	// Skipped marks a declared component this run's scope left out. Listed rather than omitted,
	// because an absent row reads exactly like one that passed.
	Skipped        bool
	Prioritized    bool
	P1, P2, P3, P4 int
	Findings       int
	Unscanned      string // "2/3 repositories not scanned", empty where everything was reached
	// Failed names the controls this component did not pass. Carried for the strip and not for the
	// table: which control failed is the next question once somebody has narrowed to one component,
	// and a column of it across every row is a second controls table read sideways.
	Failed []string
}

type htmlControl struct {
	Control  string
	Fail     bool
	Errored  bool // its scanner failed: whatever it reported is partial
	NoReport bool // it produced nothing at all, so has no counts to show
	// Bands are how many findings landed in each priority, which is the vocabulary the verdict, the
	// components and the gate all speak. The severities stay for a run that ranked nothing, where
	// they are all there is.
	P1, P2, P3, P4              int
	Prioritized                 bool
	Critical, High, Medium, Low int
}

// htmlSignal is one thing that argued with this run's ranking, and how many findings it moved.
type htmlSignal struct{ Name, Effect string }

// htmlDecision is one acceptance: how many findings it covers, who signed it, when it lapses, and
// why. The count alone says how much was set aside and never what was acceptable about it.
type htmlDecision struct {
	N               int
	By              string
	Unattributed    bool
	Expires, Reason string
}

// htmlUnmatched is a rule that suppressed nothing, named by what a reader would go and edit.
//
// The matchers stay a list of pairs rather than one sentence: the descriptor field and the pattern
// written in it are different kinds of thing, and a reader deciding whether the pattern is right
// should not have to work out which half is ours.
type htmlUnmatched struct {
	Source   string
	Matchers []matcher
	Reason   string
}

// fixPhrase says what to do about a finding, in one clause.
//
// For a package: there is a release that ends it, there is no release yet, or somebody else has to
// publish one. For everything else the answer depends on where the problem lives, which is a
// property of the control that found it. "Change the code" is right for a flaw in code somebody
// owns and wrong everywhere else: a signature mismatch, a server header and a host on a blocklist
// have no code to change, and an instruction nobody can carry out is worse than none, because it
// teaches a reader that this column is not worth reading.
func fixPhrase(f finding) string {
	if f.pkg != nil && f.pkg.Name != "" {
		if f.pkg.FixedVersion != "" {
			return "upgrade to " + firstFixedVersion(f.pkg.FixedVersion)
		}
		if f.builtUpstream {
			return "somebody else publishes it"
		}
		return "no upgrade published"
	}
	// Which control found it, rather than whether a package came with it. A dependency scanner
	// that reported no package metadata has still reported a dependency, and telling somebody to
	// change their code about a CVE in a lockfile is an instruction they cannot carry out.
	switch f.control {
	case "sca", "images", "licenses":
		return "no package reported"
	case "provenance":
		return provenanceFix(f.ruleID)
	case "secrets":
		// Removing it from the code leaves it in history and leaves it valid. The credential is the
		// thing that leaked, so it is the thing to replace.
		return "rotate the credential"
	case "headers":
		return headersFix(f.ruleID)
	case "tls":
		return "change the server's configuration"
	case "infrastructure":
		return "change the cluster's configuration"
	case "threats":
		return "stop contacting the host"
	}
	return "change the code"
}

// headersFix says what to do about a header finding. Most are the server's configuration; the
// ones comparing the policy with its page have two fixes, the policy or the page, and which is
// right depends on whether the content was meant to be there.
func headersFix(rule string) string {
	switch {
	case strings.HasPrefix(rule, "headers/csp-blocks-inline-"):
		return "move it into a file, or allow it by hash"
	case strings.HasPrefix(rule, "headers/csp-blocks-"):
		return "allow the origin, or stop loading from it"
	}
	return "change the server's configuration"
}

// provenanceFix says what to do about a signature finding. Three rules, three different next
// steps, because the three situations share nothing but the control that noticed them.
func provenanceFix(rule string) string {
	switch rule {
	case "provenance-unexpected-identity":
		// Either a build moved to another workflow or the image is not what it claims. Both start
		// with finding out which, and nothing should run this image until somebody has.
		return "find out what signed it before running it"
	case "provenance-unsigned":
		return "sign it in the build that publishes it"
	case "provenance-not-covered":
		return "declare a signer, or accept it unsigned"
	}
	return "check the signature"
}

// firstFixedVersion is the release to move to, where a scanner named several.
//
// Trivy reports one per maintained branch, so `1.24.13, 1.25.7, 1.26.0-rc.3` is three answers to
// "which branch are you on" rather than one instruction, and it is as long as the number of
// branches upstream maintains. The first is the lowest release that clears the finding; the count
// says the others exist, and the report document carries them all.
func firstFixedVersion(fixed string) string {
	first, rest, found := strings.Cut(fixed, ",")
	if !found {
		return fixed
	}
	return fmt.Sprintf("%s +%d", strings.TrimSpace(first), strings.Count(rest, ",")+1)
}

type htmlFinding struct {
	Priority, Severity, SevClass, Score, RuleID, Control, Tool, Component, Location, Message string
	// Full is the scanner's whole message, set only where Message had to be shortened to fit a
	// row. The row opens to it, so the list stays one line per finding and nothing a scanner said
	// is lost to the report.
	Full string
	// Upgrade is the dependency and the release that clears it, which is the only instruction on
	// the row. Empty for a finding that is not about a package.
	Upgrade string
	// FixKind is Fix as a menu offers it. Every release is a different phrase, and a menu listing
	// "upgrade to 2.10.1" beside "upgrade to 4.17.21" offers one value per package rather than one
	// kind of work, so every upgrade is one option.
	FixKind string
	// Fix is what to do about this finding, as a phrase rather than a version diff.
	//
	// Always set. A column carrying "jinja2 2.10 → 2.10.1" is empty for every finding that is not
	// about a package, which is most of iac, sast and secrets, and a reader learns to skip it. A
	// phrase answers for all of them, and says so in the words the plane already uses.
	Fix string
	// MovedGlyph and MovedLabel name what argued with this finding's band, in the words the console
	// uses. MovedDir is "up" or "down" where the band moved, and empty for a mark that moved nothing,
	// so the chip can wear the color of the direction rather than of whatever raised it.
	MovedGlyph, MovedLabel, MovedDir string
	// HelpURI documents the rule. Rendered as a link because this is the one format where a
	// link costs nothing, and a rule id names a finding without explaining it.
	HelpURI string
	// AcceptedVia names the authority that set this finding aside: a rule in this project's
	// descriptor, a supplier's document, or a comment in the source. Only set for a suppressed
	// finding, and set for every one of them, because a row with a reason and no author reads as a
	// decision this project made whoever actually made it.
	AcceptedVia string
	// Justification is why the finding was set aside. Only set for suppressed findings.
	Justification string
	// Search is the lower-cased haystack the filter box matches against, precomputed so the
	// page does not rebuild it per keystroke.
	Search string
	// ActionKey is the action that clears this finding, so the list can be narrowed to exactly
	// what one row of the fix list covers. Empty where nobody running the scan can act on it,
	// which is the set the fix list leaves out.
	ActionKey string
}

func (htmlReporter) Render(w io.Writer, d Data) error {
	s := summarize(d)

	view := htmlView{
		Provenance:     provenanceLines(d),
		Repositories:   d.Repositories,
		Scanned:        htmlRepos(d.Repositories),
		Exploitability: htmlFeeds(d.Exploitability),
		Pass:           s.verdict != norn.Fail,
		Prioritized:    s.prioritized,
		P1:             s.p1, P2: s.p2, P3: s.p3, P4: s.p4,
		Suppressed:  s.suppressed,
		Imported:    d.Run.Imported,
		Silenced:    d.Run.Silenced,
		SBOMCount:   s.sboms,
		SBOMFormat:  s.sbomFormat,
		MinPriority: strings.ToUpper(s.minPriority),
		Hidden:      s.hidden,
	}
	for _, name := range sortedKeys(s.scanErrors) {
		for _, msg := range dedupeMessages(s.scanErrors[name]) {
			view.Errors = append(view.Errors, htmlError{Control: name, Message: findingSummary(msg)})
		}
	}
	view.SARIFHref, view.SARIFTooBig = buildSARIFDownload(d)
	view.TSVHref = buildTSVDownload(s)
	if !d.Generated.IsZero() {
		view.Generated = d.Generated.UTC().Format("2006-01-02 15:04:05 UTC")
	}
	view.Version = BuildLabel(d.Version)
	view.Duration, view.Slowest = timings(d.Run.Stats)
	view.CacheHits = d.Run.Stats.CacheHits
	for _, f := range s.excluded {
		view.Excluded = append(view.Excluded, toHTMLFinding(f))
	}
	view.Verdict = "PASS"
	if s.verdict == norn.Fail {
		view.Verdict = "FAIL"
	}
	if name := d.ProjectName(); name != "" {
		view.Release = name
		if d.Release.Version != "" {
			view.Release += " " + d.Release.Version
		}
	}
	for _, c := range d.Verdict.Controls {
		b, at := s.bands[c.Control], s.controlBands[c.Control]
		_, bad := s.scanErrors[c.Control]
		view.Controls = append(view.Controls, htmlControl{
			Control: c.Control, Fail: c.Verdict == norn.Fail, Errored: bad,
			Prioritized: s.prioritized,
			P1:          at[0], P2: at[1], P3: at[2], P4: at[3],
			Critical: b.critical, High: b.high, Medium: b.medium, Low: b.low,
		})
	}
	// Controls that produced no report at all have no verdict entry. Omitting them is how a
	// run that could not check something reads as a run that checked it and found nothing.
	for _, name := range s.errored {
		view.Controls = append(view.Controls, htmlControl{Control: name, Errored: true, NoReport: true})
	}
	view.Components = htmlComponents(d, s)
	view.Unattributed = d.UnattributedFindings
	prio, sev, ctl, comp := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	fixes, tools := map[string]int{}, map[string]int{}
	for _, f := range s.findings {
		hf := toHTMLFinding(f)
		view.Findings = append(view.Findings, hf)
		prio[hf.Priority]++
		sev[hf.Severity]++
		ctl[hf.Control]++
		comp[hf.Component]++
		fixes[hf.FixKind]++
		tools[hf.Tool]++
	}
	// The same grouping the console prints and the control plane's "What to do" shows, from the
	// same function. A fix list that is a different shape depending on where it is read is three
	// answers to one question.
	grouped, external := groupActions(s.findings, d.Run.Stats.UnpinnedCacheHits)
	view.External = len(external)
	for _, a := range grouped {
		view.Actions = append(view.Actions, toHTMLAction(a))
	}
	view.Signals = htmlSignals(d, s)
	for _, dec := range decisions(d) {
		view.Decisions = append(view.Decisions, htmlDecision{
			N: dec.n, By: dec.by, Unattributed: dec.by == "unattributed",
			Expires: dec.expires, Reason: dec.reason,
		})
	}
	for _, e := range d.Run.UnmatchedExclusions {
		view.Unmatched = append(view.Unmatched, htmlUnmatched{
			Source: "config.exclude", Matchers: excludeMatchers(e), Reason: findingSummary(e.Reason),
		})
	}
	for _, c := range d.Run.UnmatchedClaims {
		// A claim has no field to name: the vulnerability and the package are both values, and the
		// pair is what did not line up.
		view.Unmatched = append(view.Unmatched, htmlUnmatched{
			Source: "VEX", Matchers: []matcher{{Key: "statement", Value: claimSummary(c)}},
		})
	}
	// Without its own prefix: the row it sits in is labeled `gate`, and a value that names itself
	// again says the same word twice.
	view.Gate = strings.TrimPrefix(gateSentence(d), "Gate: ")
	view.Priorities = ourVocabulary([]string{"P1", "P2", "P3", "P4"}, prio)
	view.Severities = ourVocabulary([]string{"critical", "high", "medium", "low"}, sev)
	view.ControlNames = theirVocabulary(ctl)
	view.ComponentNames = theirVocabulary(comp)
	view.Fixes = theirVocabulary(fixes)
	view.Scanners = theirVocabulary(tools)
	return htmlTemplate.Execute(w, view)
}

// htmlComponents is the per-component verdict the console prints, as table rows.
//
// The clean components are the point as much as the failing ones: a pass against a named component
// is what somebody takes back to their team, and a shared report is the copy that reaches the
// people who did not run the scan and cannot read it off the findings table by eye.
func htmlComponents(d Data, s summary) []htmlComponent {
	if len(d.Components) == 0 {
		return nil
	}
	out := make([]htmlComponent, 0, len(d.Components))
	for _, c := range d.Components {
		row := htmlComponent{
			Name: c.Name, Verdict: "PASS", Fail: c.Verdict == norn.Fail,
			Class:       classification(c.Exposure, c.Criticality),
			Prioritized: s.prioritized,
			P1:          c.Priorities[0], P2: c.Priorities[1], P3: c.Priorities[2], P4: c.Priorities[3],
			Findings: c.Findings,
			Failed:   c.Controls,
		}
		if row.Fail {
			row.Verdict = "FAIL"
		}
		// A component nothing was able to look at has not passed. Its scans failed, so "no
		// findings" is true only in the sense that none were possible, which is the reading this
		// row must not invite.
		if len(c.Unscanned) > 0 {
			row.Unscanned = unscannedDetail(c.Unscanned, c.Declared)
			if c.Findings == 0 {
				row.Verdict, row.Errored, row.Fail = "ERROR", true, false
			}
		}
		out = append(out, row)
	}
	if d.Scope != nil {
		for _, name := range d.Scope.SkippedComponents {
			out = append(out, htmlComponent{Name: name, Verdict: "not scanned", Skipped: true})
		}
	}
	return out
}

// classification renders what the descriptor declared a component to be, and nothing where it
// declared neither half.
func classification(exposure, criticality string) string {
	switch {
	case exposure != "" && criticality != "":
		return exposure + " · " + criticality
	case exposure != "":
		return exposure
	default:
		return criticality
	}
}

// htmlSignals is what argued with this run's ranking, named the way the console names it.
//
// One list rather than four scattered facts: an exploitation catalog, a prediction about one, a
// control's own floor and a reachability verdict all answer the same question, and a reader can
// only compare them where they are together.
func htmlSignals(d Data, s summary) []htmlSignal {
	var out []htmlSignal
	for _, name := range []string{"kev", "epss"} {
		n := s.bySignal[name]
		if n == 0 && !consulted(d, name) {
			continue
		}
		// "nothing raised" is a result rather than an absence: without it the only way to learn a
		// feed changed nothing is to read every finding looking for a mark that is not there.
		effect := "nothing raised"
		if n > 0 {
			effect = fmt.Sprintf("%s raised", english.Count(n, "finding"))
		}
		out = append(out, htmlSignal{Name: strings.ToUpper(name), Effect: effect})
	}
	if n := s.floored; n > 0 {
		out = append(out, htmlSignal{
			Name: "floor", Effect: fmt.Sprintf("%s raised by a control's own rule", english.Count(n, "finding")),
		})
	}
	rows, _ := reachabilityBlock(d)
	for _, row := range rows {
		analyzer, did, _ := strings.Cut(row, "  ")
		out = append(out, htmlSignal{
			Name: "reachability", Effect: strings.TrimSpace(analyzer) + " · " + strings.TrimSpace(did),
		})
	}
	return out
}

// timings renders the run's wall-clock and a worst-first control breakdown.
//
// Percentages are of the summed control time rather than of wall-clock: controls run in
// parallel, so shares of the elapsed time would add up to well over 100 and read as a bug.
func timings(st engine.Stats) (total string, slowest []htmlTiming) {
	if st.Duration <= 0 {
		return "", nil
	}
	var sum time.Duration
	for _, d := range st.ByControl {
		sum += d
	}
	for name, d := range st.ByControl {
		t := htmlTiming{Control: name, Duration: humanDuration(d)}
		if sum > 0 {
			t.Pct = int(float64(d) / float64(sum) * 100)
		}
		slowest = append(slowest, t)
	}
	sort.Slice(slowest, func(i, j int) bool {
		if slowest[i].Pct != slowest[j].Pct {
			return slowest[i].Pct > slowest[j].Pct
		}
		return slowest[i].Control < slowest[j].Control // stable when two tie
	})
	return humanDuration(st.Duration), slowest
}

// humanDuration rounds to something a reader can compare at a glance rather than to nanoseconds.
func humanDuration(d time.Duration) string {
	switch {
	case d >= time.Minute:
		return d.Round(time.Second).String()
	case d >= time.Second:
		return d.Round(100 * time.Millisecond).String()
	default:
		return d.Round(time.Millisecond).String()
	}
}

func toHTMLFinding(f finding) htmlFinding {
	// The rating the band was computed from, so a row does not contradict the band beside it, and
	// the mark that moved it. Both are what the console shows for the same finding.
	sev := rankedSeverity(f)
	var glyph, label, dir string
	if m := movedBy(f); m != nil {
		glyph, label = m.glyph, m.label
		switch m.glyph {
		case "↑":
			dir = "up"
		case "↓":
			dir = "down"
		}
	}
	fix := fixPhrase(f)
	var pkgName string
	if f.pkg != nil {
		pkgName = f.pkg.Name
	}
	kind := fix
	if strings.HasPrefix(fix, "upgrade to ") {
		kind = "upgrade"
	}
	title := findingTitle(f)
	full := strings.Join(strings.Fields(f.message), " ")
	if full == title {
		full = ""
	}
	return htmlFinding{
		Priority: dash(f.priority), Severity: string(sev), SevClass: "sev-" + string(sev),
		Score: scoreStr(f), RuleID: f.ruleID, Control: f.control, Tool: dash(f.tool),
		Component: dash(f.component),
		Location:  dash(f.location), Message: title, Full: full, HelpURI: f.helpURI,
		Upgrade:       upgradeLabel(f),
		Fix:           fix,
		FixKind:       kind,
		MovedGlyph:    glyph,
		MovedLabel:    label,
		MovedDir:      dir,
		AcceptedVia:   f.acceptedVia,
		Justification: f.justification,
		ActionKey:     actionKeyFor(f),
		Search: strings.ToLower(strings.Join(
			[]string{f.ruleID, f.control, f.tool, f.component, f.location, f.message, f.priority, string(sev), fix, pkgName}, " ")),
	}
}

// actionKeyFor is the action a finding belongs to, or empty where it belongs to none.
//
// The same key the grouping uses, from the same function, so a row in the fix list and the rows it
// claims to cover cannot disagree about which they are.
func actionKeyFor(f finding) string {
	if f.remediation == sarif.RemediationExternal {
		return ""
	}
	key, _ := actionFor(f)
	return key
}

// htmlAction is one thing to do, rendered.
type htmlAction struct {
	Key      string
	Title    string
	Priority string
	Control  string
	Clears   int
	Upstream bool
	Cached   bool
	Where    string
}

// toHTMLAction renders an action the way the console renders one, so the two agree line for line.
func toHTMLAction(a action) htmlAction {
	title := a.title
	// The version to move to, when every advisory agrees on one. In the title because it is the
	// action rather than a footnote to it.
	if v := a.target(); v != "" {
		title += " → " + v
	}
	out := htmlAction{
		Key: a.key, Title: title, Priority: a.priority, Control: a.control,
		Clears: a.count(), Upstream: a.upstream, Cached: a.cached,
	}
	if out.Priority == "" {
		out.Priority = "-"
	}
	// Not for an image action: the image is the title, and repeating it underneath says nothing.
	if !a.upstream {
		out.Where = strings.Join(a.where(2), " · ")
	}
	return out
}

// htmlRepo is one scanned repository as the report states it.
type htmlRepo struct {
	Name        string
	Revision    string
	Uncommitted int
	Local       bool
}

// htmlRepos names each repository by something portable, and says so when there is nothing
// portable to use.
//
// A descriptor may write `url: .`, and Draugr resolves that to the remote the checkout came from,
// which is what a reader elsewhere can act on. Where there is no remote there is no portable name,
// and the literal "." is worse than useless in a document somebody attaches to a ticket: it points
// at a working directory the reader does not have. The absolute path at least says which checkout
// on which machine, and the commit is what actually identifies the code either way.
func htmlRepos(refs []RepositoryProvenance) []htmlRepo {
	out := make([]htmlRepo, 0, len(refs))
	for _, r := range refs {
		e := htmlRepo{Name: r.URL, Revision: r.Short(), Uncommitted: r.Uncommitted}
		if e.Revision == "" {
			e.Revision = "unknown"
		}
		if !strings.Contains(r.URL, "://") && !strings.Contains(r.URL, "@") {
			e.Local = true
			if abs, err := filepath.Abs(r.URL); err == nil {
				e.Name = abs
			}
		}
		out = append(out, e)
	}
	return out
}

// htmlFacet is one option in a filter menu: the value, and how many findings carry it.
//
// The count is on the option rather than only on the result, because a menu that says how much
// each choice would leave is one a reader can plan with instead of one they have to try.
type htmlFacet struct {
	Value string
	Count int
}

// ourVocabulary lists every value the product defines, in the product's order, whether or not this
// run produced any.
//
// A band with no findings is a fact worth stating. Dropping the option makes "none here" and "this
// build does not rank" look the same, and the first is a result while the second is a gap.
func ourVocabulary(all []string, counts map[string]int) []htmlFacet {
	out := make([]htmlFacet, 0, len(all))
	for _, v := range all {
		out = append(out, htmlFacet{Value: v, Count: counts[v]})
	}
	return out
}

// theirVocabulary lists what this run actually produced, alphabetically.
//
// Controls and components are the project's words rather than ours, so there is no set to
// enumerate: offering one that appears nowhere would be inventing a name for somebody's estate.
func theirVocabulary(counts map[string]int) []htmlFacet {
	out := make([]htmlFacet, 0, len(counts))
	for v, n := range counts {
		if v == "" {
			continue
		}
		out = append(out, htmlFacet{Value: v, Count: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Value < out[j].Value })
	return out
}

// htmlTemplate is parsed once at package init; html/template escapes all interpolated values.
var htmlTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	// dict lets one menu template serve every dimension. Four near-identical blocks is four places
	// to fix a menu, and the one nobody edits is the one that drifts.
	"dict": func(pairs ...any) map[string]any {
		out := make(map[string]any, len(pairs)/2)
		for i := 0; i+1 < len(pairs); i += 2 {
			key, _ := pairs[i].(string)
			out[key] = pairs[i+1]
		}
		return out
	},
	// The same pluralization the console uses, so one finding is a finding here too. "1 finding(s)"
	// is a sentence nobody would write by hand and the only reason it survives is that it is never
	// read aloud.
	"plural": english.Count,
	"join":   func(items []string) string { return strings.Join(items, ", ") },
}).Parse(htmlDoc))

const htmlDoc = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Draugr report{{if .Release}} · {{.Release}}{{end}}</title>
<style>
  /* Draugr's palette, the same tokens and the same values the control plane uses, so a report a
   * developer opens and the fleet view their security lead opens are recognizably one product.
   *
   * Dark first, because that is where the product lives, with a light override for a reader whose
   * machine says so and for print. Every color is a token: a hex written into a rule is a color
   * the other theme never received, and the theme nobody looked at is the one somebody opens. */
  :root {
    color-scheme: dark light;

    --bg: #0b0e11;
    --surface: #12161b;
    --surface-sunken: #0e1216;
    --line: #232a31;
    --line-strong: #2f3841;

    --text: #e6e8ea;
    --muted: #9aa4ae;
    --faint: #78838d;

    --accent: #e8b84b;
    --accent-quiet: rgb(232 184 75 / 12%);
    --accent-text: #e8b84b;
    --on-accent: #0b0e11;

    /* The priority ramp, and it is not invented here: these are the values the console already
     * prints and the dashboard already draws, so a band means one color everywhere. */
    --p1: #e5534b;
    --p2: #e8b84b;
    --p3: #7ca6b8;
    --p4: #6b7680;
    --on-p1: #120605;
    --on-p2: #16110a;
    --on-p3: #0a1116;
    /* White rather than the body ink: P4 is the lightest fill in the ramp, and the page's own text
     * color on it measures 3.78:1, under the floor. This clears it at 4.64:1 in both themes,
     * because the P4 fill keeps its hue the way the rest of the ramp does. */
    --on-p4: #ffffff;
    /* The quiet fills a priority chip in a list sits on, the band's own hue under its own ink. */
    --p1-quiet: rgb(229 83 75 / 14%);
    --p2-quiet: rgb(232 184 75 / 14%);
    --p3-quiet: rgb(124 166 184 / 14%);
    --p4-quiet: rgb(107 118 128 / 16%);

    --pass: #57ab5a;
    --fail: #e5534b;
    --on-pass: #06120a;
    --on-fail: #120605;

    --radius: 6px;
    --control-height: 37px;
  }

  /* An explicit choice wins over the system in both directions, which is what makes the toggle
   * reversible. Light is also what somebody printing this wants: a page of near-black costs a
   * cartridge, and the print rule below only helps whoever remembers to preview. */
  /* An explicit choice wins over the system in both directions, which is what makes the toggle
   * reversible: without the :not() a reader who picks dark on a light machine gets light back.
   * Light is also what somebody printing wants, because a page of near-black costs a cartridge and
   * the print rule below only helps whoever remembers to preview.
   *
   * The same tokens twice, because CSS has no way to name a block and apply it from two places,
   * and the alternative is a light theme that only one of the two routes reaches. */
  :root[data-theme="light"] {

  --bg: #ffffff;
  --surface: #f6f7f8;
  --surface-sunken: #eef1f3;
  --line: #dfe3e7;
  --line-strong: #c3cad1;

  --text: #10161c;
  --muted: #55606b;
  --faint: #6b7680;

  --accent: #a97d12;
  --accent-quiet: rgb(232 184 75 / 26%);
  --accent-text: #7d5a08;
  --on-accent: #ffffff;

  /* The bands keep their hue, because a band that changed color with the theme would be two
  * scales for one set of numbers. Only the ink on them moves. */
  --p1: #c0342b;
  --on-p1: #ffffff;
  --p2: #e8b84b;
  --p3: #7ca6b8;
  --p4: #6b7680;
  --p1-quiet: rgb(192 52 43 / 11%);
  --p2-quiet: rgb(169 125 18 / 26%);
  --p3-quiet: rgb(52 99 122 / 22%);
  --p4-quiet: rgb(107 118 128 / 14%);

  --pass: #2e7d33;
  --fail: #c0342b;
  --on-pass: #ffffff;
  --on-fail: #ffffff;
  }

  @media (prefers-color-scheme: light) {
    :root:not([data-theme="dark"]) {

    --bg: #ffffff;
    --surface: #f6f7f8;
    --surface-sunken: #eef1f3;
    --line: #dfe3e7;
    --line-strong: #c3cad1;

    --text: #10161c;
    --muted: #55606b;
    --faint: #6b7680;

    --accent: #a97d12;
    --accent-quiet: rgb(232 184 75 / 26%);
    --accent-text: #7d5a08;
    --on-accent: #ffffff;

    /* The bands keep their hue, because a band that changed color with the theme would be two
    * scales for one set of numbers. Only the ink on them moves. */
    --p1: #c0342b;
    --on-p1: #ffffff;
    --p2: #e8b84b;
    --p3: #7ca6b8;
    --p4: #6b7680;
    --p1-quiet: rgb(192 52 43 / 11%);
    --p2-quiet: rgb(169 125 18 / 26%);
    --p3-quiet: rgb(52 99 122 / 22%);
    --p4-quiet: rgb(107 118 128 / 14%);

    --pass: #2e7d33;
    --fail: #c0342b;
    --on-pass: #ffffff;
    --on-fail: #ffffff;
    }
  }

  * { box-sizing: border-box; }

  /* Once, for everything. A rule that sets display outranks the hidden attribute's own
   * display:none, so any element given both is hidden in the markup and visible on screen. Fixing
   * it per rule fixes the one that was noticed; this fixes the ones that are not. */
  [hidden] { display: none !important; }

  body {
    font: 15px/1.55 "Space Grotesk", ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    margin: 0 auto;
    max-width: 64rem;
    padding: 2.25rem 1.25rem 4rem;
  }

  h1, h2, h3 { font-weight: 600; letter-spacing: -0.01em; }
  h1 { font-size: 1.05rem; margin: 0; }
  h2 { font-size: 1.05rem; margin: 2.25rem 0 .5rem; }
  h3.sub { font-size: .82rem; margin: 1.5rem 0 .4rem; color: var(--muted);
           text-transform: uppercase; letter-spacing: .12em; font-weight: 500; }

  code, .mono { font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  code { font-size: .86em; }
  a { color: inherit; }

  /* The verdict strip: what the run decided, what it was about, and the shape of what it found,
   * in one band at the top. Three separate things on three lines made a reader assemble the answer
   * from parts; the plane puts them together and so does this. */
  .strip {
    display: flex; flex-wrap: wrap; align-items: center; gap: .75rem 1.1rem;
    background: var(--surface);
    border: 1px solid var(--line);
    border-radius: var(--radius);
    padding: .85rem 1rem;
    margin: 0 0 1.25rem;
  }
  .mark { font-family: "JetBrains Mono", ui-monospace, monospace; font-size: .78rem;
          letter-spacing: .22em; color: var(--muted); text-transform: uppercase; }
  .verdict {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: .8rem; font-weight: 600; letter-spacing: .1em;
    padding: .2rem .6rem; border-radius: 4px; text-transform: uppercase;
  }
  .verdict.pass { background: var(--pass); color: var(--on-pass); }
  .verdict.fail { background: var(--fail); color: var(--on-fail); }
  .rel { color: var(--muted); font-size: .9rem; margin: 0; }
  /* How long the run took, beside what it decided. A fact about the run belongs with the run: in a
   * colophon it reads as a note about the document, and somebody asking whether a scan is worth
   * putting in a pull request has to hunt for the one number that answers them. */
  .took {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: .78rem; color: var(--faint); margin: 0;
  }
  .strip .spacer { flex: 1 1 auto; }

  /* Bands as chips carrying the ramp, rather than colored words. A count nobody can find is a
   * count nobody reads, and the ramp is the one thing a reader already knows how to read. */
  /* Three states rather than two, so a reader who chose one has a way back to following their
   * machine. Without it the first press is irreversible.
   *
   * In the nav rather than beside the verdict: everything in that strip is something the run
   * decided, and a control for how the page looks sitting among them reads as one more fact about
   * the scan. */
  /* All three at once, current one lit, so the options are visible and any of them is one press
   * away. A single cycling control hides both: a reader cannot see that a third state exists, and
   * reaching the far one takes two presses at something whose label has already changed.
   *
   * Drawn rather than named, because the names do not carry equally. A sun and a moon are read
   * without being learned; "Auto" means nothing until somebody has pressed it and watched what
   * happened. A circle half filled says half of each, which is what it does. */
  .themes { display: inline-flex; gap: .1rem; }
  .rung { display: inline-flex; align-items: center; padding: .35rem .5rem; }
  .rung svg { display: block; }

  .bands { display: flex; gap: .35rem; flex-wrap: wrap; }
  .band {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: .78rem; font-weight: 500;
    padding: .2rem .5rem; border-radius: 4px; white-space: nowrap;
  }
  .band.b1 { background: var(--p1); color: var(--on-p1); }
  .band.b2 { background: var(--p2); color: var(--on-p2); }
  .band.b3 { background: var(--p3); color: var(--on-p3); }
  .band.b4 { background: var(--p4); color: var(--on-p4); }
  .band.zero { background: transparent; color: var(--faint); border: 1px solid var(--line); }

  /* The report's own sections, as a tab row. Outlined pills read as filters, which is what the
   * controls below them are, and two different kinds of thing wearing one treatment is how a
   * reader learns to press the wrong one. A tab row is unbordered, sits on a rule, and is the
   * shape this product already uses for "where in here am I". */
  .tabs {
    display: flex; flex-wrap: wrap; align-items: center; gap: .15rem;
    margin: 0 0 1.75rem; padding-bottom: .3rem;
    border-bottom: 1px solid var(--line);
  }
  .tabs .spacer { flex: 1 1 auto; }
  .tab {
    padding: .35rem .75rem; white-space: nowrap; text-decoration: none;
    border: 0; border-radius: var(--radius); background: none;
    color: var(--muted); font: inherit; font-size: .86rem; font-weight: 500; cursor: pointer;
  }
  .tab:hover { color: var(--text); }
  .tab.err { color: var(--p1); }
  /* The section the reader is in, which for an anchored document is whichever they last followed.
   * :target is the browser's own answer and costs no script. */
  .tab:is(:target, .on) { background: var(--accent-quiet); color: var(--accent); font-weight: 600; }

  table { border-collapse: collapse; width: 100%; margin: .4rem 0 1.25rem; font-size: .88rem; }
  th, td { text-align: left; padding: .45rem .7rem; vertical-align: top; }
  thead th {
    font-size: .74rem; font-weight: 500; text-transform: uppercase; letter-spacing: .1em;
    color: var(--faint); border-bottom: 1px solid var(--line-strong); white-space: nowrap;
  }
  tbody td { border-bottom: 1px solid var(--line); }
  td.num, th.num { text-align: right; font-family: "JetBrains Mono", ui-monospace, monospace; }

  /* A finding is two rows: what it is, then what it says. The second carries the sentence somebody
   * reads, so it gets the body ink and the first stays quiet. */
  tr.meta td { border-bottom: 0; padding-bottom: .1rem; color: var(--muted); }
  tr.msg td { border-bottom: 1px solid var(--line); padding-top: 0; color: var(--text); }

  .pri { font-family: "JetBrains Mono", ui-monospace, monospace; font-weight: 600; }
  .pri.P1 { color: var(--p1); }
  .pri.P2 { color: var(--p2); }
  .pri.P3 { color: var(--p3); }
  .pri.P4 { color: var(--p4); }
  .sev-critical { color: var(--p1); font-weight: 600; }
  .sev-high { color: var(--p1); }
  .sev-medium { color: var(--p2); }
  .sev-low { color: var(--faint); }
  .err { color: var(--p1); font-weight: 600; }
  .ok { color: var(--pass); }

  /* Controls as rows rather than a grid of four number columns. The question is which control
   * failed and what it found, and a row answers it left to right; a table made a reader scan four
   * columns of mostly zeros to find the one that was not. A severity with nothing in it stays,
   * quiet, because "0 critical" is a result and an absent column is a gap. */
  ul.controls { list-style: none; padding: 0; margin: .4rem 0 1.25rem; }
  .ctl {
    display: flex; align-items: baseline; flex-wrap: wrap; gap: .5rem .9rem;
    padding: .55rem .8rem; border: 1px solid var(--line); border-radius: var(--radius);
    background: var(--surface); margin-bottom: .35rem;
  }
  .ctl.bad { border-color: var(--p1); }
  .ctl-name { font-weight: 600; min-width: 8rem; }
  /* The words the console prints, spelled the same way. text-transform would show the same thing
   * and leave the document saying something else: a screen reader reads the source, and so does
   * anybody who copies a line out of the page. */
  .ctl-verdict {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: .76rem; letter-spacing: .1em; min-width: 4rem;
  }
  .ctl-none { color: var(--faint); font-size: .84rem; font-style: italic; }
  .sevs { display: flex; gap: .35rem; flex-wrap: wrap; margin-left: auto; }
  .sev {
    font-family: "JetBrains Mono", ui-monospace, monospace; font-size: .74rem;
    padding: .1rem .45rem; border-radius: 3px; white-space: nowrap;
    border: 1px solid transparent;
  }
  .sev.s-critical { background: var(--p1); color: var(--on-p1); }
  .sev.s-high     { background: var(--p1); color: var(--on-p1); }
  .sev.s-medium   { background: var(--p2); color: var(--on-p2); }
  .sev.s-low      { background: var(--p4); color: var(--on-p4); }
  /* The bands wear the same chips, from the same ramp, because a control's counts and the strip
   * above them are now the same measurement and a second palette would say otherwise. */
  .sev.s-p1 { background: var(--p1); color: var(--on-p1); }
  .sev.s-p2 { background: var(--p2); color: var(--on-p2); }
  .sev.s-p3 { background: var(--p3); color: var(--on-p3); }
  .sev.s-p4 { background: var(--p4); color: var(--on-p4); }
  .sev.off { background: transparent; color: var(--faint); border-color: var(--line); }

  /* Components as a table, where the controls above them are rows: a reader compares components
   * against each other and a control against the gate, and comparing means a column to run down.
   * The same chips, because a component's bands and the strip in the header are one measurement. */
  table.components th[scope="row"] { font-weight: 600; white-space: nowrap; }
  table.components .sevs { display: inline-flex; margin-left: 0; vertical-align: middle; }
  table.components td:nth-child(3) {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: .76rem; letter-spacing: .1em; white-space: nowrap;
  }
  .cls { color: var(--muted); white-space: nowrap; }
  .none { color: var(--faint); font-style: italic; }
  /* The gap sits under the bands rather than beside them. A component can be partly scanned and
   * hold findings worth acting on, and either fact read alone is wrong. */
  .gap { display: block; margin-top: .25rem; color: var(--p1); font-size: .82rem; }
  tr.skipped th[scope="row"] { color: var(--muted); font-weight: 500; }

  /* What moved a band, beside the rating it moved. Muted: the row is already found by its band,
   * and the mark is the reason rather than the alarm. */
  .moved { color: var(--muted); font-size: .74rem; white-space: nowrap; }
  /* A date is one token. Wrapped across two lines it reads as two values. */
  .when { white-space: nowrap; }

  /* The descriptor field a rule was written in, beside what was written in it. Set apart because
   * they are different kinds of thing: one is our vocabulary and the other is theirs, and one
   * typeface for both leaves a reader working out which half to check. */
  .mk { color: var(--faint); font-size: .78rem; }
  .why { color: var(--muted); }
  .why::before { content: "· "; color: var(--faint); }

  /* Sections fold. Native disclosure rather than script, so a report opened from a file, an email
   * attachment or a viewer that strips scripts folds exactly the same way, and the keyboard and
   * screen-reader behavior is the browser's rather than ours to reimplement.
   *
   * Open on arrival, every one of them. A report is read once and kept; a section closed before
   * anybody asked is one a reader has to know to look for, and the fold is for putting away what
   * you have read rather than for deciding what somebody sees first. */
  .fold { margin: 0 0 1.4rem; }
  .fold > summary {
    cursor: pointer; list-style: none; display: flex; align-items: center; gap: .5rem;
    margin: 1.6rem 0 .7rem; border-radius: 4px;
  }
  .fold > summary::-webkit-details-marker { display: none; }
  /* The marker turns rather than swaps, so the control says which way the section will move. */
  .fold > summary::before {
    content: ""; flex: none; width: 0; height: 0; border-style: solid;
    border-width: .3rem 0 .3rem .42rem; border-color: transparent transparent transparent var(--faint);
    transition: transform .12s ease;
  }
  .fold[open] > summary::before { transform: rotate(90deg); }
  @media (prefers-reduced-motion: reduce) { .fold > summary::before { transition: none; } }
  .fold > summary:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
  .fold > summary .sec {
    font-size: 1.02rem; font-weight: 600; color: var(--text); letter-spacing: -.01em;
  }
  .fold.sub { margin: 0 0 1rem; }
  .fold.sub > summary { margin: 1.1rem 0 .5rem; }

  /* Printed reports carry everything. A folded section is a reading convenience and must not
   * decide what reaches an auditor's copy. */
  @media print {
    .fold > summary::before { display: none; }
    .fold > summary { cursor: default; }
    .rows .hint { display: none; }
  }
  /* A finding is a row in a panel, the shape the plane's lists use: chips in a fixed gutter, then
   * what it is, then a line of labeled context underneath. Columns were the wrong shape for this
   * content and no width answered it: a version pair runs to sixty-five characters, a rule id to
   * fifty, a location to forty, and seven columns of that in one reading column means something is
   * always cut. The thing that was always cut was the one column carrying an instruction. */
  .rows {
    border: 1px solid var(--line); border-radius: var(--radius);
    background: var(--surface-sunken); overflow: hidden; margin-top: 10px;
  }
  .rows > .f, .rows > .act {
    display: grid; grid-template-columns: 132px minmax(0, 1fr); gap: 16px; align-items: baseline;
    padding: 13px 8px; border-bottom: 1px solid var(--line);
  }
  /* Past the page, or narrowed away. One class for both, because either way the row is not shown
   * and the count line says how many were not. */
  .rows > .cut { display: none; }
  .rows > .opens, .rows > .act { cursor: pointer; }
  .rows > .opens:hover, .rows > .act:hover { background: var(--surface); }
  .rows .chips { display: flex; gap: 6px; align-items: baseline; }
  .rows .pri {
    display: inline-block; min-width: 30px; padding: 2px 0; border-radius: 2px; text-align: center;
    font: 600 11px "JetBrains Mono", ui-monospace, monospace;
  }
  .rows .pri.P1 { background: var(--p1-quiet); }
  .rows .pri.P2 { background: var(--p2-quiet); }
  .rows .pri.P3 { background: var(--p3-quiet); }
  .rows .pri.P4 { background: var(--p4-quiet); }
  /* Severity outlined and priority filled, so the two ratings never read as one: the band is the
   * decision, and the severity is one of the things it was decided from. */
  .rows .sevchip {
    padding: 2px 7px; border-radius: 2px; border: 1px solid var(--line-strong); white-space: nowrap;
    font: 400 11px "JetBrains Mono", ui-monospace, monospace; color: var(--text);
  }
  .rows .sevchip.sev-critical { border-color: var(--p1); }
  .rows .sevchip.sev-high { border-color: var(--p2); }
  .rows .sevchip.sev-medium { border-color: var(--p3); }
  .rows .sevchip.sev-low { border-color: var(--p4); }
  .rows .what { min-width: 0; overflow-wrap: anywhere; }
  .rows .rule { line-height: 1.45; }
  .rows .rule .id, .rows .rule .name {
    font: 500 15px "Space Grotesk", ui-sans-serif, system-ui, sans-serif; color: var(--text);
  }
  .rows .rule .id a { text-decoration: none; }
  .rows .rule .id a:hover { text-decoration: underline; }
  .rows .rule .said { font-size: 13px; color: var(--muted); }
  /* A row whose message was shortened opens to the whole of it. A disclosure rather than a dialog:
   * it needs no script, the search box already matches the whole message, printing opens it with
   * every other fold, and the rows around it stay where they were. Closed, it holds one line and
   * the message runs to an ellipsis; open, the full message takes the summary's place rather than
   * repeating it. */
  .rows summary.rule {
    display: flex; align-items: baseline; gap: 7px; min-width: 0;
    white-space: nowrap; list-style: none;
  }
  .rows summary.rule::-webkit-details-marker { display: none; }
  .rows summary.rule .id { flex: none; }
  .rows summary.rule .said { overflow: hidden; text-overflow: ellipsis; min-width: 0; }
  .rows details[open] > summary .said,
  .rows details[open] > summary .hint { display: none; }
  /* Says the row opens, on every row that does, without hovering: a touch screen has no hover, and
   * a report is often read by somebody who was sent it. Hidden from assistive technology, which
   * already announces the summary as a collapsed disclosure. */
  .rows .hint {
    flex: none; padding: .02rem .4rem; font-size: .7rem; white-space: nowrap; color: var(--muted);
    border: 1px solid var(--line-strong); border-radius: 999px;
  }
  .rows .opens:hover .hint { color: var(--text); border-color: var(--muted); }
  .rows .full { margin: .25rem 0 .1rem; line-height: 1.5; color: var(--text); }
  /* The context line. Labeled in the vocabulary the rest of the product uses, and small, because
   * it answers "where" after the row has already answered "what". */
  .rows .sub { margin-top: 3px; font-size: 12.5px; color: var(--muted); }
  .rows .lbl {
    font: 10px "JetBrains Mono", ui-monospace, monospace; letter-spacing: .08em;
    text-transform: uppercase; color: var(--faint);
  }
  .rows .faint { color: var(--faint); }
  /* What moved a band, first on the line, in the color of the direction it moved. */
  .rows .moved {
    display: inline-flex; align-items: center; gap: 3px; padding: 0 5px; margin-right: 6px;
    border: 1px solid var(--line); border-radius: 4px; font-size: 11.5px; color: var(--text);
    white-space: nowrap;
  }
  .rows .moved.up { border-color: var(--p1); }
  .rows .moved.up .g { color: var(--p1); font-weight: 700; }
  .rows .moved.down { border-color: var(--p3); }
  .rows .moved.down .g { color: var(--p3); }
  /* The count is the way into the rows behind it. A fix list that says "5 findings" and cannot
   * show which five asks a reader to take it on trust, and the five are already on the page. */
  .rows .act-clears {
    font: inherit; padding: 0; border: 0; background: none; color: var(--accent-text); cursor: pointer;
    text-decoration: underline; text-underline-offset: 2px;
  }

  /* The count line over a list and the page size beside it, then paging inside the panel's foot.
   * A report of a thousand findings drawn at once is a page nobody reaches the bottom of, and the
   * downloads and the sections below it went with the bottom. */
  .listbar { display: flex; align-items: center; justify-content: space-between; padding: 12px 2px 8px; }
  .lcount { font: 12px "JetBrains Mono", ui-monospace, monospace; color: var(--muted); }
  .sizes { display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--faint); }
  .size {
    padding: 4px 11px; border: 1px solid var(--line-strong); border-radius: 2px; background: none;
    color: var(--muted); font: 11px "JetBrains Mono", ui-monospace, monospace; cursor: pointer;
  }
  .size:hover { border-color: var(--accent); color: var(--text); }
  .size.on { border-color: transparent; background: var(--accent-quiet); color: var(--accent-text); font-weight: 600; }
  .next {
    display: block; width: 100%; padding: 12px 8px 4px; border: 0; background: none;
    color: var(--accent-text); font: inherit; font-size: 13px; font-weight: 500; text-align: left; cursor: pointer;
  }
  .next:hover { background: var(--surface); }
  .rest { margin: 0; padding: 0 8px 10px; font: 12px "JetBrains Mono", ui-monospace, monospace; color: var(--muted); }
  .nomatch { margin: 10px 0 0; padding: 30px 8px; color: var(--muted); border-bottom: 1px solid var(--line); }
  .nomatch b { display: block; font-weight: 500; color: var(--text); }
  .nomatch span { display: block; margin-top: 3px; font-size: 13px; }

  /* Two views of one set, and the toggle between them. The plane leads with the work and keeps the
   * list beside it, because a reader opening a report is deciding what to do rather than scanning
   * output. Hidden until scripts run: without them both sections render, each under its own
   * heading, which is a complete document rather than a dead control over half of one. The same
   * row picks one subsection at a time where a section holds several. */
  .views { display: flex; gap: .35rem; margin: 0 0 .9rem; }
  .views.panes { margin-top: .2rem; }
  .view {
    font: inherit; font-size: .86rem; padding: .35rem .8rem; cursor: pointer;
    border: 1px solid var(--line-strong); border-radius: 4px;
    background: var(--surface); color: var(--muted);
  }
  .view:hover { color: var(--text); border-color: var(--accent); }
  .view.on { background: var(--accent); border-color: var(--accent); color: var(--on-accent); font-weight: 600; }

  /* Sections as tabs, once the script has sorted the page into them. The verdict and the tab row
   * stay pinned while a long list scrolls under them, so the answer and the way to the rest of the
   * report are never more than a glance away. Without scripts the page is one document read top to
   * bottom, and a pinned header over it would cover every heading an anchor jumps to. */
  body.tabbed .pin {
    position: sticky; top: 0; z-index: 20; background: var(--bg);
    padding-top: .6rem; margin: -.6rem 0 1.5rem;
  }
  body.tabbed .pin .tabs { margin-bottom: 0; }
  body.tabbed [id] { scroll-margin-top: calc(var(--pin, 0px) + .75rem); }
  body.tabbed details.fold:not(.sub) > summary,
  body.tabbed .paned > details.fold.sub > summary { display: none; }
  .off { display: none !important; }

  .errors { border-left: 2px solid var(--p1); padding: .1rem 0 .1rem .9rem; margin: 0 0 1.5rem; list-style: none; }
  .errors li { margin: .25rem 0; }

  .note { color: var(--muted); font-size: .86rem; margin: .35rem 0 1rem; max-width: 46rem; }
  .empty, .just { color: var(--faint); font-style: italic; }

  code.cmd {
    background: var(--surface); border: 1px solid var(--line); border-radius: 4px;
    padding: .08rem .35rem; white-space: nowrap;
  }
  pre.cmd {
    background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius);
    padding: .6rem .8rem; overflow-x: auto; font-size: .84rem; margin: .4rem 0 1rem;
    font-family: "JetBrains Mono", ui-monospace, monospace;
  }

  /* Search and menus in one strip, the dashboard's, so a reader who has learned it there does not
   * learn it again here. Priority and fix lead because they decide what to do first; the rest fold
   * behind Narrow, which carries how many of them are narrowing while they are out of sight. */
  .bar { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; margin: 0 0 28px; }
  .bar:has(+ .tokens:not(:empty)) { margin-bottom: 12px; }
  .bar input[type=search] {
    flex: 1 1 auto; min-width: 0; min-height: var(--control-height); box-sizing: border-box; padding: 0 11px;
    font: 13px "JetBrains Mono", ui-monospace, monospace; color: var(--text); background: var(--surface);
    border: 1px solid var(--line-strong); border-radius: var(--radius);
  }
  .bar input[type=search]::placeholder { color: var(--faint); }
  .bar input[type=search]:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }

  /* A filter menu, a chip that opens a list of ticks rather than a one-of control: choosing P1 and
   * P2 asks for both, because that is what filtering over a set of values means. The chip carries
   * how many are ticked. A closed menu that is narrowing the list has to say so, or the list reads
   * as unfiltered. */
  .menu-anchor { position: relative; display: inline-flex; min-height: var(--control-height); }
  .menu-anchor.folded:not(.shown) { display: none; }
  .chip-menu, .narrow {
    display: inline-flex; align-items: center; min-height: var(--control-height); box-sizing: border-box;
    padding: 0 10px; border: 1px solid var(--line-strong); border-radius: 3px; background: none;
    color: var(--muted); font: inherit; font-size: 12.5px; cursor: pointer;
  }
  .chip-menu:hover { border-color: var(--accent); color: var(--text); }
  .chip-menu.on { color: var(--text); border-color: var(--accent); }
  .chip-menu:focus-visible, .narrow:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
  .chip-menu .c, .menu-row .c {
    font: 10.5px "JetBrains Mono", ui-monospace, monospace; color: var(--faint); margin-left: 5px;
  }
  .chip-menu .c::before { content: "· "; }
  .caret { color: var(--faint); margin-left: 4px; }
  .narrow { border-radius: var(--radius); background: var(--surface); color: var(--text); font-size: 12px; }
  .narrow.open { background: var(--accent); border-color: var(--accent); color: var(--on-accent); font-weight: 600; }

  .menu {
    position: absolute; top: calc(100% + 6px); left: 0; z-index: 40; min-width: 244px; padding: 6px;
    box-sizing: border-box; border: 1px solid var(--line-strong); border-radius: 4px;
    background: var(--surface); box-shadow: 0 8px 24px rgb(0 0 0 / 28%);
    display: flex; flex-direction: column; max-height: min(58vh, 460px);
  }
  /* Anchored to whichever edge keeps it on the page. The last chip in the strip sits near the
   * right margin, and a menu that opens off the edge is a menu whose counts nobody can read. */
  .menu.right { left: auto; right: 0; }
  .menu-head {
    padding: 4px 6px 6px; font-size: 10.5px; letter-spacing: .07em;
    text-transform: uppercase; color: var(--faint);
  }
  .menu-options { overflow-y: auto; min-height: 0; }
  .menu-row {
    display: flex; justify-content: space-between; gap: 16px;
    padding: 4px 6px; font-size: 13px; color: var(--text); cursor: pointer;
  }
  .menu-row:hover { background: var(--surface-sunken); }
  .menu-row > span:first-child { display: flex; align-items: baseline; white-space: nowrap; }
  .menu-row input { margin: 0 8px 0 0; }
  /* A value nothing here carries stays in the list and says zero. Which narrowings exist is part
   * of what the strip teaches, and removing the option answers a different question from the one
   * the reader asked. It is disabled rather than hidden, so nobody spends a click on it. */
  .menu-row:has(input:disabled) { color: var(--faint); cursor: default; }

  /* What is on, each beside what turns it off. A reader has to be able to see the state of the
   * list without opening a menu, and a filtered list nobody can tell is filtered is one somebody
   * reads as the whole set. */
  .tokens { display: flex; flex-wrap: wrap; gap: 6px; margin: 0 0 28px; }
  .tokens:empty { display: none; }
  .token {
    padding: 3px 8px; border-radius: 3px; border: 1px solid var(--accent); background: var(--surface-sunken);
    color: var(--text); font: inherit; font-size: 12.5px; cursor: pointer;
  }
  .token .x { color: var(--faint); margin-left: 6px; }
  .token:hover .x { color: var(--text); }
  .clear {
    display: inline-flex; align-items: center; gap: 5px; padding: 3px 9px; border-radius: var(--radius);
    border: 1px solid var(--line-strong); background: var(--surface); color: var(--text);
    font: inherit; font-size: 12.5px; cursor: pointer;
  }
  .clear:hover { border-color: var(--accent); background: var(--surface-sunken); }
  .clear .x { color: var(--faint); }

  /* The component the reader narrowed to, between the menus and the count. Above the list rather
   * than in it, because it describes the whole of what is below and nothing in the list says it. */
  .focus {
    display: flex; flex-wrap: wrap; align-items: baseline; gap: .4rem .7rem;
    padding: .5rem .75rem; margin: 0 0 .45rem;
    border: 1px solid var(--line); border-left: 3px solid var(--accent);
    border-radius: var(--radius); background: var(--surface);
  }
  .focus-name { font-weight: 600; }
  .focus-verdict { font-family: "JetBrains Mono", ui-monospace, monospace; font-size: .76rem; letter-spacing: .1em; }
  .focus-facts { color: var(--muted); font-size: .84rem; margin-left: auto; }

  .dl { display: flex; gap: .4rem; flex-wrap: wrap; align-items: center; margin: 0 0 1rem; }
  .dl a {
    display: inline-block; padding: .3rem .7rem; text-decoration: none; font-size: .84rem;
    border: 1px solid var(--line); border-radius: 4px; color: var(--muted);
  }
  .dl a:hover { color: var(--text); border-color: var(--line-strong); }

  .bar-track {
    display: inline-block; width: 8rem; height: .5rem; background: var(--line);
    border-radius: 3px; overflow: hidden; vertical-align: middle; margin-right: .45rem;
  }
  .bar-fill { display: block; height: 100%; background: var(--p3); }

  footer {
    color: var(--faint); font-size: .82rem; margin-top: 2.5rem;
    border-top: 1px solid var(--line); padding-top: .8rem;
  }

  :focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }

  @media print {
    body.tabbed .pin { position: static; }
    .off { display: revert !important; }
    body.tabbed details.fold:not(.sub) > summary,
    body.tabbed .paned > details.fold.sub > summary { display: revert; }
    #tools, .views, .listbar, .next, .rest, .dl { display: none !important; }
    .rows > .cut { display: grid; }
    body { max-width: none; background: #fff; color: #000; }
    tr { break-inside: avoid; }
    a::after { content: " (" attr(href) ")"; font-size: .8em; color: #444; }
  }
</style>
</head>
<body>
<div class="pin">
<header class="strip">
  <span class="mark">Draugr</span>
  <h1><span class="verdict {{if .Pass}}pass{{else}}fail{{end}}">{{.Verdict}}</span></h1>
  {{if .Release}}<p class="rel">{{.Release}}</p>{{end}}
  {{if .Duration}}<p class="took">{{.Duration}}{{if .CacheHits}} · {{.CacheHits}} from cache{{end}}</p>{{end}}
  <span class="spacer"></span>
  {{if .Prioritized}}<span class="bands">
    <span class="band {{if .P1}}b1{{else}}zero{{end}}">{{.P1}} P1</span>
    <span class="band {{if .P2}}b2{{else}}zero{{end}}">{{.P2}} P2</span>
    <span class="band {{if .P3}}b3{{else}}zero{{end}}">{{.P3}} P3</span>
    <span class="band {{if .P4}}b4{{else}}zero{{end}}">{{.P4}} P4</span>
  </span>{{end}}
</header>

<nav class="tabs" aria-label="Sections of this report">
  <a class="tab" href="#findings-h">Findings</a>
  {{if .Signals}}<a class="tab" href="#signals">Signals</a>{{end}}
  {{if .Controls}}<a class="tab" href="#controls">Controls</a>{{end}}
  {{if .Components}}<a class="tab" href="#components">Components</a>{{end}}
  {{if .Errors}}<a class="tab err" href="#errors">Errors</a>{{end}}
  {{if or .Suppressed .Decisions .Unmatched .Excluded}}<a class="tab" href="#suppressed">Accepted</a>{{end}}
  {{if or .Gate .SBOMCount .Slowest .Scanned .Provenance .Exploitability}}<a class="tab" href="#timing">Evidence</a>{{end}}
  <a class="tab" href="#about">About</a>
  <span class="spacer"></span>
  <span class="themes" id="themes" hidden role="group" aria-label="Color theme">
    <button type="button" class="tab rung" data-theme="system" title="Follow this machine" aria-label="Follow this machine">
      <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true" focusable="false">
        <circle cx="8" cy="8" r="5.8" fill="none" stroke="currentColor" stroke-width="1.3"/>
        <path fill="currentColor" d="M8 2.2a5.8 5.8 0 0 0 0 11.6z"/>
      </svg>
    </button>
    <button type="button" class="tab rung" data-theme="light" title="Light, and the one to print" aria-label="Light, and the one to print">
      <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true" focusable="false">
        <circle cx="8" cy="8" r="3.1" fill="currentColor"/>
        <path fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"
              d="M8 1.3v1.6M8 13.1v1.6M1.3 8h1.6M13.1 8h1.6M3.3 3.3l1.1 1.1M11.6 11.6l1.1 1.1M12.7 3.3l-1.1 1.1M4.4 11.6l-1.1 1.1"/>
      </svg>
    </button>
    <button type="button" class="tab rung" data-theme="dark" title="Dark" aria-label="Dark">
      <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true" focusable="false">
        <path fill="currentColor" d="M13.4 10.1A5.9 5.9 0 0 1 5.9 2.6a5.9 5.9 0 1 0 7.5 7.5z"/>
      </svg>
    </button>
  </span>
</nav>
</div>

{{if .Prioritized}}
<p class="note">Priority combines how severe a finding is with how exposed and how business-critical
the component is, so the same issue ranks differently on a public API than on an internal tool.
<strong>P1</strong> is act now, <strong>P4</strong> is track it.</p>
{{end}}

{{if .Signals}}
<details class="fold" open><summary id="signals"><span class="sec">Signals</span></summary>
<p class="note">What argued with this run's ranking, and how many findings each one moved.</p>
<table class="provenance">
<thead><tr><th scope="col">Signal</th><th scope="col">Effect</th></tr></thead>
{{range .Signals}}<tr><td><code>{{.Name}}</code></td><td>{{.Effect}}</td></tr>{{end}}
</table>
</details>
{{end}}
{{if .Controls}}
<details class="fold" open><summary id="controls"><span class="sec">Controls</span></summary>
<ul class="controls">
{{range .Controls}}<li class="ctl{{if .Errored}} bad{{end}}">
  <span class="ctl-name">{{.Control}}</span>
  <span class="ctl-verdict">{{if .Errored}}<span class="err">ERROR</span>{{else if .Fail}}<span class="err">FAIL</span>{{else}}<span class="ok">pass</span>{{end}}</span>
  {{if .NoReport}}<span class="ctl-none">nothing to report, this control did not run</span>
  {{else if .Prioritized}}<span class="sevs">
    <span class="sev s-p1{{if not .P1}} off{{end}}">{{.P1}} P1</span>
    <span class="sev s-p2{{if not .P2}} off{{end}}">{{.P2}} P2</span>
    <span class="sev s-p3{{if not .P3}} off{{end}}">{{.P3}} P3</span>
    <span class="sev s-p4{{if not .P4}} off{{end}}">{{.P4}} P4</span>
  </span>
  {{else}}<span class="sevs">
    <span class="sev s-critical{{if not .Critical}} off{{end}}">{{.Critical}} critical</span>
    <span class="sev s-high{{if not .High}} off{{end}}">{{.High}} high</span>
    <span class="sev s-medium{{if not .Medium}} off{{end}}">{{.Medium}} medium</span>
    <span class="sev s-low{{if not .Low}} off{{end}}">{{.Low}} low</span>
  </span>{{end}}
</li>{{end}}
</ul>
</details>
{{end}}
{{if .Components}}
<details class="fold" open><summary id="components"><span class="sec">Components</span></summary>
<p class="note">The verdict for each part of the application on its own findings, under the same gate
as the run.</p>
<table class="components">
<thead><tr>
  <th scope="col">Component</th>
  <th scope="col">Declared</th>
  <th scope="col">Verdict</th>
  <th scope="col">{{if .Prioritized}}Priority{{else}}Findings{{end}}</th>
</tr></thead>
<tbody>
{{range .Components}}<tr{{if .Skipped}} class="skipped"{{end}}>
  <th scope="row">{{.Name}}</th>
  <td class="cls">{{if .Class}}{{.Class}}{{else}}<span class="none">not declared</span>{{end}}</td>
  <td>{{if .Skipped}}<span class="none">not scanned</span>{{else if .Errored}}<span class="err">ERROR</span>{{else if .Fail}}<span class="err">FAIL</span>{{else}}<span class="ok">PASS</span>{{end}}</td>
  <td>
    {{if .Skipped}}
    {{else if and .Prioritized .Findings}}<span class="sevs">
      <span class="sev s-p1{{if not .P1}} off{{end}}">{{.P1}} P1</span>
      <span class="sev s-p2{{if not .P2}} off{{end}}">{{.P2}} P2</span>
      <span class="sev s-p3{{if not .P3}} off{{end}}">{{.P3}} P3</span>
      <span class="sev s-p4{{if not .P4}} off{{end}}">{{.P4}} P4</span>
    </span>
    {{else if .Findings}}{{plural .Findings "finding"}}
    {{else if not .Errored}}<span class="none">no findings</span>{{end}}
    {{if .Unscanned}}<span class="gap">{{.Unscanned}}</span>{{end}}
  </td>
</tr>{{end}}
</tbody>
</table>
{{if .Unattributed}}<p class="note">{{plural .Unattributed "finding"}} not tied to a component
(project-wide controls).</p>{{end}}
</details>
{{end}}

{{if .Errors}}
<h3 id="errors" class="err">Controls that could not run</h3>
<p class="note">These checks were requested and did not complete, so this report says nothing
about what they would have found. For everything the tool printed, re-run with
<code class="cmd">--log-level trace</code>.</p>
<pre class="cmd">draugr scan &lt;saga.yaml&gt; --log-level trace</pre>
<ul class="errors">
{{range .Errors}}<li><strong>{{.Control}}</strong> · {{.Message}}</li>{{end}}
</ul>
{{end}}

<details class="fold" open><summary id="findings-h"><span class="sec">Findings{{if .MinPriority}} · {{.MinPriority}} and above{{end}}</span></summary>

{{if .Actions}}
<div class="views" id="views" hidden>
  <button type="button" class="view on" data-view="work">What to do</button>
  <button type="button" class="view" data-view="all">All findings</button>
</div>
{{end}}

{{if .Findings}}
<div id="tools" hidden>
  <div class="bar">
    <input type="search" id="q" placeholder="Find a rule, a package, a file or a message" aria-label="Find a finding">
    {{template "menu" dict "K" "p" "Label" "Priority" "Options" .Priorities}}
    {{template "menu" dict "K" "fix" "Label" "Fix" "Options" .Fixes}}
    <button type="button" class="narrow" id="narrow" aria-expanded="false">Narrow ▾</button>
    {{template "menu" dict "K" "s" "Label" "Severity" "Options" .Severities "Folded" true}}
    {{template "menu" dict "K" "m" "Label" "Component" "Options" .ComponentNames "Folded" true}}
    {{template "menu" dict "K" "c" "Label" "Control" "Options" .ControlNames "Folded" true}}
    {{template "menu" dict "K" "sc" "Label" "Scanner" "Options" .Scanners "Folded" true}}
  </div>
  <div class="tokens" id="tokens"></div>
  {{range .Components}}{{if not .Skipped}}
  <div class="focus" data-m="{{.Name}}" hidden>
    <span class="focus-name">{{.Name}}</span>
    {{if .Class}}<span class="cls">{{.Class}}</span>{{end}}
    <span class="focus-verdict">{{if .Errored}}<span class="err">ERROR</span>{{else if .Fail}}<span class="err">FAIL</span>{{else}}<span class="ok">PASS</span>{{end}}</span>
    {{if and .Prioritized .Findings}}<span class="sevs">
      <span class="sev s-p1{{if not .P1}} off{{end}}">{{.P1}} P1</span>
      <span class="sev s-p2{{if not .P2}} off{{end}}">{{.P2}} P2</span>
      <span class="sev s-p3{{if not .P3}} off{{end}}">{{.P3}} P3</span>
      <span class="sev s-p4{{if not .P4}} off{{end}}">{{.P4}} P4</span>
    </span>{{end}}
    <span class="focus-facts">
      {{/* The count only where the bands are not shown. With them it is their sum, and the line
           under this one already says how many the filter left. */}}
      {{if not (and .Prioritized .Findings)}}{{plural .Findings "finding"}}{{if or .Failed .Unscanned}} · {{end}}{{end}}
      {{- if .Failed}}failing {{join .Failed}}{{if .Unscanned}} · {{end}}{{end}}
      {{- if .Unscanned}}{{.Unscanned}}{{end}}
    </span>
  </div>
  {{end}}{{end}}
</div>
{{end}}

{{if .Actions}}
<section id="work">
  <h3 class="sub js-off">What to do</h3>
  <p class="note">One row per thing to do rather than per finding.</p>
  {{template "listbar"}}
  <div class="rows" id="acts">
  {{range .Actions}}<div class="act" data-a="{{.Key}}" data-title="{{.Title}}">
    <span class="chips"><span class="pri {{.Priority}}">{{.Priority}}</span></span>
    <div class="what">
      <div class="rule"><span class="name">{{.Title}}</span></div>
      <div class="sub"><span class="lbl">control</span> {{.Control}}<span class="faint"> · </span><button type="button" class="act-clears" data-a="{{.Key}}" data-title="{{.Title}}">{{plural .Clears "finding"}}</button>{{if .Upstream}}<span class="faint"> · </span>upstream{{end}}{{if .Cached}}<span class="faint"> · </span>from cache{{end}}{{if .Where}}<span class="faint"> · </span>{{.Where}}{{end}}</div>
    </div>
  </div>{{end}}
  {{template "paging"}}
  </div>
  {{template "nomatch"}}
  {{if .External}}<p class="note">{{plural .External "finding"}} are somebody else's to fix, so they are
  reported rather than listed as work.</p>{{end}}
</section>
{{end}}

<section id="all">
<h3 class="sub js-off">All findings</h3>
{{if .MinPriority}}<p class="note">{{if .Hidden}}{{plural .Hidden "lower-priority finding"}} are not listed, and the counts still describe the whole run{{else}}The counts describe the whole run{{end}}.</p>{{end}}

{{if .Findings}}
{{template "listbar"}}
<div class="rows" id="findings">
{{range .Findings}}<div class="f" data-p="{{.Priority}}" data-s="{{.Severity}}" data-c="{{.Control}}" data-m="{{.Component}}" data-fix="{{.FixKind}}" data-sc="{{.Tool}}" data-a="{{.ActionKey}}" data-q="{{.Search}}">
  <span class="chips"><span class="pri {{.Priority}}">{{.Priority}}</span><span class="sevchip {{.SevClass}}">{{.Severity}}</span></span>
  <div class="what">
    {{if .Full}}<details class="more"><summary class="rule">{{template "rule" .}}<span class="hint" aria-hidden="true">more</span></summary><p class="full">{{.Full}}</p></details>
    {{- else}}<div class="rule">{{template "rule" .}}</div>{{end}}
    <div class="sub">{{if .MovedLabel}}<span class="moved {{.MovedDir}}"><span class="g">{{.MovedGlyph}}</span>{{.MovedLabel}}</span>{{end}}{{if .Component}}<span class="lbl">component</span> {{.Component}}<span class="faint"> · </span>{{end}}{{if .Location}}{{.Location}}<span class="faint"> · </span>{{end}}<span class="lbl">scanner</span> {{.Tool}}<span class="faint"> · </span><span class="lbl">fix</span> {{.Fix}}</div>
  </div>
</div>{{end}}
{{template "paging"}}
</div>
{{template "nomatch"}}
{{else if .Errors}}
<p>No findings from the controls that ran. See the errors reported above.</p>
{{else}}
<p>No findings. ✓</p>
{{end}}

<p class="dl">
  {{if .SARIFHref}}<a href="{{.SARIFHref}}" download="results.sarif">⬇ SARIF</a>{{end}}
  {{if .TSVHref}}<a href="{{.TSVHref}}" download="findings.tsv">⬇ TSV</a>{{end}}
  {{if .SARIFTooBig}}<span class="note">SARIF too large to embed · re-run with <code class="cmd">-o &lt;dir&gt;</code>.</span>{{end}}
</p>
</section>
</details>

{{define "rule"}}<span class="id">{{if .HelpURI}}<a href="{{.HelpURI}}">{{.RuleID}}</a>{{else}}{{.RuleID}}{{end}}</span>{{if .Message}}<span class="said"><span class="faint"> · </span>{{.Message}}</span>{{end}}{{end}}
{{define "menu"}}
<span class="menu-anchor{{if .Folded}} folded{{end}}" data-k="{{.K}}">
  <button class="chip-menu" type="button" aria-expanded="false" aria-haspopup="true">
    {{.Label}}<span class="c" hidden></span><span class="caret" aria-hidden="true">&#9662;</span>
  </button>
  <div class="menu" hidden role="group" aria-label="{{.Label}}">
    <div class="menu-head">{{.Label}}</div>
    <div class="menu-options">
      {{range .Options}}
      <label class="menu-row">
        <span><input type="checkbox" data-k="{{$.K}}" value="{{.Value}}"{{if not .Count}} disabled{{end}}>{{.Value}}</span>
        <span class="c">{{.Count}}</span>
      </label>
      {{end}}
    </div>
  </div>
</span>
{{end}}
{{define "listbar"}}<div class="listbar" hidden>
  <span class="lcount"></span>
  <span class="sizes">Show <button type="button" class="size" data-n="25">25</button><button type="button" class="size" data-n="50">50</button><button type="button" class="size" data-n="100">100</button></span>
</div>{{end}}
{{define "paging"}}<button type="button" class="next" hidden></button><p class="rest" hidden></p>{{end}}
{{define "nomatch"}}<p class="nomatch" hidden><b>Nothing here matches.</b><span>Take a narrowing off to widen it.</span></p>{{end}}

{{if or .Suppressed .Imported .Silenced .Decisions .Unmatched .Excluded}}
<details class="fold" open><summary id="suppressed"><span class="sec">Accepted</span></summary>
<p class="note">
{{- if .Suppressed}}<code class="cmd">config.exclude</code>: {{plural .Suppressed "finding"}} suppressed. {{end -}}
{{- if .Imported}}VEX: {{plural .Imported "finding"}} excused. {{end -}}
{{- if .Silenced}}Scanner exclusions: {{plural .Silenced "finding"}} suppressed. {{end -}}
{{- if not (or .Suppressed .Imported .Silenced)}}Set aside by <code class="cmd">config.exclude</code>.{{end -}}
</p>
{{if .Decisions}}
<details class="fold sub" open><summary class="sub"><span class="sub">Decisions</span></summary>
<table class="provenance">
<thead><tr><th scope="col" class="num">Findings</th><th scope="col">Accepted by</th><th scope="col">Expires</th><th scope="col">Reason</th></tr></thead>
{{range .Decisions}}<tr>
  <td class="num">{{.N}}</td>
  <td>{{if .Unattributed}}<span class="err">unattributed</span>{{else}}{{.By}}{{end}}</td>
  <td class="when">{{if .Expires}}{{.Expires}}{{else}}<span class="faint">never</span>{{end}}</td>
  <td>{{.Reason}}</td>
</tr>{{end}}
</table>
</details>
{{end}}

{{if .Unmatched}}
<details class="fold sub" open><summary class="sub"><span class="sub">Unmatched</span></summary>
<p class="note">These rules suppressed nothing.</p>
<table class="provenance">
<thead><tr><th scope="col">Source</th><th scope="col">Rule</th></tr></thead>
{{range .Unmatched}}<tr>
  <td><code>{{.Source}}</code></td>
  <td>{{range .Matchers}}<span class="mk">{{.Key}}</span> <code>{{.Value}}</code> {{end}}{{if .Reason}}<span class="why">{{.Reason}}</span>{{end}}</td>
</tr>{{end}}
</table>
</details>
{{end}}

{{if .Excluded}}
<details class="fold sub" open><summary class="sub"><span class="sub">Findings</span></summary>
<table>
<thead><tr><th scope="col">Severity</th><th scope="col">Rule</th><th scope="col">Control</th><th scope="col">Component</th><th scope="col">Location</th><th scope="col">Accepted via</th></tr></thead>
{{range .Excluded}}<tbody>
<tr class="meta">
  <td class="{{.SevClass}}">{{.Severity}}</td>
  <td><code>{{if .HelpURI}}<a href="{{.HelpURI}}">{{.RuleID}}</a>{{else}}{{.RuleID}}{{end}}</code></td>
  <td>{{.Control}}</td>
  <td>{{.Component}}</td>
  <td><code>{{.Location}}</code></td>
  <td>{{.AcceptedVia}}</td>
</tr>
<tr class="msg"><td colspan="6">{{.Message}}<br><span class="just">Reason: {{.Justification}}</span></td></tr>
</tbody>{{end}}
</table>
</details>
{{end}}
</details>
{{end}}

{{if or .Gate .SBOMCount .Slowest .Scanned .Provenance .Exploitability}}
<details class="fold" open><summary id="timing"><span class="sec">Evidence</span></summary>
<p class="note">What stands behind the verdict rather than what it found.</p>

{{if or .Gate .SBOMCount}}
<table class="provenance">
<tbody>
{{if .Gate}}<tr><td><span class="mk">gate</span></td><td>{{.Gate}}</td></tr>{{end}}
{{if .SBOMCount}}<tr><td><span class="mk">sbom</span></td><td>{{.SBOMCount}} document(s) ({{.SBOMFormat}})</td></tr>{{end}}
</tbody>
</table>
{{end}}

{{if .Scanned}}
<details class="fold sub" open><summary class="sub"><span class="sub">Scanned</span></summary>
<table class="provenance">
<thead><tr><th scope="col">Repository</th><th scope="col">Revision</th><th scope="col">Not included</th></tr></thead>
<tbody>
{{range .Scanned}}<tr>
  <td>{{.Name}}{{if .Local}} <span class="ctl-none">local checkout, no remote</span>{{end}}</td>
  <td><code>{{.Revision}}</code></td>
  <td>{{if .Uncommitted}}{{.Uncommitted}} uncommitted{{else}}&mdash;{{end}}</td>
</tr>{{end}}
</tbody>
</table>
</details>
{{end}}

{{if .Provenance}}
<details class="fold sub" open><summary class="sub"><span class="sub">Measured against</span></summary>
<table class="provenance">
<thead><tr><th scope="col">Control</th><th scope="col">Scanner</th><th scope="col">Run</th></tr></thead>
<tbody>
{{range .Provenance}}<tr><td>{{.Control}}</td><td>{{.Label}}</td><td>{{.Detail}}</td></tr>{{end}}
</tbody>
</table>
</details>
{{end}}

{{if .Exploitability}}
<details class="fold sub" open><summary class="sub"><span class="sub">Exploitability data</span></summary>
<table class="provenance">
<thead><tr><th scope="col">Feed</th><th scope="col">Obtained</th><th scope="col">Digest</th></tr></thead>
<tbody>
{{range .Exploitability}}<tr><td>{{.Name}}</td><td>{{.Obtained}}</td><td>{{.Digest}}</td></tr>{{end}}
</tbody>
</table>
</details>
{{end}}


{{if .Slowest}}
<details class="fold sub" open><summary class="sub"><span class="sub">Timing</span></summary>
<p class="note">Time spent per control, worst first.</p>
<table>
<thead><tr><th scope="col">Control</th><th scope="col" class="num">Time</th><th scope="col">Share of scanner time</th></tr></thead>
<tbody>
{{range .Slowest}}<tr>
  <td>{{.Control}}</td>
  <td class="num">{{.Duration}}</td>
  <td><span class="bar-track"><span class="bar-fill" style="width:{{.Pct}}%"></span></span> {{.Pct}}%</td>
</tr>{{end}}
</tbody>
</table>
</details>
{{end}}
</details>
{{end}}

<footer id="about">
  Generated by <strong>Draugr</strong>{{if .Version}} {{.Version}}{{end}}{{if .Generated}} · {{.Generated}}{{end}}.
  <br>A passing verdict means the controls you configured found nothing they were looking for; it is not a guarantee of security.
</footer>
<script>
// Progressive enhancement, and deliberately so: everything above renders complete without this.
// The toolbar starts hidden and is revealed here, so a reader with scripts disabled, or an email
// client or artifact viewer that strips them, sees the full table rather than dead controls that
// do nothing.
(function () {
  // A folded section still prints. A browser does not render a closed disclosure's content, so a
  // reader who put a section away and then printed would hand somebody a report missing it, which
  // is the one thing a fold must never decide. Reopened before the dialog and restored after, so
  // the screen looks the way they left it.
  var reopened = [];
  window.addEventListener("beforeprint", function () {
    reopened = [];
    document.querySelectorAll("details:not([open])").forEach(function (el) {
      reopened.push(el);
      el.open = true;
    });
  });
  window.addEventListener("afterprint", function () {
    reopened.forEach(function (el) { el.open = false; });
    reopened = [];
  });

  // The theme chooser, first and on its own: it is the one control that is worth having even when
  // there is nothing to filter, and a report with no findings still gets printed.
  var themeBox = document.getElementById("themes");
  if (themeBox) {
    var rungs = Array.prototype.slice.call(themeBox.querySelectorAll(".rung"));
    var read = function () {
      try { return localStorage.getItem("draugr-report-theme") || "system"; } catch (e) { return "system"; }
    };
    var applyTheme = function (name) {
      if (name === "system") delete document.documentElement.dataset.theme;
      else document.documentElement.dataset.theme = name;
      rungs.forEach(function (r) {
        var on = r.dataset.theme === name;
        r.classList.toggle("on", on);
        r.setAttribute("aria-pressed", String(on));
      });
      // A file:// document may have no storage at all, and a choice that lasts the session beats
      // refusing to make one.
      try {
        if (name === "system") localStorage.removeItem("draugr-report-theme");
        else localStorage.setItem("draugr-report-theme", name);
      } catch (e) { /* the choice lasts as long as the page does */ }
    };
    themeBox.hidden = false;
    applyTheme(read());
    rungs.forEach(function (r) {
      r.addEventListener("click", function () { applyTheme(r.dataset.theme); });
    });
  }

  // Sections as tabs. Every element after the pinned row belongs to the section whose heading it
  // follows, and one section shows at a time; the headings go, because the tab row names them. A
  // section holding several subsections shows one of those at a time too, under a second row.
  // Before the findings, because a report with none still has sections to move between.
  var pin = document.querySelector(".pin");
  var nav = pin && pin.querySelector("nav.tabs");
  if (pin && nav) {
    var tabs = Array.prototype.slice.call(nav.querySelectorAll("a.tab"));
    var ids = tabs.map(function (t) { return t.getAttribute("href").slice(1); });
    // What the pinned row covers, measured, so an anchor lands below it rather than under it.
    var measure = function () {
      document.documentElement.style.setProperty("--pin", pin.offsetHeight + "px");
    };
    if (window.ResizeObserver) new ResizeObserver(measure).observe(pin);
    measure();
    document.body.classList.add("tabbed");

    var pane = {}, current = ids[0];
    ids.forEach(function (id) { pane[id] = []; });
    for (var node = pin.nextElementSibling; node; node = node.nextElementSibling) {
      if (node.tagName === "SCRIPT") continue;
      var head = node.matches("details.fold:not(.sub)") && node.querySelector(":scope > summary[id]");
      if (head && pane[head.id]) current = head.id;
      if (node.id && pane[node.id]) current = node.id;
      // A heading that is hidden cannot be pressed to open its section again.
      if (node.matches("details.fold")) node.open = true;
      pane[current].push(node);
    }

    var subOf = {};
    Array.prototype.forEach.call(document.querySelectorAll("details.fold:not(.sub)"), function (top) {
      var subs = Array.prototype.slice.call(top.querySelectorAll(":scope > details.fold.sub"));
      if (subs.length < 2) return;
      var parent = top.querySelector(":scope > summary").id;
      var row = document.createElement("div");
      row.className = "views panes";
      subs.forEach(function (sub) {
        var sum = sub.querySelector(":scope > summary");
        var name = sum.textContent.trim();
        var id = parent + "-" + name.toLowerCase().replace(/[^a-z0-9]+/g, "-");
        sum.id = id;
        sub.open = true;
        var b = document.createElement("button");
        b.type = "button";
        b.className = "view";
        b.textContent = name;
        b.dataset.sub = id;
        b.addEventListener("click", function () { history.pushState(null, "", "#" + id); route(); });
        row.appendChild(b);
        subOf[id] = { top: parent, el: sub, row: row, subs: subs };
      });
      top.classList.add("paned");
      top.insertBefore(row, subs[0]);
    });

    var showSub = function (id) {
      var s = subOf[id];
      s.subs.forEach(function (x) { x.classList.toggle("off", x !== s.el); });
      Array.prototype.forEach.call(s.row.children, function (b) {
        b.classList.toggle("on", b.dataset.sub === id);
        b.setAttribute("aria-pressed", String(b.dataset.sub === id));
      });
    };
    // A second row with nothing chosen shows its first subsection rather than none of them.
    var firstSubs = function () {
      var seen = {};
      Object.keys(subOf).forEach(function (id) {
        var top = subOf[id].top;
        if (seen[top]) return;
        seen[top] = true;
        if (!subOf[id].row.querySelector(".on")) showSub(id);
      });
    };
    var showPane = function (id) {
      ids.forEach(function (k) {
        pane[k].forEach(function (n) { n.classList.toggle("off", k !== id); });
      });
      tabs.forEach(function (t) {
        var on = t.getAttribute("href") === "#" + id;
        t.classList.toggle("on", on);
        if (on) t.setAttribute("aria-current", "true"); else t.removeAttribute("aria-current");
      });
      firstSubs();
    };
    // The address says which section is open, so a link to one opens it and Back returns.
    var route = function () {
      var h = decodeURIComponent(location.hash.slice(1));
      var target = h && document.getElementById(h);
      if (!target || pane[h]) { showPane(target ? h : ids[0]); window.scrollTo(0, 0); return; }
      if (subOf[h]) { showPane(subOf[h].top); showSub(h); window.scrollTo(0, 0); return; }
      var owner = ids.filter(function (k) {
        return pane[k].some(function (n) { return n.contains(target); });
      })[0];
      if (owner) showPane(owner);
      Object.keys(subOf).forEach(function (k) { if (subOf[k].el.contains(target)) showSub(k); });
      target.scrollIntoView();
    };
    window.addEventListener("hashchange", route);
    window.addEventListener("popstate", route);
    route();
  }

  var tools = document.getElementById("tools");
  var list = document.getElementById("findings");
  if (!tools || !list) return;
  tools.hidden = false;

  var rows = Array.prototype.map.call(list.querySelectorAll(":scope > .f"), function (el) {
    return { el: el, d: el.dataset, ok: true };
  });

  // The whole row opens its message, not only the line the disclosure owns. A link inside the row
  // keeps its own meaning, the summary toggles itself natively, and a click that ends a text
  // selection is somebody copying a path rather than asking for more.
  rows.forEach(function (r) {
    var more = r.el.querySelector("details.more");
    if (!more) return;
    r.el.classList.add("opens");
    r.el.addEventListener("click", function (e) {
      if (e.target.closest("a, summary")) return;
      if (String(window.getSelection && window.getSelection()) !== "") return;
      more.open = !more.open;
    });
  });

  // Ticks within one menu add up, and the menus narrow each other. Choosing P1 and P2 asks for
  // both rather than replacing one with the other; across menus it is an and, because each
  // answers a different question. Nothing ticked in a menu is no constraint from that menu.
  var dims = Array.prototype.map.call(tools.querySelectorAll(".menu-anchor"), function (a) {
    var boxes = Array.prototype.slice.call(a.querySelectorAll("input[type=checkbox]"));
    return {
      k: a.dataset.k, anchor: a, folded: a.classList.contains("folded"),
      button: a.querySelector(".chip-menu"), menu: a.querySelector(".menu"),
      badge: a.querySelector(".chip-menu .c"), boxes: boxes,
    };
  });
  var q = document.getElementById("q");
  var narrow = document.getElementById("narrow");
  var tokenBox = document.getElementById("tokens");
  var strips = Array.prototype.slice.call(tools.querySelectorAll(".focus"));

  // A narrowing set by following an action rather than by a menu. Held apart from the menus
  // because it is not a dimension somebody browses: it is one row of the fix list, and the way
  // out of it is the token it leaves in the row above.
  var state = { q: "", act: "", actTitle: "", open: false, cap: {}, size: 50 };
  try { state.size = Number(localStorage.getItem("draugr-report-page-size")) || 50; } catch (e) { /* the default */ }

  function ticked(d) {
    return d.boxes.filter(function (b) { return b.checked; }).map(function (b) { return b.value; });
  }
  function passes(r, skip) {
    for (var i = 0; i < dims.length; i++) {
      var d = dims[i];
      if (d.k === skip) continue;
      var on = ticked(d);
      if (on.length && on.indexOf(r.d[d.k]) < 0) return false;
    }
    return true;
  }
  function searched(r) { return !state.q || r.d.q.indexOf(state.q) >= 0; }
  function inAction(r) { return !state.act || r.d.a === state.act; }
  function narrowed() {
    return state.q || state.act || dims.some(function (d) { return ticked(d).length; });
  }

  function closeMenus() {
    dims.forEach(function (d) {
      d.menu.hidden = true;
      d.button.setAttribute("aria-expanded", "false");
    });
  }
  dims.forEach(function (d) {
    d.button.addEventListener("click", function (e) {
      e.stopPropagation();
      var wasOpen = !d.menu.hidden;
      closeMenus();
      if (wasOpen) return;
      d.menu.hidden = false;
      d.button.setAttribute("aria-expanded", "true");
      // Measured rather than assumed: which chips sit near the right margin depends on how the
      // strip wrapped, which depends on the window.
      d.menu.classList.remove("right");
      if (d.menu.getBoundingClientRect().right > document.documentElement.clientWidth - 8) {
        d.menu.classList.add("right");
      }
      var first = d.menu.querySelector("input:not([disabled])");
      if (first) first.focus();
    });
    d.menu.addEventListener("click", function (e) { e.stopPropagation(); });
    d.boxes.forEach(function (b) { b.addEventListener("change", reset); });
  });
  // One menu at a time, and the page takes the click that closes it.
  document.addEventListener("click", closeMenus);
  document.addEventListener("keydown", function (e) { if (e.key === "Escape") closeMenus(); });
  narrow.addEventListener("click", function () { state.open = !state.open; render(); });
  q.addEventListener("input", function () { state.q = q.value.trim().toLowerCase(); reset(); });

  // Two views of one set. What to do leads and the list sits behind the toggle; the headings that
  // separate them without scripts go, because the toggle names them.
  var views = document.getElementById("views");
  var work = document.getElementById("work");
  var all = document.getElementById("all");
  function showView(which) {
    if (!views) return;
    work.classList.toggle("off", which !== "work");
    all.classList.toggle("off", which !== "all");
    Array.prototype.forEach.call(views.querySelectorAll(".view"), function (b) {
      b.classList.toggle("on", b.dataset.view === which);
      b.setAttribute("aria-pressed", String(b.dataset.view === which));
    });
  }
  if (views && work) {
    views.hidden = false;
    Array.prototype.forEach.call(document.querySelectorAll(".js-off"), function (h) { h.classList.add("off"); });
    Array.prototype.forEach.call(views.querySelectorAll(".view"), function (b) {
      b.addEventListener("click", function () { showView(b.dataset.view); });
    });
    showView("work");
  }

  // One row per action, and a row is the way into the findings it clears. Following it opens the
  // list already narrowed to them; the token it leaves is how a reader gets back.
  var byAct = {};
  rows.forEach(function (r) { (byAct[r.d.a] = byAct[r.d.a] || []).push(r); });
  var acts = Array.prototype.map.call(document.querySelectorAll("#acts > .act"), function (el) {
    var a = {
      el: el, key: el.dataset.a, label: el.dataset.title || "", ok: true,
      count: el.querySelector(".act-clears"),
    };
    a.title = a.label.toLowerCase();
    a.total = (byAct[a.key] || []).length;
    el.addEventListener("click", function () {
      state.act = a.key;
      state.actTitle = a.label;
      showView("all");
      reset();
      window.scrollTo(0, 0);
    });
    return a;
  });

  // The count over each list, the page size beside it, and paging in the panel's foot.
  function panel(section, items, noun) {
    if (!section) return null;
    var p = {
      items: items, noun: noun, bar: section.querySelector(".listbar"),
      rows: section.querySelector(".rows"), next: section.querySelector(".next"),
      rest: section.querySelector(".rest"), empty: section.querySelector(".nomatch"),
    };
    p.bar.hidden = false;
    p.sizes = Array.prototype.slice.call(p.bar.querySelectorAll(".size"));
    p.sizes.forEach(function (b) {
      b.addEventListener("click", function () {
        state.size = Number(b.dataset.n);
        try { localStorage.setItem("draugr-report-page-size", String(state.size)); } catch (e) { /* this page only */ }
        reset();
      });
    });
    p.next.addEventListener("click", function () { p.cap += state.size; render(); });
    return p;
  }
  var panels = [panel(work, acts, "action"), panel(all, rows, "finding")].filter(Boolean);

  function counted(n, noun) { return n.toLocaleString() + " " + noun + (n === 1 ? "" : "s"); }
  function paint(p) {
    var matched = p.items.filter(function (x) { return x.ok; }).length, shown = 0;
    p.items.forEach(function (x) {
      var visible = x.ok && shown < p.cap;
      if (visible) shown++;
      x.el.classList.toggle("cut", !visible);
    });
    p.bar.querySelector(".lcount").textContent = matched === p.items.length
      ? counted(matched, p.noun)
      : matched.toLocaleString() + " of " + p.items.length.toLocaleString();
    p.sizes.forEach(function (b) { b.classList.toggle("on", Number(b.dataset.n) === state.size); });
    var left = matched - shown;
    p.next.hidden = p.rest.hidden = left <= 0;
    p.next.textContent = "Show " + Math.min(state.size, left) + " more";
    p.rest.textContent = shown.toLocaleString() + " of " + matched.toLocaleString();
    p.bar.hidden = p.rows.hidden = !matched;
    p.empty.hidden = !!matched;
  }

  function token(label, title, off) {
    var t = document.createElement("button");
    t.type = "button";
    t.className = "token";
    t.title = title;
    t.appendChild(document.createTextNode(label));
    var x = document.createElement("span");
    x.className = "x";
    x.textContent = "×";
    t.appendChild(x);
    t.addEventListener("click", function () { off(); reset(); });
    tokenBox.appendChild(t);
  }

  function render() {
    rows.forEach(function (r) { r.ok = passes(r) && searched(r) && inAction(r); });
    // Under a narrowing each action says how many of its findings are left, and one with none
    // left goes. A search that names the action keeps all of its findings.
    acts.forEach(function (a) {
      var titled = state.q && a.title.indexOf(state.q) >= 0, n = 0;
      (byAct[a.key] || []).forEach(function (r) { if (passes(r) && (titled || searched(r))) n++; });
      a.ok = n > 0;
      a.count.textContent = (n === a.total ? "" : n + " of ") + counted(a.total, "finding");
    });
    panels.forEach(paint);

    var folded = 0;
    dims.forEach(function (d) {
      var on = ticked(d).length;
      if (d.folded) {
        folded += on;
        d.anchor.classList.toggle("shown", state.open);
      }
      d.badge.textContent = on ? String(on) : "";
      d.badge.hidden = !on;
      d.button.classList.toggle("on", on > 0);
      // Each option counts what ticking it would show, given every other narrowing that is on.
      var c = {};
      rows.forEach(function (r) {
        if (passes(r, d.k) && searched(r) && inAction(r)) c[r.d[d.k]] = (c[r.d[d.k]] || 0) + 1;
      });
      d.boxes.forEach(function (b) {
        b.closest(".menu-row").querySelector(".c").textContent = (c[b.value] || 0).toLocaleString();
        b.disabled = !c[b.value] && !b.checked;
      });
    });
    narrow.textContent = "Narrow" + (folded ? " " + folded : "") + " " + (state.open ? "▴" : "▾");
    narrow.classList.toggle("open", state.open);
    narrow.setAttribute("aria-expanded", String(state.open));

    // Every narrowing that is on, each carrying the way to take it off, and one control that takes
    // them all off, offered only when something is narrowed.
    while (tokenBox.firstChild) tokenBox.removeChild(tokenBox.firstChild);
    dims.forEach(function (d) {
      d.boxes.forEach(function (b) {
        if (b.checked) token(b.value.toLowerCase(), "Stop filtering by " + b.value, function () { b.checked = false; });
      });
    });
    if (state.act) {
      token(state.actTitle.toLowerCase(), "Show every finding again", function () { state.act = ""; state.actTitle = ""; });
    }
    if (narrowed()) {
      var clear = document.createElement("button");
      clear.type = "button";
      clear.className = "clear";
      var x = document.createElement("span");
      x.className = "x";
      x.textContent = "✕";
      clear.appendChild(x);
      clear.appendChild(document.createTextNode(" Clear filters"));
      clear.addEventListener("click", function () {
        dims.forEach(function (d) { d.boxes.forEach(function (b) { b.checked = false; }); });
        q.value = "";
        state.q = state.act = state.actTitle = "";
        reset();
      });
      tokenBox.appendChild(clear);
    }

    // What the reader narrowed to, said once above the list. Only for a single component: the
    // facts on it are that component's verdict, its failing controls and its gaps, and there is no
    // such thing for two, because a strip averaging them is a number nothing holds.
    var m = dims.filter(function (d) { return d.k === "m"; }).map(ticked)[0] || [];
    var only = m.length === 1 ? m[0] : "";
    strips.forEach(function (el) { el.hidden = el.dataset.m !== only; });
  }
  // A narrowing starts every list from its first page again.
  function reset() {
    panels.forEach(function (p) { p.cap = state.size; });
    render();
  }
  reset();
})();
</script>
</body>
</html>
`

// htmlFeed is one exploitability dataset, rendered.
type htmlFeed struct {
	Name     string
	Obtained string
	Digest   string
}

// htmlFeeds renders feed provenance for the template, resolving each field to the string the
// reader should see rather than leaving the template to decide.
func htmlFeeds(feeds []FeedProvenance) []htmlFeed {
	if len(feeds) == 0 {
		return nil
	}
	out := make([]htmlFeed, 0, len(feeds))
	for _, f := range feeds {
		obtained := "supplied as a file"
		if !f.FetchedAt.IsZero() {
			obtained = f.FetchedAt.UTC().Format(time.DateOnly)
		}
		if f.Stale {
			obtained += " (stale)"
		}
		digest := f.SHA256
		if len(digest) > 12 {
			digest = "sha256:" + digest[:12]
		}
		out = append(out, htmlFeed{Name: f.Name, Obtained: obtained, Digest: digest})
	}
	return out
}
