package report

import (
	"fmt"
	"html/template"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

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
	Findings       []htmlFinding
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
	Errors      []htmlError
	Suppressed  int
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
	// Excluded are the findings a config.exclude rule set aside, each with the reason given.
	// The count alone answers "was anything hidden"; an auditor asks who decided it was
	// acceptable, which needs the reason next to the finding.
	Excluded []htmlFinding
	// Facets are the distinct values the filter controls offer, so the toolbar only ever shows
	// options that match something.
	// The menus above the findings. Priority and severity are the product's own vocabulary, so
	// every value is offered with a zero where this run has none; a reader cannot tell "no P1s
	// here" from "this filter does not exist" when the option is simply absent. Control and
	// component are the project's, so they offer what appears.
	Priorities, Severities       []htmlFacet
	ControlNames, ComponentNames []htmlFacet
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
type htmlUnmatched struct{ Source, Rule string }

type htmlFinding struct {
	Priority, Severity, SevClass, Score, RuleID, Control, Tool, Component, Location, Message string
	// Upgrade is the dependency and the release that clears it, which is the only instruction on
	// the row. Empty for a finding that is not about a package.
	Upgrade string
	// Moved names what argued with this finding's band, in the words the console uses.
	Moved string
	// HelpURI documents the rule. Rendered as a link because this is the one format where a
	// link costs nothing, and a rule id names a finding without explaining it.
	HelpURI string
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
	view.Version = d.Version
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
	prio, sev, ctl, comp := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	for _, f := range s.findings {
		hf := toHTMLFinding(f)
		view.Findings = append(view.Findings, hf)
		prio[hf.Priority]++
		sev[hf.Severity]++
		ctl[hf.Control]++
		comp[hf.Component]++
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
		view.Unmatched = append(view.Unmatched, htmlUnmatched{Source: "config.exclude", Rule: excludeSummary(e)})
	}
	for _, c := range d.Run.UnmatchedClaims {
		view.Unmatched = append(view.Unmatched, htmlUnmatched{Source: "VEX", Rule: claimSummary(c)})
	}
	view.Gate = gateSentence(d)
	view.Priorities = ourVocabulary([]string{"P1", "P2", "P3", "P4"}, prio)
	view.Severities = ourVocabulary([]string{"critical", "high", "medium", "low"}, sev)
	view.ControlNames = theirVocabulary(ctl)
	view.ComponentNames = theirVocabulary(comp)
	return htmlTemplate.Execute(w, view)
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
			effect = fmt.Sprintf("%s raised", plural(n, "finding"))
		}
		out = append(out, htmlSignal{Name: strings.ToUpper(name), Effect: effect})
	}
	if n := s.floored; n > 0 {
		out = append(out, htmlSignal{
			Name: "floor", Effect: fmt.Sprintf("%s raised by a control's own rule", plural(n, "finding")),
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
	var moved string
	if m := movedBy(f); m != nil {
		moved = m.glyph + " " + m.label
	}
	return htmlFinding{
		Priority: dash(f.priority), Severity: string(sev), SevClass: "sev-" + string(sev),
		Score: scoreStr(f), RuleID: f.ruleID, Control: f.control, Tool: dash(f.tool),
		Component: dash(f.component),
		Location:  dash(f.location), Message: findingTitle(f), HelpURI: f.helpURI,
		Upgrade:       upgradeLabel(f),
		Moved:         moved,
		Justification: f.justification,
		ActionKey:     actionKeyFor(f),
		Search: strings.ToLower(strings.Join(
			[]string{f.ruleID, f.control, f.tool, f.location, f.message, f.priority, string(sev)}, " ")),
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
    --line: #232a31;
    --line-strong: #2f3841;

    --text: #e6e8ea;
    --muted: #9aa4ae;
    --faint: #78838d;

    --accent: #e8b84b;
    --accent-quiet: rgb(232 184 75 / 12%);
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

    --pass: #57ab5a;
    --fail: #e5534b;
    --on-pass: #06120a;
    --on-fail: #120605;

    --radius: 6px;
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
  --line: #dfe3e7;
  --line-strong: #c3cad1;

  --text: #10161c;
  --muted: #55606b;
  --faint: #6b7680;

  --accent: #a97d12;
  --accent-quiet: rgb(232 184 75 / 26%);
  --on-accent: #ffffff;

  /* The bands keep their hue, because a band that changed color with the theme would be two
  * scales for one set of numbers. Only the ink on them moves. */
  --p1: #c0342b;
  --on-p1: #ffffff;
  --p2: #e8b84b;
  --p3: #7ca6b8;
  --p4: #6b7680;

  --pass: #2e7d33;
  --fail: #c0342b;
  --on-pass: #ffffff;
  --on-fail: #ffffff;
  }

  @media (prefers-color-scheme: light) {
    :root:not([data-theme="dark"]) {

    --bg: #ffffff;
    --surface: #f6f7f8;
    --line: #dfe3e7;
    --line-strong: #c3cad1;

    --text: #10161c;
    --muted: #55606b;
    --faint: #6b7680;

    --accent: #a97d12;
    --accent-quiet: rgb(232 184 75 / 26%);
    --on-accent: #ffffff;

    /* The bands keep their hue, because a band that changed color with the theme would be two
    * scales for one set of numbers. Only the ink on them moves. */
    --p1: #c0342b;
    --on-p1: #ffffff;
    --p2: #e8b84b;
    --p3: #7ca6b8;
    --p4: #6b7680;

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

  /* What moved a band, beside the rating it moved. Muted: the row is already found by its band,
   * and the mark is the reason rather than the alarm. */
  .moved { color: var(--muted); font-size: .74rem; white-space: nowrap; }
  /* A date is one token. Wrapped across two lines it reads as two values. */
  .when { white-space: nowrap; }
  /* The release that ends a finding wears the color a passing verdict wears, which is what the
   * console and the dashboard both do with this fact. */
  .upg { font-family: "JetBrains Mono", ui-monospace, monospace; font-size: .78rem; white-space: nowrap; }
  .upg { color: var(--muted); }

  /* Two views of one set, and the toggle between them. The plane leads with the work and keeps the
   * list beside it, because a reader opening a report is deciding what to do rather than scanning
   * output. Hidden until scripts run: without them both sections render, each under its own
   * heading, which is a complete document rather than a dead control over half of one. */
  .views { display: flex; gap: .35rem; margin: 0 0 .9rem; }
  .view {
    font: inherit; font-size: .86rem; padding: .35rem .8rem; cursor: pointer;
    border: 1px solid var(--line-strong); border-radius: 4px;
    background: var(--surface); color: var(--muted);
  }
  .view:hover { color: var(--text); border-color: var(--accent); }
  .view.on { background: var(--accent); border-color: var(--accent); color: var(--on-accent); font-weight: 600; }

  ul.actions { list-style: none; padding: 0; margin: .4rem 0 1.25rem; }
  .act {
    display: grid; gap: .15rem .8rem; align-items: baseline;
    grid-template-columns: 2.2rem 1fr auto;
    padding: .55rem .8rem; border: 1px solid var(--line); border-radius: var(--radius);
    background: var(--surface); margin-bottom: .35rem;
  }
  .act-title { font-weight: 600; }
  .act-meta { color: var(--faint); font-size: .8rem; text-align: right; white-space: nowrap; }
  /* The count is the way into the rows behind it. A fix list that says "5 findings" and cannot
   * show which five asks a reader to take it on trust, and the five are already on the page. */
  .act-clears {
    font: inherit; font-size: inherit; padding: 0; border: 0; background: none;
    color: var(--accent); cursor: pointer; text-decoration: underline;
    text-underline-offset: 2px; text-decoration-color: var(--line-strong);
  }
  .act-clears:hover { text-decoration-color: var(--accent); }

  .act-where {
    grid-column: 2 / -1; color: var(--muted); font-size: .8rem;
    font-family: "JetBrains Mono", ui-monospace, monospace;
  }

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

  /* Search and menus in one strip, the count under it. The dashboard narrows every list this way,
   * and a reader who has learned it there does not learn it again here. */
  .bar { display: flex; flex-wrap: wrap; gap: .45rem; align-items: center; margin: 0 0 .45rem; }
  .bar input[type=search] {
    flex: 1 1 18rem; font: inherit; font-size: .86rem; padding: .42rem .65rem;
    border: 1px solid var(--line-strong); border-radius: 4px;
    background: var(--surface); color: var(--text);
  }
  .bar input[type=search]::placeholder { color: var(--faint); }

  /* A filter menu, the shape the dashboard uses. A chip that opens a list of ticks rather than a
   * one-of control: choosing P1 and P2 asks for both, because that is what filtering over a set of
   * values means, and a reader who has learned that there does not learn it again here.
   *
   * The chip carries how many are ticked. A closed menu that is narrowing the list has to say so,
   * or the list reads as unfiltered. */
  .menu-anchor { position: relative; display: inline-block; }
  .chip-menu {
    font: inherit; font-size: .86rem; padding: .42rem .7rem;
    border: 1px solid var(--line-strong); border-radius: 4px;
    background: var(--surface); color: var(--muted); cursor: pointer;
  }
  .chip-menu:hover { color: var(--text); border-color: var(--accent); }
  .chip-menu.on { color: var(--text); border-color: var(--accent); }
  .chip-menu .c, .menu-row .c {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: .68rem; color: var(--faint); margin-left: .3rem;
  }
  .chip-menu.on .c { color: var(--accent); }
  .caret { color: var(--faint); margin-left: .25rem; }

  .menu {
    position: absolute; top: calc(100% + 6px); left: 0; z-index: 20;
    min-width: 15rem; padding: 6px;
    border: 1px solid var(--line-strong); border-radius: 4px;
    background: var(--surface); box-shadow: 0 8px 24px rgb(0 0 0 / 28%);
    display: flex; flex-direction: column; max-height: min(58vh, 460px);
  }
  /* Anchored to whichever edge keeps it on the page. The last chip in the strip sits near the
   * right margin, and a menu that opens off the edge is a menu whose counts nobody can read. */
  .menu.right { left: auto; right: 0; }
  .menu-head {
    flex: none; padding: 4px 6px 6px; font-size: .66rem; letter-spacing: .07em;
    text-transform: uppercase; color: var(--faint);
  }
  .menu-options { overflow-y: auto; min-height: 0; padding: 1px; margin: -1px; }
  .menu-row {
    display: flex; justify-content: space-between; gap: 1rem;
    padding: 4px 6px; font-size: .84rem; color: var(--text); cursor: pointer;
  }
  .menu-row:hover { background: var(--bg); }
  .menu-row.on { background: var(--bg); box-shadow: inset 2px 0 0 var(--accent); }
  .menu-row input { margin-right: .5rem; }
  /* A value nothing here carries stays in the list and says zero. Which narrowings exist is part
   * of what the strip teaches, and removing the option answers a different question from the one
   * the reader asked. It is disabled rather than hidden, so nobody spends a click on it. */
  .menu-row:has(input:disabled) { color: var(--faint); cursor: default; }
  /* What is on, beside what turns it off. A reader has to be able to see the state of the list
   * without opening a menu, and a filtered list nobody can tell is filtered is one somebody reads
   * as the whole set. */
  .state { display: flex; flex-wrap: wrap; align-items: center; gap: .4rem .7rem; margin: 0 0 1rem; }
  .count { color: var(--faint); font-size: .82rem; }
  .tokens { display: flex; flex-wrap: wrap; gap: .3rem; }
  .token {
    font: inherit; font-size: .78rem; padding: .12rem .45rem;
    border: 1px solid var(--accent); border-radius: 3px;
    background: var(--surface); color: var(--text); cursor: pointer;
  }
  .token .x { color: var(--faint); margin-left: .35rem; }
  .token:hover .x { color: var(--text); }
  .linkish {
    padding: 0; border: 0; background: none; color: var(--accent);
    cursor: pointer; font: inherit; font-size: .82rem;
  }
  .linkish:hover { text-decoration: underline; }

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

  .hide { display: none; }

  footer {
    color: var(--faint); font-size: .82rem; margin-top: 2.5rem;
    border-top: 1px solid var(--line); padding-top: .8rem;
  }

  :focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }

  @media print {
    .bar, .facets, .dl, .nav { display: none; }
    body { max-width: none; background: #fff; color: #000; }
    tr { break-inside: avoid; }
    a::after { content: " (" attr(href) ")"; font-size: .8em; color: #444; }
  }
</style>
</head>
<body>
<header class="strip">
  <span class="mark">Draugr</span>
  <h1><span class="verdict {{if .Pass}}pass{{else}}fail{{end}}">{{.Verdict}}</span></h1>
  {{if .Release}}<p class="rel">{{.Release}}</p>{{end}}
  {{if .Duration}}<p class="took">{{.Duration}}{{if .CacheHits}} · {{.CacheHits}} from cache{{end}}</p>{{end}}
  <span class="spacer"></span>
  {{if .Prioritized}}<span class="bands">
    <span class="band {{if .P1}}b1{{else}}zero{{end}}">P1 {{.P1}}</span>
    <span class="band {{if .P2}}b2{{else}}zero{{end}}">P2 {{.P2}}</span>
    <span class="band {{if .P3}}b3{{else}}zero{{end}}">P3 {{.P3}}</span>
    <span class="band {{if .P4}}b4{{else}}zero{{end}}">P4 {{.P4}}</span>
  </span>{{end}}
</header>

<nav class="tabs" aria-label="Sections of this report">
  {{if .Signals}}<a class="tab" href="#signals">Signals</a>{{end}}
  {{if .Controls}}<a class="tab" href="#controls">Controls</a>{{end}}
  {{if .Errors}}<a class="tab err" href="#errors">Errors</a>{{end}}
  <a class="tab" href="#findings-h">Findings</a>
  {{if .Decisions}}<a class="tab" href="#suppressed">Accepted</a>{{end}}
  {{if .Slowest}}<a class="tab" href="#timing">Timing</a>{{end}}
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

{{if .Prioritized}}
<p class="note">Priority combines how severe a finding is with how exposed and how business-critical
the component is, so the same issue ranks differently on a public API than on an internal tool.
<strong>P1</strong> is act now, <strong>P4</strong> is track it. Counts cover the whole run.</p>
{{end}}

{{if .Signals}}
<h2 id="signals">Signals</h2>
<p class="note">What argued with this run's ranking, and how many findings each one moved. Counted over the whole run rather than over the list below, which any filter narrows.</p>
<table class="provenance">
<thead><tr><th scope="col">Signal</th><th scope="col">Effect</th></tr></thead>
{{range .Signals}}<tr><td><code>{{.Name}}</code></td><td>{{.Effect}}</td></tr>{{end}}
</table>
{{end}}
{{if .Controls}}
<h2 id="controls">Controls</h2>
<ul class="controls">
{{range .Controls}}<li class="ctl{{if .Errored}} bad{{end}}">
  <span class="ctl-name">{{.Control}}</span>
  <span class="ctl-verdict">{{if .Errored}}<span class="err">ERROR</span>{{else if .Fail}}<span class="err">FAIL</span>{{else}}<span class="ok">pass</span>{{end}}</span>
  {{if .NoReport}}<span class="ctl-none">nothing to report, this control did not run</span>
  {{else if .Prioritized}}<span class="sevs">
    <span class="sev s-p1{{if not .P1}} off{{end}}">P1 {{.P1}}</span>
    <span class="sev s-p2{{if not .P2}} off{{end}}">P2 {{.P2}}</span>
    <span class="sev s-p3{{if not .P3}} off{{end}}">P3 {{.P3}}</span>
    <span class="sev s-p4{{if not .P4}} off{{end}}">P4 {{.P4}}</span>
  </span>
  {{else}}<span class="sevs">
    <span class="sev s-critical{{if not .Critical}} off{{end}}">{{.Critical}} critical</span>
    <span class="sev s-high{{if not .High}} off{{end}}">{{.High}} high</span>
    <span class="sev s-medium{{if not .Medium}} off{{end}}">{{.Medium}} medium</span>
    <span class="sev s-low{{if not .Low}} off{{end}}">{{.Low}} low</span>
  </span>{{end}}
</li>{{end}}
</ul>
{{if .Exploitability}}
<h3 class="sub">Exploitability data</h3>
<table class="provenance">
<thead><tr><th scope="col">Feed</th><th scope="col">Obtained</th><th scope="col">Digest</th></tr></thead>
<tbody>
{{range .Exploitability}}<tr><td>{{.Name}}</td><td>{{.Obtained}}</td><td>{{.Digest}}</td></tr>{{end}}
</tbody>
</table>
{{end}}
{{if .Scanned}}
<h3 class="sub">Scanned</h3>
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
{{end}}
{{if .Provenance}}
<h3 class="sub">Measured against</h3>
<table class="provenance">
<thead><tr><th scope="col">Control</th><th scope="col">Scanner</th><th scope="col">Run</th></tr></thead>
<tbody>
{{range .Provenance}}<tr><td>{{.Control}}</td><td>{{.Label}}</td><td>{{.Detail}}</td></tr>{{end}}
</tbody>
</table>
{{end}}
{{end}}

{{if .Errors}}
<h3 id="errors" class="err">Controls that could not run</h3>
<p class="note">These checks were requested and did not complete, so this report says nothing
about what they would have found. For everything the tool printed, re-run with the
<code class="cmd">--log-level trace</code> flag:</p>
<pre class="cmd">draugr scan &lt;saga.yaml&gt; --log-level trace</pre>
<ul class="errors">
{{range .Errors}}<li><strong>{{.Control}}</strong> · {{.Message}}</li>{{end}}
</ul>
{{end}}

{{if .Suppressed}}<p class="note">{{.Suppressed}} finding(s) suppressed by <code class="cmd">config.exclude</code> · reported, not deleted; each carries the reason it was set aside.</p>{{end}}
{{if .Gate}}<p class="note">{{.Gate}}.</p>{{end}}
{{if .SBOMCount}}<p class="note">SBOM: {{.SBOMCount}} document(s) ({{.SBOMFormat}}).</p>{{end}}

<h2 id="findings-h">Findings{{if .MinPriority}} · {{.MinPriority}} and above{{end}}</h2>

{{if .Actions}}
<div class="views" id="views" hidden>
  <button type="button" class="view on" data-view="work">What to do</button>
  <button type="button" class="view" data-view="all">All findings</button>
</div>

<section id="work">
  <h3 class="sub js-off">What to do</h3>
  <p class="note">One row per thing to do rather than per finding: eight advisories in one library
  are one upgrade. Always the whole run, so these agree with the counts at the top of the page.</p>
  <ul class="actions">
  {{range .Actions}}<li class="act">
    <span class="pri {{.Priority}}">{{.Priority}}</span>
    <span class="act-title">{{.Title}}</span>
    <span class="act-meta">{{.Control}} · <button type="button" class="act-clears" data-a="{{.Key}}" data-title="{{.Title}}">{{.Clears}} finding{{if ne .Clears 1}}s{{end}}</button>{{if .Upstream}} · upstream{{end}}{{if .Cached}} · from cache{{end}}</span>
    {{if .Where}}<span class="act-where">{{.Where}}</span>{{end}}
  </li>{{end}}
  </ul>
  {{if .External}}<p class="note">{{.External}} finding(s) belong to somebody else to fix, and are
  in the list beside this one rather than here: work a reader cannot do, at the top of a list of
  what to do, teaches them the list is not worth reading.</p>{{end}}
</section>
{{end}}

<section id="all">
<h3 class="sub js-off">All findings</h3>
{{if .MinPriority}}<p class="note">The counts above describe the whole run{{if .Hidden}}; {{.Hidden}} lower-priority finding(s) are not listed{{end}}.</p>{{end}}

<p class="dl">
  {{if .SARIFHref}}<a href="{{.SARIFHref}}" download="results.sarif">⬇ SARIF</a>{{end}}
  {{if .TSVHref}}<a href="{{.TSVHref}}" download="findings.tsv">⬇ TSV</a>{{end}}
  {{if .SARIFTooBig}}<span class="note">SARIF too large to embed · re-run with <code class="cmd">-o &lt;dir&gt;</code>.</span>{{end}}
</p>

<div id="tools" hidden>
  <div class="bar">
    <input type="search" id="q" placeholder="Search rule, message, file, component…" aria-label="Search findings">
    {{template "menu" dict "K" "p" "Label" "Priority" "Options" .Priorities}}
    {{template "menu" dict "K" "s" "Label" "Severity" "Options" .Severities}}
    {{template "menu" dict "K" "c" "Label" "Control" "Options" .ControlNames}}
    {{template "menu" dict "K" "m" "Label" "Component" "Options" .ComponentNames}}
  </div>
  <p class="state">
    <span class="count" id="count"></span>
    <span class="tokens" id="tokens"></span>
    <button type="button" class="linkish" id="clear" hidden>Show everything</button>
  </p>
</div>

{{define "menu"}}
<span class="menu-anchor">
  <button class="chip-menu" type="button" data-k="{{.K}}" aria-expanded="false" aria-haspopup="true">
    {{.Label}}<span class="c num" hidden></span><span class="caret" aria-hidden="true">&#9662;</span>
  </button>
  <div class="menu" hidden role="group" aria-label="{{.Label}}">
    <div class="menu-head">{{.Label}}</div>
    <div class="menu-options">
      {{range .Options}}
      <label class="menu-row">
        <span><input type="checkbox" class="f" data-k="{{$.K}}" value="{{.Value}}"{{if not .Count}} disabled{{end}}> {{.Value}}</span>
        <span class="c num">{{.Count}}</span>
      </label>
      {{end}}
    </div>
  </div>
</span>
{{end}}
{{if .Findings}}
<table id="findings">
<thead><tr>
  <th scope="col">Priority</th><th scope="col">Severity</th>
  <th scope="col">Rule</th><th scope="col">Scanner</th><th scope="col">Component</th><th scope="col">Location</th><th scope="col">Upgrade</th>
</tr></thead>
{{range .Findings}}<tbody class="f" data-p="{{.Priority}}" data-s="{{.Severity}}" data-c="{{.Control}}" data-m="{{.Component}}" data-a="{{.ActionKey}}" data-q="{{.Search}}">
<tr class="meta">
  <td class="pri {{.Priority}}">{{.Priority}}</td>
  <td class="{{.SevClass}}">{{.Severity}}{{if .Moved}} <span class="moved">{{.Moved}}</span>{{end}}</td>
  <td><code>{{if .HelpURI}}<a href="{{.HelpURI}}">{{.RuleID}}</a>{{else}}{{.RuleID}}{{end}}</code></td>
  <td>{{.Tool}}</td>
  <td>{{.Component}}</td>
  <td><code>{{.Location}}</code></td>
  <td class="upg">{{.Upgrade}}</td>
</tr>
<tr class="msg"><td colspan="7">{{.Message}}</td></tr>
</tbody>{{end}}
</table>
<p class="empty" id="none" hidden>No findings match this filter.</p>
{{else if .Errors}}
<p>No findings from the controls that ran. See the errors reported above.</p>
{{else}}
<p>No findings. ✓</p>
{{end}}
</section>

{{if .Decisions}}
<h2 id="suppressed">Accepted</h2>
<p class="note">Set aside by <code class="cmd">config.exclude</code>. Reported rather than deleted, so the decision is visible and reviewable.</p>
<h3 class="sub">Decisions</h3>
<table class="provenance">
<thead><tr><th scope="col" class="num">Findings</th><th scope="col">Accepted by</th><th scope="col">Expires</th><th scope="col">Reason</th></tr></thead>
{{range .Decisions}}<tr>
  <td class="num">{{.N}}</td>
  <td>{{if .Unattributed}}<span class="err">unattributed</span>{{else}}{{.By}}{{end}}</td>
  <td class="when">{{if .Expires}}{{.Expires}}{{else}}<span class="faint">never</span>{{end}}</td>
  <td>{{.Reason}}</td>
</tr>{{end}}
</table>
{{end}}

{{if .Unmatched}}
<h3 class="sub">Unmatched</h3>
<p class="note">These rules suppressed nothing. A rule that matches nothing claims a decision it is not making, and reads exactly like one that is working.</p>
<table class="provenance">
<thead><tr><th scope="col">Source</th><th scope="col">Rule</th></tr></thead>
{{range .Unmatched}}<tr><td><code>{{.Source}}</code></td><td>{{.Rule}}</td></tr>{{end}}
</table>
{{end}}

{{if .Excluded}}
<h3 class="sub">What was set aside</h3>
<table>
<thead><tr><th scope="col">Severity</th><th scope="col">Rule</th><th scope="col">Control</th><th scope="col">Component</th><th scope="col">Location</th></tr></thead>
{{range .Excluded}}<tbody>
<tr class="meta">
  <td class="{{.SevClass}}">{{.Severity}}</td>
  <td><code>{{if .HelpURI}}<a href="{{.HelpURI}}">{{.RuleID}}</a>{{else}}{{.RuleID}}{{end}}</code></td>
  <td>{{.Control}}</td>
  <td>{{.Component}}</td>
  <td><code>{{.Location}}</code></td>
</tr>
<tr class="msg"><td colspan="5">{{.Message}}<br><span class="just">Reason: {{.Justification}}</span></td></tr>
</tbody>{{end}}
</table>
{{end}}

{{if .Slowest}}
<h2 id="timing">Where the time went</h2>
<p class="note">Time spent per control, worst first. Controls run in parallel, so these sum to
more than the elapsed time, because the shares are of the total work rather than of the wall clock.</p>
<table>
<thead><tr><th scope="col">Control</th><th scope="col" class="num">Time</th><th scope="col">Share</th></tr></thead>
<tbody>
{{range .Slowest}}<tr>
  <td>{{.Control}}</td>
  <td class="num">{{.Duration}}</td>
  <td><span class="bar-track"><span class="bar-fill" style="width:{{.Pct}}%"></span></span> {{.Pct}}%</td>
</tr>{{end}}
</tbody>
</table>
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

  var tools = document.getElementById("tools");
  var rows = Array.prototype.slice.call(document.querySelectorAll("tbody.f"));
  if (!tools || !rows.length) return;
  tools.hidden = false;

  // Two views of one set. "What to do" leads, the list sits behind the toggle, and the headings
  // that separate them without scripts are dropped because the toggle now names them.
  var views = document.getElementById("views");
  var work = document.getElementById("work");
  var all = document.getElementById("all");
  if (views && work && all) {
    views.hidden = false;
    Array.prototype.forEach.call(document.querySelectorAll(".js-off"), function (h) {
      h.hidden = true;
    });
    var show = function (which) {
      work.hidden = which !== "work";
      all.hidden = which !== "all";
      Array.prototype.forEach.call(views.querySelectorAll(".view"), function (b) {
        b.classList.toggle("on", b.dataset.view === which);
        b.setAttribute("aria-pressed", String(b.dataset.view === which));
      });
    };
    Array.prototype.forEach.call(views.querySelectorAll(".view"), function (b) {
      b.addEventListener("click", function () { show(b.dataset.view); });
    });
    show("work");

    // Following a count is a question about those findings, so it opens the list already narrowed
    // to them. The token it leaves in the row above is how a reader gets back, and is the only
    // thing on screen that says why the list is short.
    Array.prototype.forEach.call(document.querySelectorAll(".act-clears"), function (btn) {
      btn.addEventListener("click", function () {
        actionKey = btn.dataset.a || "";
        actionTitle = btn.dataset.title || "";
        show("all");
        apply();
      });
    });
  }

  var q = document.getElementById("q");
  var count = document.getElementById("count");
  var none = document.getElementById("none");
  var boxes = Array.prototype.slice.call(document.querySelectorAll("#tools input.f"));
  var anchors = Array.prototype.slice.call(document.querySelectorAll("#tools .menu-anchor"));

  // Ticks within one menu add up, and the menus narrow each other. Choosing P1 and P2 asks for
  // both rather than replacing one with the other, which is what a filter over a set of values
  // means; across dimensions it is an and, because each answers a different question.
  //
  // Nothing ticked in a menu is no constraint from that menu rather than a demand for nothing. A
  // reader who unticks every priority to be shown an empty table has expressed no such intent.
  // A narrowing set by following an action rather than by a menu. Held apart from the menus
  // because it is not a dimension somebody browses: it is one row of the fix list, and the way out
  // of it is the token it puts in the row above.
  var actionKey = "", actionTitle = "";

  function ticked(kind) {
    var on = boxes.filter(function (b) { return b.dataset.k === kind && b.checked; });
    return on.length ? on.map(function (b) { return b.value; }) : null;
  }

  function closeMenus(except) {
    anchors.forEach(function (a) {
      if (a === except) return;
      a.querySelector(".menu").hidden = true;
      a.querySelector(".chip-menu").setAttribute("aria-expanded", "false");
    });
  }

  anchors.forEach(function (a) {
    var button = a.querySelector(".chip-menu");
    var menu = a.querySelector(".menu");
    button.addEventListener("click", function (e) {
      e.stopPropagation();
      var wasOpen = !menu.hidden;
      closeMenus();
      if (wasOpen) return;
      menu.hidden = false;
      button.setAttribute("aria-expanded", "true");
      // Measured rather than assumed: which chips sit near the right margin depends on how the
      // strip wrapped, which depends on the window.
      menu.classList.remove("right");
      if (menu.getBoundingClientRect().right > document.documentElement.clientWidth - 8) {
        menu.classList.add("right");
      }
      var first = menu.querySelector("input:not([disabled])");
      if (first) first.focus();
    });
    menu.addEventListener("click", function (e) { e.stopPropagation(); });
  });
  // One menu at a time, and the page takes the click that closes it.
  document.addEventListener("click", function () { closeMenus(); });
  document.addEventListener("keydown", function (e) { if (e.key === "Escape") closeMenus(); });

  function apply() {
    var needle = (q.value || "").trim().toLowerCase();
    var p = ticked("p"), s = ticked("s"), c = ticked("c"), m = ticked("m");
    var shown = 0;
    rows.forEach(function (row) {
      var d = row.dataset;
      var ok = (!p || p.indexOf(d.p) >= 0) &&
               (!s || s.indexOf(d.s) >= 0) &&
               (!c || c.indexOf(d.c) >= 0) &&
               (!m || m.indexOf(d.m) >= 0) &&
               (!actionKey || d.a === actionKey) &&
               (!needle || d.q.indexOf(needle) >= 0);
      row.classList.toggle("hide", !ok);
      if (ok) shown++;
    });
    // A menu that is narrowing says so and says by how much, because a list nobody can tell is
    // filtered is a list somebody reads as the whole set.
    anchors.forEach(function (a) {
      var button = a.querySelector(".chip-menu");
      var n = a.querySelectorAll("input.f:checked").length;
      var badge = button.querySelector(".c");
      badge.textContent = n ? String(n) : "";
      badge.hidden = !n;
      button.classList.toggle("on", n > 0);
    });
    a11yRows();
    tokens();
    count.textContent = shown === rows.length
      ? shown + " finding(s)"
      : "showing " + shown + " of " + rows.length;
    none.hidden = shown > 0;
  }

  function a11yRows() {
    boxes.forEach(function (b) {
      b.closest(".menu-row").classList.toggle("on", b.checked);
    });
  }

  // Every narrowing that is on, each carrying the way to take it off, and one control that takes
  // them all off. Offered only when something is narrowed: a reset beside an unfiltered list is a
  // button that does nothing, and a reader who presses it learns the control is not worth reading.
  var tokenBox = document.getElementById("tokens");
  var clear = document.getElementById("clear");
  function tokens() {
    while (tokenBox.firstChild) tokenBox.removeChild(tokenBox.firstChild);
    var on = boxes.filter(function (b) { return b.checked; });
    on.forEach(function (b) {
      var t = document.createElement("button");
      t.type = "button";
      t.className = "token";
      t.title = "Stop filtering by " + b.value;
      t.appendChild(document.createTextNode(b.value));
      var x = document.createElement("span");
      x.className = "x";
      x.textContent = "\u2715";
      t.appendChild(x);
      t.addEventListener("click", function () { b.checked = false; apply(); });
      tokenBox.appendChild(t);
    });
    // The action, named by what it is rather than by its key: a reader who followed "5 findings"
    // is looking at one upgrade, and the token has to say which.
    if (actionKey) {
      var t = document.createElement("button");
      t.type = "button";
      t.className = "token";
      t.title = "Show every finding again";
      t.appendChild(document.createTextNode(actionTitle));
      var x = document.createElement("span");
      x.className = "x";
      x.textContent = "\u2715";
      t.appendChild(x);
      t.addEventListener("click", function () { actionKey = ""; actionTitle = ""; apply(); });
      tokenBox.appendChild(t);
    }
    // The search counts as a narrowing, because a reader who typed and forgot is in exactly the
    // state this row exists to make visible.
    if (q.value.trim()) {
      var t = document.createElement("button");
      t.type = "button";
      t.className = "token";
      t.title = "Clear the search";
      t.appendChild(document.createTextNode("\u201c" + q.value.trim() + "\u201d"));
      var x = document.createElement("span");
      x.className = "x";
      x.textContent = "\u2715";
      t.appendChild(x);
      t.addEventListener("click", function () { q.value = ""; apply(); });
      tokenBox.appendChild(t);
    }
    clear.hidden = !on.length && !q.value.trim() && !actionKey;
  }

  clear.addEventListener("click", function () {
    boxes.forEach(function (b) { b.checked = false; });
    q.value = "";
    actionKey = "";
    actionTitle = "";
    apply();
  });

  q.addEventListener("input", apply);
  boxes.forEach(function (b) { b.addEventListener("change", apply); });
  apply();
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
