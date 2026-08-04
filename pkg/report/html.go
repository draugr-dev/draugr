package report

import (
	"html/template"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
)

// htmlReporter renders a self-contained HTML report — a single file with inline CSS, viewable
// in any browser and shareable as a build artifact. Leads with the verdict, priority counts,
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
	// Provenance is what each scanner said about its own run — the standard applied, how much of
	// it was decided, what it was scoped to. A shared HTML report is the copy that reaches
	// someone who did not run the scan, so it is the one that most needs to say what was
	// measured rather than only what was found.
	Provenance []provenanceLine
	// Repositories is which repository was read and at which commit — the thing that makes the
	// report reproducible, and the answer to "does this describe my change or the last release".
	Repositories []RepositoryProvenance
	// Exploitability names the datasets that raised severities, with the date each was obtained.
	// A shared report claiming a finding is critical has to be able to say on what data — and
	// this is the copy most likely to be read by someone who cannot re-run the scan.
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
	// Excluded are the findings a config.exclude rule set aside, each with the reason given.
	// The count alone answers "was anything hidden"; an auditor asks who decided it was
	// acceptable, which needs the reason next to the finding.
	Excluded []htmlFinding
	// Facets are the distinct values the filter controls offer, so the toolbar only ever shows
	// options that match something.
	Priorities, Severities, ControlNames []string
	// SARIFHref and TSVHref are data: URIs — downloads that work with no JavaScript and under
	// any content-security policy.
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
	Control                     string
	Fail                        bool
	Errored                     bool // its scanner failed: whatever it reported is partial
	NoReport                    bool // it produced nothing at all, so has no counts to show
	Critical, High, Medium, Low int
}

type htmlFinding struct {
	Priority, Severity, SevClass, Score, RuleID, Control, Tool, Component, Location, Message string
	// HelpURI documents the rule. Rendered as a link because this is the one format where a
	// link costs nothing, and a rule id names a finding without explaining it.
	HelpURI string
	// Justification is why the finding was set aside. Only set for suppressed findings.
	Justification string
	// Search is the lower-cased haystack the filter box matches against, precomputed so the
	// page does not rebuild it per keystroke.
	Search string
}

func (htmlReporter) Render(w io.Writer, d Data) error {
	s := summarize(d)

	view := htmlView{
		Provenance:     provenanceLines(d),
		Repositories:   d.Repositories,
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
	if d.Release.Name != "" {
		view.Release = d.Release.Name
		if d.Release.Version != "" {
			view.Release += " " + d.Release.Version
		}
	}
	for _, c := range d.Verdict.Controls {
		b := s.bands[c.Control]
		_, bad := s.scanErrors[c.Control]
		view.Controls = append(view.Controls, htmlControl{
			Control: c.Control, Fail: c.Verdict == norn.Fail, Errored: bad,
			Critical: b.critical, High: b.high, Medium: b.medium, Low: b.low,
		})
	}
	// Controls that produced no report at all have no verdict entry. Omitting them is how a
	// run that could not check something reads as a run that checked it and found nothing.
	for _, name := range s.errored {
		view.Controls = append(view.Controls, htmlControl{Control: name, Errored: true, NoReport: true})
	}
	seenPrio, seenSev, seenCtl := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, f := range s.findings {
		hf := toHTMLFinding(f)
		view.Findings = append(view.Findings, hf)
		// Facets are collected from the findings actually listed, so the toolbar never offers a
		// filter that matches nothing.
		addFacet(seenPrio, &view.Priorities, hf.Priority)
		addFacet(seenSev, &view.Severities, hf.Severity)
		addFacet(seenCtl, &view.ControlNames, hf.Control)
	}
	sort.Strings(view.Priorities)
	sort.Strings(view.ControlNames)
	view.Severities = orderSeverities(view.Severities)
	return htmlTemplate.Execute(w, view)
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
	return htmlFinding{
		Priority: dash(f.priority), Severity: string(f.severity), SevClass: "sev-" + string(f.severity),
		Score: scoreStr(f), RuleID: f.ruleID, Control: f.control, Tool: dash(f.tool),
		Component: dash(f.component),
		Location:  dash(f.location), Message: f.message, HelpURI: f.helpURI,
		Justification: f.justification,
		Search: strings.ToLower(strings.Join(
			[]string{f.ruleID, f.control, f.tool, f.location, f.message, f.priority, string(f.severity)}, " ")),
	}
}

func addFacet(seen map[string]bool, out *[]string, v string) {
	if v == "" || v == "-" || seen[v] {
		return
	}
	seen[v] = true
	*out = append(*out, v)
}

// orderSeverities sorts by how bad rather than alphabetically, so the filter row reads the way
// the table does.
func orderSeverities(got []string) []string {
	rank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
	sort.Slice(got, func(i, j int) bool { return rank[got[i]] < rank[got[j]] })
	return got
}

// htmlTemplate is parsed once at package init; html/template escapes all interpolated values.
var htmlTemplate = template.Must(template.New("report").Parse(htmlDoc))

const htmlDoc = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Draugr report{{if .Release}} — {{.Release}}{{end}}</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 15px/1.5 system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem auto; max-width: 60rem; padding: 0 1rem; }
  h1 { font-size: 1.5rem; margin: 0 0 .25rem; }
  .verdict { display: inline-block; padding: .15rem .6rem; border-radius: .4rem; font-weight: 700; color: #fff; }
  .pass { background: #197a3d; }
  .fail { background: #b3261e; }
  .rel { color: #666; margin: 0 0 1.25rem; }
  table { border-collapse: collapse; width: 100%; margin: .5rem 0 1.5rem; font-size: .92rem; }
  th, td { text-align: left; padding: .4rem .6rem; border-bottom: 1px solid #8883; vertical-align: top; }
  th { font-weight: 600; }
  td.num, th.num { text-align: right; }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .88em; }
  code.cmd { background: #8881; border: 1px solid #8883; border-radius: .3rem; padding: .08rem .35rem; white-space: nowrap; }
  pre.cmd { background: #8881; border: 1px solid #8883; border-radius: .4rem; padding: .5rem .7rem; overflow-x: auto; font-size: .86rem; margin: .4rem 0 0; }
  .chips span { display: inline-block; margin-right: 1rem; }
  .p1 { color: #b3261e; font-weight: 700; }
  .p2 { color: #c25e00; font-weight: 600; }
  .sev-critical { color: #b3261e; font-weight: 700; }
  .sev-high { color: #c2410c; font-weight: 600; }
  .sev-medium { color: #b45309; }
  .sev-low { color: #888; }
  .err { color: #b3261e; font-weight: 700; }
  .errors { border-left: 3px solid #b3261e; padding: .1rem 0 .1rem .8rem; margin: 0 0 1.5rem; }
  .errors li { margin: .2rem 0; }
  .note { color: #555; font-size: .88rem; margin: -.5rem 0 1.25rem; }
  a { color: inherit; }
  footer { color: #888; font-size: .82rem; margin-top: 2rem; border-top: 1px solid #8883; padding-top: .6rem; }
  /* The page declares color-scheme: light dark, so the browser paints dark chrome in dark mode.
     These keep the text legible against it — greys tuned for white are unreadable on near-black. */
  @media (prefers-color-scheme: dark) {
    .rel, .note { color: #aaa; }
    .sev-low { color: #999; }
    .sev-medium { color: #e0a458; }
    .sev-high { color: #ff9e6d; }
    .sev-critical, .p1, .err { color: #ff6b6b; }
    .p2 { color: #ffa94d; }
    .errors { border-left-color: #ff6b6b; }
    .count, tr.msg td, .just, .empty { color: #aaa; }
  }
  .nav { display: flex; flex-wrap: wrap; gap: 1rem; margin: 0 0 1.5rem; font-size: .88rem; }
  .nav a { text-decoration: none; border-bottom: 1px solid #8886; padding-bottom: .1rem; }
  .nav a:hover { border-bottom-color: currentColor; }
  .bar { display: flex; flex-wrap: wrap; gap: .5rem 1rem; align-items: center; margin: 0 0 .75rem; }
  .bar input[type=search] { flex: 1 1 16rem; font: inherit; padding: .35rem .6rem; border: 1px solid #8886; border-radius: .35rem; background: transparent; color: inherit; }
  .facets { display: flex; flex-wrap: wrap; gap: .3rem .9rem; margin: 0 0 1rem; font-size: .86rem; }
  .facets label { cursor: pointer; user-select: none; white-space: nowrap; }
  .count { color: #666; font-size: .86rem; white-space: nowrap; }
  .dl a { display: inline-block; padding: .3rem .7rem; border: 1px solid #8886; border-radius: .35rem; text-decoration: none; font-size: .86rem; }
  .dl a:hover { border-color: #888; }
  tr.msg td { border-bottom: 1px solid #8883; padding-top: 0; color: #444; }
  tr.meta td { border-bottom: 0; padding-bottom: .15rem; }
  .hide { display: none; }
  .just { color: #555; font-style: italic; }
  .bar-track { display: inline-block; width: 8rem; height: .55rem; background: #8883; border-radius: .3rem; overflow: hidden; vertical-align: middle; margin-right: .4rem; }
  .bar-fill { display: block; height: 100%; background: #6b7fd7; }
  .empty { color: #666; font-style: italic; }
  @media print {
    .bar, .facets, .dl, .nav { display: none; }
    body { max-width: none; }
    tr { break-inside: avoid; }
    a::after { content: " (" attr(href) ")"; font-size: .8em; color: #555; }
  }
</style>
</head>
<body>
<h1>Draugr — <span class="verdict {{if .Pass}}pass{{else}}fail{{end}}">{{.Verdict}}</span></h1>
{{if .Release}}<p class="rel">{{.Release}}</p>{{end}}

<nav class="nav">
  {{if .Controls}}<a href="#controls">Controls</a>{{end}}
  {{if .Errors}}<a href="#errors" class="err">Errors</a>{{end}}
  <a href="#findings-h">Findings</a>
  {{if .Excluded}}<a href="#suppressed">Suppressed</a>{{end}}
  {{if .Slowest}}<a href="#timing">Timing</a>{{end}}
  <a href="#about">About this report</a>
</nav>

{{if .Prioritized}}
<h2>Findings by priority</h2>
<p class="chips">
  <span class="p1">P1 {{.P1}}</span>
  <span class="p2">P2 {{.P2}}</span>
  <span>P3 {{.P3}}</span>
  <span>P4 {{.P4}}</span>
</p>
<p class="note">Priority combines how severe a finding is with how exposed and how business-critical
the component is — so the same issue ranks differently on a public API than on an internal tool.
<strong>P1</strong> is act now, <strong>P4</strong> is track it. Counts cover the whole run.</p>
{{end}}

{{if .Controls}}
<h2 id="controls">Controls</h2>
<table>
<thead><tr><th scope="col">Control</th><th scope="col">Verdict</th><th class="num">Critical</th><th class="num">High</th><th class="num">Medium</th><th class="num">Low</th></tr></thead>
<tbody>
{{range .Controls}}<tr>
  <td>{{.Control}}</td>
  <td>{{if .Errored}}<span class="err">ERROR</span>{{else if .Fail}}<strong>FAIL</strong>{{else}}pass{{end}}</td>
  {{if .NoReport}}<td class="num">—</td><td class="num">—</td><td class="num">—</td><td class="num">—</td>
  {{else}}<td class="num">{{.Critical}}</td>
  <td class="num">{{.High}}</td>
  <td class="num">{{.Medium}}</td>
  <td class="num">{{.Low}}</td>{{end}}
</tr>{{end}}
</tbody>
</table>
{{if .Exploitability}}
<h3 class="sub">Exploitability data</h3>
<table class="provenance">
<thead><tr><th scope="col">Feed</th><th scope="col">Obtained</th><th scope="col">Digest</th></tr></thead>
<tbody>
{{range .Exploitability}}<tr><td>{{.Name}}</td><td>{{.Obtained}}</td><td>{{.Digest}}</td></tr>{{end}}
</tbody>
</table>
{{end}}
{{if .Repositories}}
<h3 class="sub">Scanned</h3>
<table class="provenance">
<thead><tr><th scope="col">Repository</th><th scope="col">Revision</th><th scope="col">Not included</th></tr></thead>
<tbody>
{{range .Repositories}}<tr><td>{{.URL}}</td><td>{{.Short}}</td><td>{{if .Uncommitted}}{{.Uncommitted}} uncommitted{{else}}—{{end}}</td></tr>{{end}}
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
{{range .Errors}}<li><strong>{{.Control}}</strong> — {{.Message}}</li>{{end}}
</ul>
{{end}}

{{if .Suppressed}}<p class="note">{{.Suppressed}} finding(s) suppressed by <code class="cmd">config.exclude</code> — reported, not deleted; each carries the reason it was set aside.</p>{{end}}
{{if .SBOMCount}}<p class="note">SBOM: {{.SBOMCount}} document(s) ({{.SBOMFormat}}).</p>{{end}}

<h2 id="findings-h">Findings{{if .MinPriority}} — {{.MinPriority}} and above{{end}}</h2>
{{if .MinPriority}}<p class="note">The counts above describe the whole run{{if .Hidden}}; {{.Hidden}} lower-priority finding(s) are not listed{{end}}.</p>{{end}}

<p class="dl">
  {{if .SARIFHref}}<a href="{{.SARIFHref}}" download="results.sarif">⬇ SARIF</a>{{end}}
  {{if .TSVHref}}<a href="{{.TSVHref}}" download="findings.tsv">⬇ TSV</a>{{end}}
  {{if .SARIFTooBig}}<span class="note">SARIF too large to embed — re-run with <code class="cmd">-o &lt;dir&gt;</code>.</span>{{end}}
</p>

<div id="tools" hidden>
  <div class="bar">
    <input type="search" id="q" placeholder="Search rule, message, file, control…" aria-label="Search findings">
    <span class="count" id="count"></span>
  </div>
  <div class="facets" id="facets">
    {{range .Priorities}}<label><input type="checkbox" class="f" data-k="p" value="{{.}}" checked> {{.}}</label>{{end}}
    {{if .Priorities}}<span aria-hidden="true">·</span>{{end}}
    {{range .Severities}}<label><input type="checkbox" class="f" data-k="s" value="{{.}}" checked> {{.}}</label>{{end}}
    {{if .Severities}}<span aria-hidden="true">·</span>{{end}}
    {{range .ControlNames}}<label><input type="checkbox" class="f" data-k="c" value="{{.}}" checked> {{.}}</label>{{end}}
  </div>
</div>
{{if .Findings}}
<table id="findings">
<thead><tr>
  <th scope="col">Priority</th><th scope="col">Severity</th><th scope="col" class="num">Score</th>
  <th scope="col">Rule</th><th scope="col">Control</th><th scope="col">Scanner</th><th scope="col">Component</th><th scope="col">Location</th>
</tr></thead>
{{range .Findings}}<tbody class="f" data-p="{{.Priority}}" data-s="{{.Severity}}" data-c="{{.Control}}" data-q="{{.Search}}">
<tr class="meta">
  <td>{{.Priority}}</td>
  <td class="{{.SevClass}}">{{.Severity}}</td>
  <td class="num">{{.Score}}</td>
  <td><code>{{if .HelpURI}}<a href="{{.HelpURI}}">{{.RuleID}}</a>{{else}}{{.RuleID}}{{end}}</code></td>
  <td>{{.Control}}</td>
  <td>{{.Tool}}</td>
  <td>{{.Component}}</td>
  <td><code>{{.Location}}</code></td>
</tr>
<tr class="msg"><td colspan="8">{{.Message}}</td></tr>
</tbody>{{end}}
</table>
<p class="empty" id="none" hidden>No findings match this filter.</p>
{{else if .Errors}}
<p>No findings from the controls that ran — see the errors above.</p>
{{else}}
<p>No findings. ✓</p>
{{end}}

{{if .Excluded}}
<h2 id="suppressed">Suppressed</h2>
<p class="note">Excluded by <code class="cmd">config.exclude</code>. Reported rather than deleted, so the decision is visible and reviewable.</p>
<table>
<thead><tr><th scope="col">Severity</th><th scope="col">Rule</th><th scope="col">Control</th><th scope="col">Location</th></tr></thead>
{{range .Excluded}}<tbody>
<tr class="meta">
  <td class="{{.SevClass}}">{{.Severity}}</td>
  <td><code>{{if .HelpURI}}<a href="{{.HelpURI}}">{{.RuleID}}</a>{{else}}{{.RuleID}}{{end}}</code></td>
  <td>{{.Control}}</td>
  <td>{{.Component}}</td>
  <td><code>{{.Location}}</code></td>
</tr>
<tr class="msg"><td colspan="4">{{.Message}}<br><span class="just">Reason: {{.Justification}}</span></td></tr>
</tbody>{{end}}
</table>
{{end}}

{{if .Slowest}}
<h2 id="timing">Where the time went</h2>
<p class="note">Time spent per control, worst first. Controls run in parallel, so these sum to
more than the elapsed time — the shares are of the total work, not of the wall clock.</p>
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
  {{if .Duration}}<br>Completed in {{.Duration}}{{if .CacheHits}} ({{.CacheHits}} result(s) from cache){{end}}.{{end}}
  <br>A passing verdict means the controls you configured found nothing they were looking for; it is not a guarantee of security.
</footer>
<script>
// Progressive enhancement, and deliberately so: everything above renders complete without this.
// The toolbar starts hidden and is revealed here, so a reader with scripts disabled — or an
// email client or artifact viewer that strips them — sees the full table rather than dead
// controls that do nothing.
(function () {
  var tools = document.getElementById("tools");
  var rows = Array.prototype.slice.call(document.querySelectorAll("tbody.f"));
  if (!tools || !rows.length) return;
  tools.hidden = false;

  var q = document.getElementById("q");
  var count = document.getElementById("count");
  var none = document.getElementById("none");
  var boxes = Array.prototype.slice.call(document.querySelectorAll("input.f"));

  // A facet with nothing ticked means "no constraint" rather than "match nothing" — unticking
  // every priority to be shown an empty table is nobody's intent.
  function allowed(kind) {
    var on = boxes.filter(function (b) { return b.dataset.k === kind && b.checked; });
    var all = boxes.filter(function (b) { return b.dataset.k === kind; });
    if (!all.length || !on.length) return null;
    return on.map(function (b) { return b.value; });
  }

  function apply() {
    var needle = (q.value || "").trim().toLowerCase();
    var p = allowed("p"), s = allowed("s"), c = allowed("c");
    var shown = 0;
    rows.forEach(function (row) {
      var d = row.dataset;
      var ok = (!p || p.indexOf(d.p) >= 0) &&
               (!s || s.indexOf(d.s) >= 0) &&
               (!c || c.indexOf(d.c) >= 0) &&
               (!needle || d.q.indexOf(needle) >= 0);
      row.classList.toggle("hide", !ok);
      if (ok) shown++;
    });
    count.textContent = shown === rows.length
      ? shown + " finding(s)"
      : "showing " + shown + " of " + rows.length;
    none.hidden = shown > 0;
  }

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
