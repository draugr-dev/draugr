package report

import (
	"html/template"
	"io"

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
}

type htmlControl struct {
	Control                     string
	Fail                        bool
	Critical, High, Medium, Low int
}

type htmlFinding struct {
	Priority, Severity, SevClass, Score, RuleID, Control, Tool, Location, Message string
}

func (htmlReporter) Render(w io.Writer, d Data) error {
	s := summarize(d)

	view := htmlView{
		Pass:        s.verdict != norn.Fail,
		Prioritized: s.prioritized,
		P1:          s.p1, P2: s.p2, P3: s.p3, P4: s.p4,
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
		view.Controls = append(view.Controls, htmlControl{
			Control: c.Control, Fail: c.Verdict == norn.Fail,
			Critical: b.critical, High: b.high, Medium: b.medium, Low: b.low,
		})
	}
	for _, f := range s.findings {
		view.Findings = append(view.Findings, htmlFinding{
			Priority: dash(f.priority), Severity: string(f.severity), SevClass: "sev-" + string(f.severity),
			Score: scoreStr(f), RuleID: f.ruleID, Control: f.control, Tool: f.tool,
			Location: dash(f.location), Message: f.message,
		})
	}
	return htmlTemplate.Execute(w, view)
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
  .chips span { display: inline-block; margin-right: 1rem; }
  .p1 { color: #b3261e; font-weight: 700; }
  .p2 { color: #c25e00; font-weight: 600; }
  .sev-critical { color: #b3261e; font-weight: 700; }
  .sev-high { color: #c2410c; font-weight: 600; }
  .sev-medium { color: #b45309; }
  .sev-low { color: #888; }
  footer { color: #888; font-size: .82rem; margin-top: 2rem; }
</style>
</head>
<body>
<h1>Draugr — <span class="verdict {{if .Pass}}pass{{else}}fail{{end}}">{{.Verdict}}</span></h1>
{{if .Release}}<p class="rel">{{.Release}}</p>{{end}}

{{if .Prioritized}}
<p class="chips">
  <span class="p1">P1 {{.P1}}</span>
  <span class="p2">P2 {{.P2}}</span>
  <span>P3 {{.P3}}</span>
  <span>P4 {{.P4}}</span>
</p>
{{end}}

{{if .Controls}}
<h2>Controls</h2>
<table>
<thead><tr><th>Control</th><th>Verdict</th><th class="num">Critical</th><th class="num">High</th><th class="num">Medium</th><th class="num">Low</th></tr></thead>
<tbody>
{{range .Controls}}<tr>
  <td>{{.Control}}</td>
  <td>{{if .Fail}}<strong>FAIL</strong>{{else}}pass{{end}}</td>
  <td class="num">{{.Critical}}</td>
  <td class="num">{{.High}}</td>
  <td class="num">{{.Medium}}</td>
  <td class="num">{{.Low}}</td>
</tr>{{end}}
</tbody>
</table>
{{end}}

<h2>Findings</h2>
{{if .Findings}}
<table>
<thead><tr><th>Priority</th><th>Severity</th><th class="num">Score</th><th>Rule</th><th>Control</th><th>Tool</th><th>Location</th><th>Message</th></tr></thead>
<tbody>
{{range .Findings}}<tr>
  <td>{{.Priority}}</td>
  <td class="{{.SevClass}}">{{.Severity}}</td>
  <td class="num">{{.Score}}</td>
  <td><code>{{.RuleID}}</code></td>
  <td>{{.Control}}</td>
  <td>{{.Tool}}</td>
  <td><code>{{.Location}}</code></td>
  <td>{{.Message}}</td>
</tr>{{end}}
</tbody>
</table>
{{else}}
<p>No findings. ✓</p>
{{end}}

<footer>Generated by Draugr.</footer>
</body>
</html>
`
