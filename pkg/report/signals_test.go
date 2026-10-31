package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A signal listed without its rule is a count a reader cannot interpret: "2 findings raised" says
// nothing to somebody who does not know KEV takes a finding straight to critical while EPSS raises
// it one band. Every report draws its Signals rows from signalKinds, so holding every entry there to
// a movement and a condition is what keeps a new signal from shipping without one.
func TestEverySignalSaysHowItMovesAFinding(t *testing.T) {
	runs := map[string]Data{
		"no settings recorded": {},
		"an EPSS threshold":    {Run: engine.Result{Consulted: []sarif.Consulted{{Signal: "epss", Threshold: 0.2}}}},
	}
	seen := map[string]bool{}
	for _, k := range signalKinds {
		if k.name == "" || k.moves == nil || k.did == nil {
			t.Fatalf("signal %+v is missing its name, its movement or what it did", k)
		}
		if seen[k.name] {
			t.Errorf("%s is listed twice", k.name)
		}
		seen[k.name] = true
		for run, d := range runs {
			m := k.moves(d)
			if m.Change == "" || m.Condition == "" {
				t.Errorf("%s, %s: moves = %+v, want a change and the condition it applies under", k.name, run, m)
			}
			if m.Glyph() != "↑" && m.Glyph() != "↓" {
				t.Errorf("%s: glyph %q", k.name, m.Glyph())
			}
		}
	}
}

// signalData is a run in which every signal the section can list has something to say: both feeds
// consulted, one finding raised by each, a floor control that floored one of its two findings, and
// a reachability analyzer, with the threshold given.
func signalData(threshold float64) Data {
	return Data{
		Exploitability: []FeedProvenance{{Name: "kev"}, {Name: "epss"}},
		Run: engine.Result{
			Consulted:     []sarif.Consulted{{Signal: "kev"}, {Signal: "epss", Threshold: threshold}},
			ContextFloors: []string{"secrets"},
			Controls: map[string]plugin.ControlResult{
				"sca": {Control: "sca", Report: sarif.Report{Tool: "trivy", Results: []sarif.Result{
					{RuleID: "CVE-2024-3094", Level: sarif.LevelError, Priority: "P1", Component: "api",
						Escalation: &sarif.Escalation{Signal: "kev", From: "high", To: "critical"}},
					{RuleID: "CVE-2019-20477", Level: sarif.LevelWarning, Priority: "P2", Component: "worker",
						Escalation: &sarif.Escalation{Signal: "epss", From: "medium", To: "high", Detail: "EPSS 0.87"}},
				}}},
				"secrets": {Control: "secrets", Report: sarif.Report{Tool: "gitleaks", Results: []sarif.Result{
					{RuleID: "generic-api-key", Level: sarif.LevelError, Priority: "P1", Component: "api"},
					{RuleID: "generic-api-key", Level: sarif.LevelError, Priority: "P1", Component: "worker",
						PriorityFloor: "a leaked credential is high priority wherever it is found"},
				}}},
			},
			Reachability: engine.ReachabilitySummary{
				Analyzers: []engine.AnalyzerReachability{{Analyzer: "govulncheck", Reachable: 2, Unreachable: 3, Unknown: 1}},
				Reachable: 2, Unreachable: 3, Unknown: 1,
			},
		},
	}
}

// The HTML report puts each signal's rule between its name and what it did, inside the mark a
// finding row wears for the same movement, so a reader can match the rule to the rows it marked.
func TestTheHTMLSignalsSayHowEachOneMovesAFinding(t *testing.T) {
	var b bytes.Buffer
	if err := (htmlReporter{}).Render(&b, signalData(0.5)); err != nil {
		t.Fatal(err)
	}
	page := b.String()
	for _, want := range []string{
		`<th scope="col">Signal</th><th scope="col">How it moves a finding</th><th scope="col">This run</th>`,
		`<td><code>KEV</code></td><td class="how"><span class="moved up"><span class="g">↑</span>severity to critical</span> ` +
			`when it is on CISA&#39;s Known Exploited Vulnerabilities catalog</td><td>1 finding raised</td>`,
		`<td><code>EPSS</code></td><td class="how"><span class="moved up"><span class="g">↑</span>severity one band</span> ` +
			`when its predicted exploitation is at or above <code>0.5</code>, this run&#39;s threshold</td><td>1 finding raised</td>`,
		`<td><code>floor</code></td><td class="how"><span class="moved up"><span class="g">↑</span>priority to P1</span> ` +
			`for a leaked credential, whatever its component declares; severity unchanged</td>` +
			`<td>1 finding raised by a control&#39;s own rule</td>`,
		`<td><code>reachability</code></td><td class="how"><span class="moved down"><span class="g">↓</span>severity one band</span> ` +
			`when analysis finds no path from your code to it</td><td>govulncheck · 2 reachable, 3 unreachable, 1 unknown</td>`,
		// The qualifier the console prints under the rows, which the page prints under its table.
		`<p class="note">Unknown means no analyzer covered it. Those are ranked as reported.</p>`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the html report is missing\n%s", want)
		}
	}
}

// The markdown report carries the same rule in the same words, with the movement in bold where
// the HTML report draws the mark.
func TestTheMarkdownSignalsSayHowEachOneMovesAFinding(t *testing.T) {
	var b bytes.Buffer
	if err := (markdownReporter{}).Render(&b, signalData(0.5)); err != nil {
		t.Fatal(err)
	}
	want := "### Signals\n\n" +
		"| Signal | How it moves a finding | This run |\n" +
		"|---|---|---|\n" +
		"| KEV | **↑ severity to critical** when it is on CISA's Known Exploited Vulnerabilities catalog | 1 finding raised |\n" +
		"| EPSS | **↑ severity one band** when its predicted exploitation is at or above `0.5`, this run's threshold | 1 finding raised |\n" +
		"| floor | **↑ priority to P1** for a leaked credential, whatever its component declares; severity unchanged | 1 finding raised by a control's own rule |\n" +
		"| reachability | **↓ severity one band** when analysis finds no path from your code to it | govulncheck · 2 reachable, 3 unreachable, 1 unknown |\n" +
		"\n_Unknown means no analyzer covered it. Those are ranked as reported._\n"
	if !strings.Contains(b.String(), want) {
		t.Errorf("markdown signals:\n%s\nwant:\n%s", b.String(), want)
	}
}

// The threshold printed is the one the run measured against. A report that printed the default
// beside a run with another would explain a band by a rule the run did not apply.
func TestTheEPSSRowStatesTheThresholdTheRunUsed(t *testing.T) {
	for _, tc := range []struct {
		name string
		d    Data
		html string
		md   string
	}{
		{
			name: "a threshold the descriptor set",
			d:    signalData(0.1),
			html: `at or above <code>0.1</code>, this run&#39;s threshold</td>`,
			md:   "at or above `0.1`, this run's threshold |",
		},
		{
			// Zero turns the raise off while keeping KEV, and "at or above 0" alone reads as every
			// finding.
			name: "a threshold of zero",
			d:    signalData(0),
			html: `at or above <code>0</code>, this run&#39;s threshold, which turns it off</td>`,
			md:   "at or above `0`, this run's threshold, which turns it off |",
		},
		{
			// A caller that did not record what it consulted gets no number rather than a guessed one.
			name: "no threshold recorded",
			d: func() Data {
				d := signalData(0.5)
				d.Run.Consulted = nil
				return d
			}(),
			html: `when its predicted exploitation is at or above this run&#39;s threshold</td>`,
			md:   "when its predicted exploitation is at or above this run's threshold |",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var page, md bytes.Buffer
			if err := (htmlReporter{}).Render(&page, tc.d); err != nil {
				t.Fatal(err)
			}
			if err := (markdownReporter{}).Render(&md, tc.d); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(page.String(), tc.html) {
				t.Errorf("html EPSS row does not end %q", tc.html)
			}
			if !strings.Contains(md.String(), tc.md) {
				t.Errorf("markdown EPSS row does not end %q:\n%s", tc.md, md.String())
			}
		})
	}
}

// The floor is listed whenever a control that declares one ran, the way KEV and EPSS are listed
// whenever they were consulted: "nothing raised" is a result, and a missing row cannot be told
// from a floor that was never applied.
func TestTheFloorRowIsListedWheneverAFloorControlRan(t *testing.T) {
	// Only the public, critical component's secret, which the floor had nothing to raise.
	unfloored := func() Data {
		d := signalData(0.5)
		secrets := d.Run.Controls["secrets"]
		secrets.Report.Results = secrets.Report.Results[:1]
		d.Run.Controls["secrets"] = secrets
		return d
	}
	floored := signalData(0.5)
	clean := unfloored()
	absent := signalData(0.5)
	delete(absent.Run.Controls, "secrets")
	undeclared := unfloored()
	undeclared.Run.ContextFloors = nil

	for _, tc := range []struct {
		name string
		d    Data
		want string // the floor row, or "" for none
	}{
		{"a floor that raised one finding", floored, "floor         1 finding raised by a control's own rule"},
		{"a floor that raised nothing", clean, "floor         nothing raised"},
		{"no floor control ran", absent, ""},
		{"the run did not record its floors", undeclared, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			if err := (consoleReporter{}).Render(&b, tc.d); err != nil {
				t.Fatal(err)
			}
			out := b.String()
			if tc.want == "" {
				if strings.Contains(out, "  floor ") {
					t.Errorf("a floor row with no floor control in the run:\n%s", out)
				}
				return
			}
			if !strings.Contains(out, "\n  "+tc.want+"\n") {
				t.Errorf("console signals want %q:\n%s", tc.want, out)
			}
		})
	}
}

// A floor that raised findings is listed even when the run did not record its floors, such as a
// report built by a caller that ranks without enrich.Load. The count alone shows a floor applied.
func TestAFloorThatRaisedIsListedWithoutTheRunsFloors(t *testing.T) {
	d := signalData(0.5)
	d.Run.ContextFloors = nil
	rows, _ := signals(d, summarize(d))
	for _, r := range rows {
		if r.Name == "floor" {
			if r.Did != "1 finding raised by a control's own rule" {
				t.Errorf("floor did = %q", r.Did)
			}
			return
		}
	}
	t.Errorf("no floor row in %+v", rows)
}

// healthData is a run whose dependency-health lookup raised one of two components' findings as
// deprecated, and found nothing malicious.
func healthData(recorded bool) Data {
	d := Data{Run: engine.Result{Controls: map[string]plugin.ControlResult{
		"sca": {Control: "sca", Report: sarif.Report{Tool: "trivy", Results: []sarif.Result{
			{RuleID: "NSWG-ECO-328", Level: sarif.LevelWarning, Priority: "P2", Component: "web",
				Escalation: &sarif.Escalation{Signal: "deprecated", From: "medium", To: "high"}},
			{RuleID: "CVE-2019-20477", Level: sarif.LevelWarning, Priority: "P3", Component: "api"},
		}}},
	}}}
	if recorded {
		d.Run.Consulted = []sarif.Consulted{{Signal: "dependency-health", AsOf: "2026-10-31", Entries: 2}}
	}
	return d
}

// Dependency health's two signals are listed whenever its lookup answered, each with what it raised,
// in every report: "nothing raised" for malicious is a result, and a missing row cannot be told from
// a run that never asked.
func TestDependencyHealthIsListedWheneverItsLookupAnswered(t *testing.T) {
	var console, page, md bytes.Buffer
	d := healthData(true)
	if err := (consoleReporter{}).Render(&console, d); err != nil {
		t.Fatal(err)
	}
	if err := (htmlReporter{}).Render(&page, d); err != nil {
		t.Fatal(err)
	}
	if err := (markdownReporter{}).Render(&md, d); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"\n  malicious   nothing raised\n", "\n  deprecated  1 finding raised\n"} {
		if !strings.Contains(console.String(), want) {
			t.Errorf("console signals want %q:\n%s", want, console.String())
		}
	}
	for _, want := range []string{
		`<td><code>malicious</code></td><td class="how"><span class="moved up"><span class="g">↑</span>severity to critical</span> ` +
			`when the package is in the OSSF Malicious Packages Project</td><td>nothing raised</td>`,
		`<td><code>deprecated</code></td><td class="how"><span class="moved up"><span class="g">↑</span>severity one band</span> ` +
			`when the publisher has marked the version as no longer supported</td><td>1 finding raised</td>`,
	} {
		if !strings.Contains(page.String(), want) {
			t.Errorf("the html report is missing\n%s", want)
		}
	}
	for _, want := range []string{
		"| malicious | **↑ severity to critical** when the package is in the OSSF Malicious Packages Project | nothing raised |\n",
		"| deprecated | **↑ severity one band** when the publisher has marked the version as no longer supported | 1 finding raised |\n",
	} {
		if !strings.Contains(md.String(), want) {
			t.Errorf("markdown signals want %q:\n%s", want, md.String())
		}
	}
}

// A run that did not ask lists neither. One whose caller ranked with dependency health without
// recording the lookup still lists the signal that raised something, because the count alone shows
// it applied, and leaves out the one it cannot vouch for.
func TestDependencyHealthIsLeftOutWhenNothingSaysItRan(t *testing.T) {
	names := func(d Data) map[string]string {
		rows, _ := signals(d, summarize(d))
		out := map[string]string{}
		for _, r := range rows {
			out[r.Name] = r.Did
		}
		return out
	}
	off := healthData(false)
	sca := off.Run.Controls["sca"]
	sca.Report.Results[0].Escalation = nil
	off.Run.Controls["sca"] = sca
	if got := names(off); got["malicious"] != "" || got["deprecated"] != "" {
		t.Errorf("a run that never asked lists %v", got)
	}
	if got := names(healthData(false)); got["deprecated"] != "1 finding raised" || got["malicious"] != "" {
		t.Errorf("an unrecorded lookup that raised one finding: %v", got)
	}
}
