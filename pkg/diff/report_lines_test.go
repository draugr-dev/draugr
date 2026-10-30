package diff

import (
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

const (
	repoAPI    = "https://github.com/acme/api.git"
	repoShared = "https://github.com/acme/shared.git"

	shellMsg  = "subprocess call with shell=True identified, security issue."
	injectID  = "python.flask.security.injection.subprocess-injection.subprocess-injection"
	injectMsg = "Detected user input entering a `subprocess` call unsafely."
	evalID    = "python.lang.security.audit.eval-detected.eval-detected"
)

// sastAt is a sast finding at a line, as a merged results.sarif carries it.
func sastAt(tool, rule, component, repo, uri string, line int, msg string) sarif.Result {
	return sarif.Result{
		Control: "sast", Tool: tool, RuleID: rule, Priority: "P2", Level: sarif.LevelError,
		Component: component, Repository: repo, Message: msg,
		Location: sarif.Location{URI: uri, StartLine: line},
	}
}

func renderActions(t *testing.T, format string, r Result) string {
	t.Helper()
	var b strings.Builder
	if err := Render(&b, format, r, Options{View: ViewActions}); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// One new line that two rules flag is one edit, as the scan's fix list counts it, and the row lists
// both rules under the title quoting one of them.
func TestTwoRulesAtOneNewLineAreOneAction(t *testing.T) {
	r := Result{
		New: []sarif.Result{
			sastAt("Bandit", "B602", "api", repoAPI, "app/app.py", 23, shellMsg),
			sastAt("Semgrep OSS", injectID, "api", repoAPI, "app/app.py", 23, injectMsg),
		},
		Rules: map[string]sarif.Rule{"B602": {HelpURI: "https://bandit.readthedocs.io/en/latest/plugins/b602.html"}},
	}
	console := renderActions(t, "console", r)
	for _, want := range []string{
		"1 action clears 2 findings",
		"Fix “subprocess call with shell=True identified, security issue”",
		"control sast · 2 findings",
		"app/app.py:23 · Bandit: B602 · Semgrep: subprocess-injection",
	} {
		if !strings.Contains(console, want) {
			t.Errorf("console: missing %q:\n%s", want, console)
		}
	}
	// One repository and one component: naming either on every row says nothing.
	for _, unwanted := range []string{"acme/api", "component"} {
		if strings.Contains(console, unwanted) {
			t.Errorf("console: %q named where nothing differs:\n%s", unwanted, console)
		}
	}

	md := renderActions(t, "markdown", r)
	for _, want := range []string{
		"### What to do · 1 action clears 2 findings",
		"| Priority | What to do | Control | Findings | Where |",
		"| P2 | Fix “subprocess call with shell=True identified, security issue” | sast | 2 | app/app.py:23 · " +
			"Bandit: [`B602`](https://bandit.readthedocs.io/en/latest/plugins/b602.html) · Semgrep: `subprocess-injection` |",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown: missing %q:\n%s", want, md)
		}
	}
}

// One rule at two new lines is two edits, so two actions.
func TestOneRuleAtTwoNewLinesIsTwoActions(t *testing.T) {
	r := Result{New: []sarif.Result{
		sastAt("Semgrep OSS", evalID, "api", repoAPI, "app/app.py", 30, "Detected the use of eval()."),
		sastAt("Semgrep OSS", evalID, "api", repoAPI, "app/app.py", 31, "Detected the use of eval()."),
	}}
	for _, format := range []string{"console", "markdown"} {
		got := renderActions(t, format, r)
		if !strings.Contains(got, "2 actions clear 2 findings") {
			t.Errorf("%s: one rule at two lines is not two actions:\n%s", format, got)
		}
		for _, want := range []string{"app/app.py:30", "app/app.py:31"} {
			if !strings.Contains(got, want) {
				t.Errorf("%s: missing %q:\n%s", format, want, got)
			}
		}
	}
}

// The same path at the same line in two repositories, and in two components sharing one, is three
// edits by up to three owners. Each row names what tells it apart from the others.
func TestTheSameLineInTwoRepositoriesAndTwoComponents(t *testing.T) {
	r := Result{New: []sarif.Result{
		sastAt("Bandit", "B602", "api", repoAPI, "app/app.py", 23, shellMsg),
		sastAt("Semgrep OSS", injectID, "api", repoAPI, "app/app.py", 23, injectMsg),
		sastAt("Bandit", "B602", "api", repoShared, "app/app.py", 23, shellMsg),
		sastAt("Bandit", "B602", "web", repoShared, "app/app.py", 23, shellMsg),
	}}

	console := renderActions(t, "console", r)
	for _, want := range []string{
		"3 actions clear 4 findings",
		"component api · control sast · 2 findings",
		"component api · control sast · 1 finding",
		"component web · control sast · 1 finding",
		"acme/api app/app.py:23 · Bandit: B602 · Semgrep: subprocess-injection",
		"acme/shared app/app.py:23 · Bandit: B602",
	} {
		if !strings.Contains(console, want) {
			t.Errorf("console: missing %q:\n%s", want, console)
		}
	}
	if n := strings.Count(console, "acme/shared app/app.py:23"); n != 2 {
		t.Errorf("console: the shared repository's line should be two rows, one per component, got %d:\n%s", n, console)
	}

	md := renderActions(t, "markdown", r)
	for _, want := range []string{
		"### What to do · 3 actions clear 4 findings",
		"| Priority | What to do | Component | Control | Findings | Where |",
		"|---|---|---|---|---:|---|",
		"| api | sast | 2 | acme/api app/app.py:23 · Bandit: `B602` · Semgrep: `subprocess-injection` |",
		"| api | sast | 1 | acme/shared app/app.py:23 · Bandit: `B602` |",
		"| web | sast | 1 | acme/shared app/app.py:23 · Bandit: `B602` |",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown: missing %q:\n%s", want, md)
		}
	}
}

// An imported SARIF file names paths and no repository. Its finding at a line joins the others at
// that line, as it does in the scan, rather than standing as a second action for one edit.
func TestAnImportedFindingJoinsItsLine(t *testing.T) {
	r := Result{New: []sarif.Result{
		sastAt("Semgrep OSS", injectID, "api", repoAPI, "app/app.py", 23, injectMsg),
		sastAt("Bandit", "B602", "api", "", "app/app.py", 23, shellMsg),
	}}
	got := renderActions(t, "console", r)
	if !strings.Contains(got, "1 action clears 2 findings") {
		t.Errorf("the imported finding stands apart from its line:\n%s", got)
	}
}

// A line whose acceptance ended, or was taken in this change, asks for a decision rather than an
// edit, and stays apart from the new findings at the same line.
func TestADecisionAboutALineIsItsOwnAction(t *testing.T) {
	r := Result{
		New:        []sarif.Result{sastAt("Bandit", "B602", "api", repoAPI, "app/app.py", 23, shellMsg)},
		Unaccepted: []sarif.Result{sastAt("Semgrep OSS", injectID, "api", repoAPI, "app/app.py", 23, injectMsg)},
		Accepted:   []sarif.Result{sastAt("Semgrep OSS", evalID, "api", repoAPI, "app/app.py", 40, "eval")},
	}
	got := renderActions(t, "console", r)
	for _, want := range []string{
		"3 actions clear 3 findings",
		"Fix “subprocess call with shell=True identified, security issue”",
		"Decide on app/app.py:23 again",
		"Review the acceptance of app/app.py:40",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q:\n%s", want, got)
		}
	}
}

// A line one rule flags, whose description would be cut, is titled by the rule with the
// description whole on the line under it, as the fix list draws it.
func TestALineTitledByItsRuleCarriesTheDescription(t *testing.T) {
	long := "Detected subprocess function 'check_output' with user controlled data and a shell, " +
		"which a malicious actor could leverage to perform command injection"
	r := Result{New: []sarif.Result{
		sastAt("Semgrep OSS", "python.lang.security.dangerous-subprocess-use.dangerous-subprocess-use",
			"api", repoAPI, "app/app.py", 23, long),
	}}
	got := renderActions(t, "console", r)
	for _, want := range []string{"Fix dangerous-subprocess-use", "      " + long + "\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q:\n%s", want, got)
		}
	}
	// The comment carries it in the same cell, after a break that keeps the row one row.
	md := renderActions(t, "markdown", r)
	if !strings.Contains(md, "| P2 | Fix dangerous-subprocess-use<br>"+long+" | sast | 1 |") {
		t.Errorf("markdown: the description is not in the title's cell:\n%s", md)
	}
}

// Every row labels its control, whether or not it names a component, so a reader never meets the
// two forms side by side.
func TestEveryRowLabelsItsControl(t *testing.T) {
	r := Result{New: []sarif.Result{
		{RuleID: "CVE-1", Level: sarif.LevelError, Priority: "P1", Control: "sca", Component: "api",
			Package: &sarif.Package{Name: "urllib3", Version: "2.0.7", FixedVersion: "2.6.0"}},
		sastAt("Bandit", "B602", "web", repoAPI, "app/app.py", 23, shellMsg),
	}}
	got := renderActions(t, "console", r)
	for _, want := range []string{
		"Upgrade urllib3 2.0.7  component api · control sca · 1 finding",
		"component web · control sast · 1 finding",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q:\n%s", want, got)
		}
	}
	single := renderActions(t, "console", Result{New: r.New[:1]})
	if !strings.Contains(single, "Upgrade urllib3 2.0.7  control sca · 1 finding") || strings.Contains(single, "component") {
		t.Errorf("one component: the control is unlabeled or the component named:\n%s", single)
	}
}

// A pipe in a scanner's description would end a markdown cell early and shift every cell after it.
func TestAPipeInATitleStaysInItsCell(t *testing.T) {
	r := Result{New: []sarif.Result{
		sastAt("Semgrep OSS", "shell-pipe", "api", repoAPI, "run.sh", 4, "Output piped with | into sh"),
	}}
	got := renderActions(t, "markdown", r)
	if !strings.Contains(got, `| Fix “Output piped with \| into sh” | sast | 1 | run.sh:4 · Semgrep: `+"`shell-pipe`"+` |`) {
		t.Errorf("the pipe was not escaped:\n%s", got)
	}
}
