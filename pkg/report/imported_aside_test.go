package report

import (
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// importedAsideData is a run in which two imported files' tools set findings aside, bandit's in two
// repositories of one component, and gosec, which Draugr ran, set one aside on its own. The engine
// counts all four among the scanners' own exclusions.
func importedAsideData() Data {
	at := func(tool, scanner, repo, rule, file, kind, why string) sarif.Result {
		return sarif.Result{RuleID: rule, Level: sarif.LevelError, Priority: "P1", Component: "app", Repository: repo,
			Tool: tool, Scanner: scanner, Location: sarif.Location{URI: file, StartLine: 3},
			Suppression: &sarif.Suppression{Kind: kind, Justification: why, Origin: map[string]string{
				"inSource": sarif.OriginTool, "external": sarif.OriginScanner}[kind]}}
	}
	results := []sarif.Result{
		at("bandit", sarif.ImportScanner, "one", "B105", "app/config.py", "inSource", ""),
		at("bandit", sarif.ImportScanner, "two", "B303", "app/cache.py", "external", "cache keys, not passwords"),
		at("Semgrep OSS", sarif.ImportScanner, "one", "python.lang.eval", "app/run.py", "inSource", "vetted"),
		at("gosec", "gosec", "one", "G101", "main.go", "inSource", "a test key"),
		{RuleID: "B608", Level: sarif.LevelError, Priority: "P1", Component: "app", Tool: "bandit", Scanner: sarif.ImportScanner,
			Location: sarif.Location{URI: "app/db.py", StartLine: 9}},
	}
	return Data{Project: "app", Run: engine.Result{Silenced: 4, Controls: map[string]plugin.ControlResult{
		"sast": {Control: "sast", Report: sarif.Report{Tool: "bandit", Results: results}},
	}}}
}

// The console's ACCEPTED block names each imported tool on a row of its own, most first, apart from
// the scanners Draugr ran, whose row counts only theirs. Each row says what the tool did and what
// Draugr did with it, and where the reasons are: --evidence lists under it where the tool recorded
// each and why, or that it gave no reason, and that the tool recorded nobody.
func TestAcceptedNamesEachImportedToolApart(t *testing.T) {
	d := importedAsideData()
	out := renderWith(t, consoleReporter{}, d)
	for _, want := range []string{
		"imported bandit       2 findings the tool suppressed, not counted · --evidence lists why",
		"imported Semgrep OSS  1 finding the tool suppressed, not counted · --evidence lists why",
		"scanner exclusions    1 finding suppressed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "no reason given") || strings.Contains(out, "why each imported tool") {
		t.Errorf("the reasons, or a second pointer to them, are printed without --evidence:\n%s", out)
	}

	d.Evidence = true
	out = renderWith(t, consoleReporter{}, d)
	for _, want := range []string{
		"imported bandit       2 findings the tool suppressed, not counted\n",
		"who: not recorded by the tool\n",
		"in a comment in the code · no reason given · 1 finding · B105",
		"in the tool's own settings · reason: cache keys, not passwords · 1 finding · B303",
		"in a comment in the code · reason: vetted · 1 finding · python.lang.eval",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if n := strings.Count(out, "who: not recorded by the tool"); n != 2 {
		t.Errorf("who is said %d times, want once under each tool:\n%s", n, out)
	}
}

// A tool with a long name keeps its ACCEPTED rows within 100 columns: where the pointer to the
// reasons does not fit on a row, it is the line under it rather than off the edge of the screen.
func TestAnImportedToolsRowFitsWithALongName(t *testing.T) {
	d := importedAsideData()
	for i := range d.Run.Controls["sast"].Report.Results {
		r := &d.Run.Controls["sast"].Report.Results[i]
		if r.Tool == "bandit" {
			r.Tool = "Fortify Static Code Analyzer"
		}
	}
	out := renderWith(t, consoleReporter{}, d)
	block := out[strings.Index(out, "ACCEPTED"):]
	block = block[:strings.Index(block, "\n\n")]
	for _, line := range strings.Split(block, "\n") {
		if n := len([]rune(line)); n > 100 {
			t.Errorf("%q is %d columns, over 100", line, n)
		}
	}
	for _, want := range []string{
		"imported Fortify Static Code Analyzer  2 findings the tool suppressed, not counted\n",
		"--evidence lists why\n",
	} {
		if !strings.Contains(block, want) {
			t.Errorf("ACCEPTED lacks %q:\n%s", want, block)
		}
	}
	if strings.Count(block, "--evidence lists why") != 2 {
		t.Errorf("want the pointer once per tool, under the long name's row and on the short one's:\n%s", block)
	}
}

// The rows and the scanner exclusions line together count what the engine counted, and a report
// built from a count alone, with no results to tell them apart, keeps the one line it always had.
func TestImportedRowsAndScannerExclusionsSumToTheEnginesCount(t *testing.T) {
	d := importedAsideData()
	n := nativeSilenced(d)
	for _, row := range toolAsides(d) {
		n += row.n
	}
	if n != d.Run.Silenced {
		t.Errorf("rows sum to %d, the engine counted %d", n, d.Run.Silenced)
	}
	if got := silencedLine(Data{Run: engine.Result{Silenced: 3}}); got != "scanner exclusions: 3 findings suppressed" {
		t.Errorf("silencedLine = %q", got)
	}
}

// The HTML report says what each imported tool suppressed beside the other authorities, offers the
// imported tools under Recorded in, and each finding's row names the tool, where it recorded the
// suppression and why, or that it gave no reason, and that it recorded nobody.
func TestHTMLNamesWhatEachImportedToolSetAside(t *testing.T) {
	out := renderWith(t, htmlReporter{}, importedAsideData())
	for _, want := range []string{
		"imported bandit: 2 findings the tool suppressed, not counted.",
		"imported Semgrep OSS: 1 finding the tool suppressed, not counted.",
		"Scanner exclusions: 1 finding suppressed.",
		"imported tool",
		"imported bandit, suppressed in a comment in the code",
		"imported bandit, suppressed in the tool&#39;s own settings",
		"no reason given",
		`<span class="lbl">who</span> <span class="none">not recorded by the tool</span>`,
		"cache keys, not passwords",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML lacks %q", want)
		}
	}
}

// githubAsideData is a run that imported a repository's code-scanning alerts, two of which people
// dismissed in GitHub, and a SARIF file whose tool suppressed one finding.
func githubAsideData() Data {
	dismissed := func(rule, file, who, why string) sarif.Result {
		return sarif.Result{RuleID: rule, Level: sarif.LevelWarning, Priority: "P2", Component: "app", Tool: "CodeQL",
			Scanner: sarif.ImportScanner, ImportFormat: "github-code-scanning", Location: sarif.Location{URI: file, StartLine: 4},
			Suppression: &sarif.Suppression{Kind: "external", Origin: sarif.OriginScanner, Justification: why, Author: who,
				Service: "GitHub code scanning", Source: "https://github.com/acme/app/security/code-scanning/1"}}
	}
	results := []sarif.Result{
		dismissed("go/path-injection", "cmd/main.go", "octocat", "false positive (the path is a constant)"),
		dismissed("go/sql-injection", "db/query.go", "monalisa", "won't fix"),
		{RuleID: "B105", Level: sarif.LevelError, Component: "app", Tool: "bandit", Scanner: sarif.ImportScanner,
			Location: sarif.Location{URI: "app/config.py"}, Suppression: &sarif.Suppression{Kind: "inSource", Origin: sarif.OriginTool}},
	}
	return Data{Project: "app", Evidence: true, Run: engine.Result{Silenced: 3, Controls: map[string]plugin.ControlResult{
		"sast": {Control: "sast", Report: sarif.Report{Results: results}},
	}}}
}

// An alert a person dismissed in GitHub is set aside under the imported tool's row, and each reason
// names who dismissed it, so the line saying the tool recorded nobody is left out where every reason
// names someone. The markdown table and the HTML row name them too.
func TestAnAlertDismissedInGitHubNamesWhoDismissedIt(t *testing.T) {
	d := githubAsideData()
	out := renderWith(t, consoleReporter{}, d)
	for _, want := range []string{
		"imported CodeQL (github-code-scanning)",
		"dismissed in GitHub code scanning by octocat · reason: false positive (the path is a constant) · 1 finding · go/path-injection",
		"dismissed in GitHub code scanning by monalisa · reason: won't fix · 1 finding · go/sql-injection",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if n := strings.Count(out, "who: not recorded by the tool"); n != 1 {
		t.Errorf("who is said unrecorded %d times, want only under bandit:\n%s", n, out)
	}

	md := renderWith(t, markdownReporter{}, d)
	if want := "| 1 | imported CodeQL (github-code-scanning) | dismissed in GitHub code scanning | won't fix | monalisa |"; !strings.Contains(md, want) {
		t.Errorf("markdown lacks %q:\n%s", want, md)
	}
	html := renderWith(t, htmlReporter{}, d)
	for _, want := range []string{
		"imported CodeQL (github-code-scanning), dismissed in GitHub code scanning",
		`<span class="lbl">who</span> octocat`,
		`<span class="lbl">who</span> <span class="none">not recorded by the tool</span>`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML lacks %q", want)
		}
	}
}

// The markdown report counts each imported tool in its Accepted table and lists where and why in a
// table of its own, a cell per reason, the file's text kept from breaking the table.
func TestMarkdownListsWhereAndWhyEachImportedToolSetFindingsAside(t *testing.T) {
	d := importedAsideData()
	d.Run.Controls["sast"].Report.Results[1].Suppression.Justification = "keys | not passwords"
	out := renderWith(t, markdownReporter{}, d)
	for _, want := range []string{
		"| imported bandit | 2 findings the tool suppressed, not counted |",
		"| scanner exclusions | 1 finding suppressed |",
		"### Set aside by imported tools",
		"| Findings | Tool | Suppressed | Reason | Who |",
		"| 1 | imported bandit | in a comment in the code | no reason given | not recorded by the tool |",
		`| 1 | imported bandit | in the tool's own settings | keys \| not passwords | not recorded by the tool |`,
		"| 1 | imported Semgrep OSS | in a comment in the code | vetted | not recorded by the tool |",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown lacks %q:\n%s", want, out)
		}
	}
}
