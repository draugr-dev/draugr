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
// the scanners Draugr ran, whose row counts only theirs. The rows are a count, and TRY offers the
// evidence, which lists under each where the tool recorded it and why, or that it gave no reason.
func TestAcceptedNamesEachImportedToolApart(t *testing.T) {
	d := importedAsideData()
	out := renderWith(t, consoleReporter{}, d)
	for _, want := range []string{
		"imported bandit       2 findings set aside in the tool",
		"imported Semgrep OSS  1 finding set aside in the tool",
		"scanner exclusions    1 finding suppressed",
		"--evidence",
		"why each imported tool set its findings aside",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "no reason given") {
		t.Errorf("the reasons are printed without --evidence:\n%s", out)
	}

	d.Evidence = true
	out = renderWith(t, consoleReporter{}, d)
	for _, want := range []string{
		"a comment in the code · no reason given · 1 finding · B105",
		"the tool's own settings · reason: cache keys, not passwords · 1 finding · B303",
		"a comment in the code · reason: vetted · 1 finding · python.lang.eval",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "why each imported tool") {
		t.Errorf("TRY offers --evidence to a run that has it:\n%s", out)
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

// The HTML report says what each imported tool set aside beside the other authorities, offers the
// imported tools under Recorded in, and each finding's row names the tool, where it recorded the
// decision and why, or that it gave no reason.
func TestHTMLNamesWhatEachImportedToolSetAside(t *testing.T) {
	out := renderWith(t, htmlReporter{}, importedAsideData())
	for _, want := range []string{
		"imported bandit: 2 findings set aside in the tool.",
		"imported Semgrep OSS: 1 finding set aside in the tool.",
		"Scanner exclusions: 1 finding suppressed.",
		"imported tool",
		"imported bandit, a comment in the code",
		"imported bandit, the tool&#39;s own settings",
		"no reason given",
		"cache keys, not passwords",
	} {
		if !strings.Contains(out, want) {
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
		"| imported bandit | 2 findings set aside in the tool |",
		"| scanner exclusions | 1 finding suppressed |",
		"### Set aside by imported tools",
		"| 1 | imported bandit | a comment in the code | no reason given |",
		`| 1 | imported bandit | the tool's own settings | keys \| not passwords |`,
		"| 1 | imported Semgrep OSS | a comment in the code | vetted |",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown lacks %q:\n%s", want, out)
		}
	}
}
