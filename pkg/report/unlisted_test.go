package report

import (
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
)

// unlistedData is a run over two repositories whose checkouts held a .semgrepignore and a
// .gitleaks.toml with an allowlist.
func unlistedData(repos ...string) Data {
	run := engine.Result{Unlisted: []engine.UnlistedSetAside{
		{Repository: "https://example.com/api.git", File: ".semgrepignore", Scanner: "semgrep"},
		{Repository: "https://example.com/web.git", File: ".gitleaks.toml", Scanner: "gitleaks"},
	}}
	run.Declared.Components = []engine.ComponentDeclaration{{Name: "api", Repositories: repos}}
	return Data{Project: "app", Run: run}
}

// A file that kept findings from a scanner without listing them is named once per repository in
// the console and the Markdown report, with its repository where the run read more than one.
func TestAFileThatKeptFindingsUnlistedIsNamed(t *testing.T) {
	d := unlistedData("https://example.com/api.git", "https://example.com/web.git")
	for _, want := range []string{
		".semgrepignore in api.git  kept some files from semgrep; what it covered is not listed",
		".gitleaks.toml in web.git  its allowlist kept some findings from gitleaks; what it covered is not listed",
	} {
		if out := renderConsole(t, d); !strings.Contains(out, want) {
			t.Errorf("console does not say %q:\n%s", want, out)
		}
	}
	md := renderWith(t, markdownReporter{}, d)
	if want := "| `.semgrepignore in api.git` | kept some files from semgrep; what it covered is not listed |"; !strings.Contains(md, want) {
		t.Errorf("markdown does not say %q:\n%s", want, md)
	}

	// One repository needs no name.
	if rows := unlistedRows(unlistedData("https://example.com/api.git")); len(rows) != 2 || rows[0].where != ".semgrepignore" {
		t.Errorf("rows = %+v", rows)
	}
}

// acceptedNote is the sentence under the HTML report's Accepted heading.
func acceptedNote(t *testing.T, d Data) string {
	t.Helper()
	page := renderWith(t, htmlReporter{}, d)
	return section(t, page, `<summary id="suppressed">`, `</p>`)
}

// Every format names each source of a set-aside the others name, in the same words: a setting's
// key and each file that kept findings from a scanner unlisted, as well as the counted sources. A
// format that leaves one out reads as a run where nothing was set aside that way.
func TestEveryFormatNamesTheSameSetAsides(t *testing.T) {
	d := acceptedRun()
	d.Run.Unlisted = unlistedData().Run.Unlisted
	d.Run.Declared.Components = []engine.ComponentDeclaration{
		{Name: "api", Repositories: []string{"https://example.com/api.git", "https://example.com/web.git"}},
	}
	var sources []unlistedRow
	for _, r := range settingRows(d) {
		sources = append(sources, unlistedRow{where: r.where(), said: r.said()})
	}
	sources = append(sources, unlistedRows(d)...)
	if len(sources) != 3 {
		t.Fatalf("the fixture has %d setting and unlisted rows, want 3: %+v", len(sources), sources)
	}
	console := renderConsole(t, d)
	md := renderWith(t, markdownReporter{}, d)
	note := acceptedNote(t, d)
	for _, s := range sources {
		if !strings.Contains(console, s.where) || !strings.Contains(console, s.said) {
			t.Errorf("console does not name %q, %q:\n%s", s.where, s.said, console)
		}
		if want := "| `" + s.where + "` | " + s.said + " |"; !strings.Contains(md, want) {
			t.Errorf("markdown does not say %q:\n%s", want, md)
		}
		if want := "<code>" + s.where + "</code>: " + s.said + "."; !strings.Contains(note, want) &&
			!strings.Contains(note, `<code class="cmd">`+s.where+"</code>: "+s.said+".") {
			t.Errorf("the HTML report does not say %q:\n%s", want, note)
		}
	}
}

// A run whose only set-aside is a file that kept findings unlisted says so on the HTML report,
// rather than that nothing was set aside or that config.exclude set something aside.
func TestTheHTMLReportNamesAnUnlistedFileOnItsOwn(t *testing.T) {
	note := acceptedNote(t, unlistedData("https://example.com/api.git"))
	for _, want := range []string{
		"<code>.semgrepignore</code>: kept some files from semgrep; what it covered is not listed.",
		"<code>.gitleaks.toml</code>: its allowlist kept some findings from gitleaks; what it covered is not listed.",
	} {
		if !strings.Contains(note, want) {
			t.Errorf("the HTML report does not say %q:\n%s", want, note)
		}
	}
	for _, wrong := range []string{"config.exclude", "Nothing in this run is set aside"} {
		if strings.Contains(note, wrong) {
			t.Errorf("the HTML report says %q:\n%s", wrong, note)
		}
	}
}
