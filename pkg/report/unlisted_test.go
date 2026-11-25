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
