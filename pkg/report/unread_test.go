package report

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
)

// Two components, one of them drawing on two repositories that each hold a package.json, and one
// file two controls missed. Each collapse the section could make is present: a file named twice, a
// path that could belong to either repository, and a component's files split across lines.
func unreadInputs() []engine.InputCoverage {
	return []engine.InputCoverage{
		{Component: "internal-tool", Control: "sca", Scanners: []string{"trivy-fs"}, Read: 1,
			Unread: []engine.UnreadInput{
				{Repository: "https://github.com/acme/admin", Path: "package.json", Reason: "no lockfile"},
				{Repository: "https://github.com/acme/web", Path: "package.json", Reason: "no lockfile"},
			}},
		{Component: "payments", Control: "licenses", Scanners: []string{"trivy-license"}, Read: 3,
			Unread: []engine.UnreadInput{
				{Repository: "https://github.com/acme/payments", Path: "app/pyproject.toml", Reason: "no lockfile"},
				{Repository: "https://github.com/acme/payments", Path: "app/requirements-dev.txt", Reason: "no packages read"},
			}},
		{Component: "payments", Control: "sca", Scanners: []string{"grype-fs", "trivy-fs"}, Read: 4,
			Unread: []engine.UnreadInput{
				{Repository: "https://github.com/acme/payments", Path: "app/pyproject.toml", Reason: "no lockfile"},
			}},
	}
}

func renderWith(t *testing.T, r Reporter, d Data) string {
	t.Helper()
	var b bytes.Buffer
	if err := r.Render(&b, d); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// Each unread file is a caveat row under its component, named once however many controls missed
// it, and prefixed with its repository where the component draws on two.
func TestConsoleNamesUnreadFilesOncePerComponent(t *testing.T) {
	for name, d := range map[string]Data{"full": goldenGroupedData(), "compact": goldenCompactData()} {
		d.Run.Inputs = unreadInputs()
		out := renderWith(t, consoleReporter{}, d)
		for _, want := range []string{
			"CAVEATS  do not fail the run · config.gate.failOnCaveats lists the kinds that do",
			"internal-tool  acme/admin:package.json   unread-files  no lockfile (sca)",
			"internal-tool  acme/web:package.json     unread-files  no lockfile (sca)",
			"payments       app/pyproject.toml        unread-files  no lockfile (licenses, sca)",
			"payments       app/requirements-dev.txt  unread-files  no packages read (licenses)",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("%s view is missing %q:\n%s", name, want, out)
			}
		}
		if n := strings.Count(out, "app/pyproject.toml"); n != 1 {
			t.Errorf("%s view names app/pyproject.toml %d times, want once", name, n)
		}
	}
}

func TestConsoleSaysNothingWhenEveryFileWasRead(t *testing.T) {
	d := goldenGroupedData()
	d.Run.Inputs = []engine.InputCoverage{{Component: "payments", Control: "sca", Scanners: []string{"trivy-fs"}, Read: 3}}
	if out := renderWith(t, consoleReporter{}, d); strings.Contains(out, "CAVEATS") {
		t.Errorf("a scan that read every file printed the section:\n%s", out)
	}
}

func TestUnreadCountsWhatItDoesNotName(t *testing.T) {
	var unread []engine.UnreadInput
	for _, p := range []string{"a/go.mod", "b/go.mod", "c/go.mod", "d/go.mod", "e/go.mod"} {
		unread = append(unread, engine.UnreadInput{Repository: "r", Path: p, Reason: "no packages read"})
	}
	groups := unreadByComponent([]engine.InputCoverage{{Component: "api", Control: "sca", Unread: unread}}, nil)
	got := groups[0].text(unreadShown, func(s string) string { return s })
	if !strings.HasSuffix(got, "c/go.mod no packages read (sca) · +2") || strings.Contains(got, "d/go.mod") {
		t.Errorf("text = %q, want three named and +2", got)
	}
}

// --top 0 asks for everything, and a list it leaves capped would be the one place it was ignored.
func TestConsoleNamesEveryUnreadFileUnderTopZero(t *testing.T) {
	var unread []engine.UnreadInput
	for i := range errorRowsShown + 2 {
		unread = append(unread, engine.UnreadInput{Repository: "r", Path: fmt.Sprintf("m%02d/go.mod", i), Reason: "no packages read"})
	}
	d := goldenGroupedData()
	d.Run.Inputs = []engine.InputCoverage{{Component: "payments", Control: "sca", Unread: unread}}
	last := fmt.Sprintf("m%02d/go.mod", errorRowsShown+1)
	if out := renderWith(t, consoleReporter{}, d); strings.Contains(out, last) || !strings.Contains(out, "… and 2 more · --top 0 lists every one") {
		t.Errorf("the default view named the last file or left it uncounted:\n%s", out)
	}
	d.TopN = -1
	if out := renderWith(t, consoleReporter{}, d); !strings.Contains(out, last) || strings.Contains(out, "more · --top 0") {
		t.Errorf("--top 0 left a file unnamed:\n%s", out)
	}
}

func TestMarkdownNamesUnreadFiles(t *testing.T) {
	d := goldenGroupedData()
	d.Run.Inputs = unreadInputs()
	out := renderWith(t, markdownReporter{}, d)
	for _, want := range []string{
		"**Unread** · " + unreadNote,
		"- `payments` · `app/pyproject.toml` no lockfile (licenses, sca) · `app/requirements-dev.txt` no packages read (licenses)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown is missing %q:\n%s", want, out)
		}
	}
	d.Run.Inputs = nil
	if out := renderWith(t, markdownReporter{}, d); strings.Contains(out, "**Unread**") {
		t.Error("markdown printed the section with nothing unread")
	}
}

// repositoryTargets is a planned repository target for each source, declared by component.
func repositoryTargets(component string, sources ...string) []engine.TargetOutcome {
	var out []engine.TargetOutcome
	for _, s := range sources {
		out = append(out, engine.TargetOutcome{Kind: "repository", Target: s, Status: engine.TargetReached,
			Components: []string{component}})
	}
	return out
}

// A component scanning two repositories names the repository of an unread file even when the other
// repository's files were all read, in the console and in markdown: a bare bun.lock could be in
// either. One repository scanned at two revisions is still one repository, and keeps the bare path.
func TestUnreadNamesTheRepositoryWhereTheComponentScansTwo(t *testing.T) {
	inputs := []engine.InputCoverage{{Component: "both", Control: "sca", Scanners: []string{"trivy-fs"}, Read: 1,
		Unread: []engine.UnreadInput{{Repository: "https://github.com/acme/remote", Path: "bun.lock", Reason: "no packages read"}}}}
	for name, c := range map[string]struct {
		targets []engine.TargetOutcome
		label   string
	}{
		"two repositories, one unread": {
			targets: repositoryTargets("both", "https://github.com/acme/remote", "https://github.com/acme/registry"),
			label:   "acme/remote:bun.lock",
		},
		"one repository at two revisions": {
			targets: repositoryTargets("both", "https://github.com/acme/remote@a1b2c3", "https://github.com/acme/remote@d4e5f6"),
			label:   "bun.lock",
		},
		"no targets recorded": {label: "bun.lock"},
	} {
		d := goldenGroupedData()
		d.Run.Inputs = inputs
		d.Run.Targets = c.targets
		row := regexp.MustCompile(`(?m)^\s+both\s+` + regexp.QuoteMeta(c.label) + `\s+unread-files\s+no packages read \(sca\)$`)
		if out := renderWith(t, consoleReporter{}, d); !row.MatchString(out) {
			t.Errorf("%s: console has no row labeling the file %q:\n%s", name, c.label, out)
		}
		md := "- `both` · `" + c.label + "` no packages read (sca)"
		if out := renderWith(t, markdownReporter{}, d); !strings.Contains(out, md) {
			t.Errorf("%s: markdown is missing %q:\n%s", name, md, out)
		}
	}
}

// A target another component declared does not make this one's repositories several.
func TestRepositoriesAreCountedPerComponent(t *testing.T) {
	targets := append(repositoryTargets("api", "https://github.com/acme/api"),
		repositoryTargets("web", "https://github.com/acme/web")...)
	targets = append(targets, engine.TargetOutcome{Kind: "image", Target: "ghcr.io/acme/api:1", Components: []string{"api"}})
	got := repositoriesByComponent(targets)
	if got["api"] != 1 || got["web"] != 1 {
		t.Errorf("repositoriesByComponent = %v, want one each", got)
	}
}
