package report

import (
	"bytes"
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

func TestConsoleNamesUnreadFilesOncePerComponent(t *testing.T) {
	for name, d := range map[string]Data{"full": goldenGroupedData(), "compact": goldenCompactData()} {
		d.Run.Inputs = unreadInputs()
		out := renderWith(t, consoleReporter{}, d)
		for _, want := range []string{
			"UNREAD  " + unreadNote,
			"internal-tool  acme/admin:package.json no lockfile (sca) · acme/web:package.json no lockfile",
			"payments       app/pyproject.toml no lockfile (licenses, sca) · app/requirements-dev.txt no",
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
	if out := renderWith(t, consoleReporter{}, d); strings.Contains(out, "UNREAD") {
		t.Errorf("a scan that read every file printed the section:\n%s", out)
	}
}

func TestUnreadCountsWhatItDoesNotName(t *testing.T) {
	var unread []engine.UnreadInput
	for _, p := range []string{"a/go.mod", "b/go.mod", "c/go.mod", "d/go.mod", "e/go.mod"} {
		unread = append(unread, engine.UnreadInput{Repository: "r", Path: p, Reason: "no packages read"})
	}
	groups := unreadByComponent([]engine.InputCoverage{{Component: "api", Control: "sca", Unread: unread}})
	got := groups[0].text(unreadShown, func(s string) string { return s })
	if !strings.HasSuffix(got, "c/go.mod no packages read (sca) · +2") || strings.Contains(got, "d/go.mod") {
		t.Errorf("text = %q, want three named and +2", got)
	}
}

// --top 0 asks for everything, and a list it leaves capped would be the one place it was ignored.
func TestConsoleNamesEveryUnreadFileUnderTopZero(t *testing.T) {
	var unread []engine.UnreadInput
	for _, p := range []string{"a/go.mod", "b/go.mod", "c/go.mod", "d/go.mod"} {
		unread = append(unread, engine.UnreadInput{Repository: "r", Path: p, Reason: "no packages read"})
	}
	d := goldenGroupedData()
	d.Run.Inputs = []engine.InputCoverage{{Component: "payments", Control: "sca", Unread: unread}}
	if out := renderWith(t, consoleReporter{}, d); strings.Contains(out, "d/go.mod") || !strings.Contains(out, "+1") {
		t.Errorf("the default view named the fourth file or left it uncounted:\n%s", out)
	}
	d.TopN = -1
	if out := renderWith(t, consoleReporter{}, d); !strings.Contains(out, "d/go.mod") {
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
