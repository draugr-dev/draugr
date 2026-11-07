package report

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/saga"
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

// Each unread file is a caveat row under its component and the controls that missed it, named once
// however many controls missed it, and prefixed with its repository where the component draws on
// two.
func TestConsoleNamesUnreadFilesOncePerComponent(t *testing.T) {
	for name, d := range map[string]Data{"full": goldenGroupedData(), "compact": goldenCompactData()} {
		d.Run.Inputs = unreadInputs()
		out := renderWith(t, consoleReporter{}, d)
		header, groups, _ := consoleCaveats(t, out)
		if want := "CAVEATS  do not fail the run · config.gate.failOnCaveats lists the kinds that do"; header != want {
			t.Errorf("%s view: header = %q, want %q", name, header, want)
		}
		want := []consoleCaveatGroup{
			{heading: "unread-files · licenses · payments", rows: []string{"app/requirements-dev.txt no packages read"}},
			{heading: "unread-files · licenses, sca · payments", rows: []string{"app/pyproject.toml no lockfile"}},
			{heading: "unread-files · sca · internal-tool", rows: []string{
				"acme/admin:package.json no lockfile", "acme/web:package.json no lockfile"}},
		}
		if !reflect.DeepEqual(groups, want) {
			t.Errorf("%s view: groups = %+v\nwant %+v:\n%s", name, groups, want, out)
		}
		if n := strings.Count(out, "app/pyproject.toml"); n != 1 {
			t.Errorf("%s view names app/pyproject.toml %d times, want once", name, n)
		}
	}
}

// One file two controls give different reasons for keeps a row per reason, since each reason names
// what clears it for its own controls. Two components in two repositories, so the rows of one cannot
// stand for the other's.
func TestConsoleKeepsARowPerReasonForOneFile(t *testing.T) {
	const resolve = "transitive dependencies not resolved, run mvn dependency:resolve"
	const grype = "transitive dependencies not read by Grype"
	d := goldenGroupedData()
	d.Run.Inputs = []engine.InputCoverage{
		{Component: "api", Control: "licenses", Unread: []engine.UnreadInput{{Repository: "api", Path: "pom.xml", Reason: resolve}}},
		{Component: "api", Control: "sca", Unread: []engine.UnreadInput{{Repository: "api", Path: "pom.xml", Reason: grype}}},
		{Component: "worker", Control: "licenses", Unread: []engine.UnreadInput{{Repository: "worker", Path: "pom.xml", Reason: resolve}}},
		{Component: "worker", Control: "sca", Unread: []engine.UnreadInput{{Repository: "worker", Path: "pom.xml", Reason: resolve}}},
	}
	out := renderWith(t, consoleReporter{}, d)
	_, groups, _ := consoleCaveats(t, out)
	want := []consoleCaveatGroup{
		{heading: "unread-files · licenses · api", rows: []string{"pom.xml " + resolve}},
		{heading: "unread-files · licenses, sca · worker", rows: []string{"pom.xml " + resolve}},
		{heading: "unread-files · sca · api", rows: []string{"pom.xml " + grype}},
	}
	if !reflect.DeepEqual(groups, want) {
		t.Errorf("groups = %+v\nwant %+v:\n%s", groups, want, out)
	}
	if n := strings.Count(out, "pom.xml"); n != 3 {
		t.Errorf("console names pom.xml %d times, want 3:\n%s", n, out)
	}
}

func TestConsoleSaysNothingWhenEveryFileWasRead(t *testing.T) {
	d := goldenGroupedData()
	d.Run.Inputs = []engine.InputCoverage{{Component: "payments", Control: "sca", Scanners: []string{"trivy-fs"}, Read: 3}}
	if out := renderWith(t, consoleReporter{}, d); strings.Contains(out, "CAVEATS") {
		t.Errorf("a scan that read every file printed the section:\n%s", out)
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

// Markdown lists every unread file, each once under its component, as the console does.
func TestMarkdownNamesUnreadFiles(t *testing.T) {
	d := goldenGroupedData()
	d.Run.Inputs = unreadInputs()
	out := renderWith(t, markdownReporter{}, d)
	payments := section(t, out, "**payments**", "\n\n#")
	for _, want := range []string{
		"- `unread-files` · `app/pyproject.toml` · no lockfile (licenses, sca)",
		"- `unread-files` · `app/requirements-dev.txt` · no packages read (licenses)",
	} {
		if !strings.Contains(payments, want) {
			t.Errorf("markdown is missing %q under payments:\n%s", want, out)
		}
	}
	if n := strings.Count(out, "app/pyproject.toml"); n != 1 {
		t.Errorf("markdown names app/pyproject.toml %d times, want once:\n%s", n, out)
	}
	d.Run.Inputs = nil
	if out := renderWith(t, markdownReporter{}, d); strings.Contains(out, "### Caveats") {
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
		out := renderWith(t, consoleReporter{}, d)
		_, groups, _ := consoleCaveats(t, out)
		want := []consoleCaveatGroup{{heading: "unread-files · sca · both", rows: []string{c.label + " no packages read"}}}
		if !reflect.DeepEqual(groups, want) {
			t.Errorf("%s: console has no row labeling the file %q:\n%s", name, c.label, out)
		}
		md := "- `unread-files` · `" + c.label + "` · no packages read (sca)"
		if out := renderWith(t, markdownReporter{}, d); !strings.Contains(out, md) {
			t.Errorf("%s: markdown is missing %q:\n%s", name, md, out)
		}
	}
}

// A file one scanner of a control read and another did not is a line of the evidence naming the
// scanner and its reason, and neither a caveat nor something the gate fails on. A file no scanner of
// a control read stays a caveat, with Trivy's parse error cut to the column and the control after it
// kept. Two components over two repositories: the shared repository's file is named under both,
// with its repository where the component scans two.
func TestAFileAnotherScannerReadIsEvidenceAndNotACaveat(t *testing.T) {
	const (
		gradle   = "https://github.com/acme/gradle"
		bun      = "https://github.com/acme/bun"
		notReadT = `not parsed: JSON decode error: json: cannot unmarshal JSON string into Go map[string]interface {} within "/packages/left-pad"`
	)
	buildscript := engine.MissedInput{Repository: gradle, Path: "buildscript-gradle.lockfile",
		Scanner: "grype-fs", Reason: "no packages read"}
	inputs := []engine.InputCoverage{
		{Component: "android", Control: "sca", Scanners: []string{"grype-fs", "trivy-fs"}, Read: 2,
			Missed: []engine.MissedInput{buildscript}},
		{Component: "web", Control: "licenses", Scanners: []string{"trivy-license"}, Read: 1,
			Unread: []engine.UnreadInput{{Repository: bun, Path: "app/bun.lock", Reason: notReadT}}},
		{Component: "web", Control: "sca", Scanners: []string{"grype-fs", "trivy-fs"}, Read: 3,
			Missed: []engine.MissedInput{
				{Repository: bun, Path: "app/bun.lock", Scanner: "trivy-fs", Reason: notReadT},
				buildscript,
			}},
	}
	d := goldenGroupedData()
	d.Run.Inputs = inputs
	d.Run.Targets = append(repositoryTargets("android", gradle), repositoryTargets("web", gradle, bun)...)
	d.TopN = -1
	d.FailOnCaveats = []saga.CaveatKind{saga.CaveatUnreadFiles}

	out := renderWith(t, consoleReporter{}, d)
	_, groups, _ := consoleCaveats(t, out)
	want := []consoleCaveatGroup{{heading: "unread-files · licenses · web", marked: true, rows: []string{
		"acme/bun:app/bun.lock " + string([]rune(notReadT)[:whyWidth-1]) + "…"}}}
	if !reflect.DeepEqual(groups, want) {
		t.Errorf("groups = %+v\nwant %+v:\n%s", groups, want, out)
	}
	if strings.Contains(out, "buildscript-gradle.lockfile") {
		t.Errorf("the default view names a file another scanner read:\n%s", out)
	}
	if failed := FailedCaveats(d); len(failed) != 1 || failed[0].What != "acme/bun:app/bun.lock" {
		t.Errorf("the gate fails on %+v, want the file no licenses scanner read alone", failed)
	}
	md := renderWith(t, markdownReporter{}, d)
	if strings.Contains(md, "buildscript-gradle.lockfile") || !strings.Contains(md, notReadT+" (licenses)") {
		t.Errorf("markdown lists a file another scanner read, or not the one none read:\n%s", md)
	}

	d.Evidence = true
	evidence := strings.Join(strings.Fields(renderWith(t, consoleReporter{}, d)), " ")
	for _, want := range []string{
		"missed sca: grype-fs · android · buildscript-gradle.lockfile · no packages read",
		"sca: trivy-fs · web · acme/bun:app/bun.lock · not parsed: JSON decode error:",
		"sca: grype-fs · web · acme/gradle:buildscript-gradle.lockfile · no packages read",
	} {
		if !strings.Contains(evidence, want) {
			t.Errorf("the evidence is missing %q:\n%s", want, evidence)
		}
	}
}

// A row's reason leaves out the controls its heading names, and a caveat that names none keeps its
// detail whole. The heading names the controls only where the caveat has some.
func TestCaveatReasonLeavesTheControlsToItsHeading(t *testing.T) {
	for _, c := range []struct {
		c               caveat
		reason, heading string
	}{
		{caveat{key: saga.CaveatUnreadFiles, component: "api", detail: "no lockfile (sca)", by: "sca"},
			"no lockfile", "unread-files · sca · api"},
		{caveat{key: saga.CaveatUnreadFiles, component: "server", detail: "no lockfile (licenses, sca)", by: "licenses, sca"},
			"no lockfile", "unread-files · licenses, sca · server"},
		{caveat{key: saga.CaveatNotChecked, component: "web", detail: "controls off: dast (x)"},
			"controls off: dast (x)", "not-checked · web"},
		{caveat{key: saga.CaveatUnreadFiles, component: "api", detail: "no lockfile", by: "sca"},
			"no lockfile", "unread-files · sca · api"},
	} {
		if got := c.c.reason(); got != c.reason {
			t.Errorf("reason(%q) = %q, want %q", c.c.detail, got, c.reason)
		}
		if got := c.c.heading(); got != c.heading {
			t.Errorf("heading of %+v = %q, want %q", c.c, got, c.heading)
		}
	}
	if kindRank("unknown") != len(saga.CaveatKinds) {
		t.Errorf("an unknown kind does not sort last")
	}
}

// A run with no findings closes on a tick only where it has no caveat, in every human format: a file
// nothing read has nothing found in it because nothing looked. Two components over two repositories,
// one with a file unread and one without.
func TestNoFindingsWithACaveatIsNotATick(t *testing.T) {
	inputs := []engine.InputCoverage{
		{Component: "shop", Control: "iac", Scanners: []string{"trivy-config"},
			Unread: []engine.UnreadInput{{Repository: "app", Path: "charts/app/Chart.yaml",
				Reason: "run helm dependency build; redis not in charts/"}}},
		{Component: "billing", Control: "iac", Scanners: []string{"trivy-config"}, Read: 1},
	}
	for _, format := range []string{"console", "markdown", "html"} {
		r, err := For(format)
		if err != nil {
			t.Fatal(err)
		}
		d := Data{Project: "p", Run: engine.Result{Inputs: inputs, Targets: append(repositoryTargets("shop", "app"),
			repositoryTargets("billing", "web")...)}}
		if out := renderWith(t, r, d); strings.Contains(out, "No findings. ✓") || !strings.Contains(out, noFindingsWithCaveats) {
			t.Errorf("%s: a run with a caveat closes as clean:\n%s", format, out)
		}
		d.Run.Inputs = inputs[1:]
		if out := renderWith(t, r, d); !strings.Contains(out, "No findings. ✓") {
			t.Errorf("%s: a run that read every file has no tick:\n%s", format, out)
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
