package report

import (
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
)

// dirtyData is a clean run of a local checkout that has uncommitted changes the scan did not read.
func dirtyData(repos ...RepositoryProvenance) Data {
	d := goldenCleanData()
	d.Repositories = repos
	return d
}

var dirtyAPI = RepositoryProvenance{URL: "https://github.com/acme/api", Revision: "abc123def456", Uncommitted: 2}

// Uncommitted files a scan left out are the shortfall a reader does not expect: they fix a finding,
// scan again, and it is still there. So they are a caveat in every view, with what reads them, and
// a clean run closes on a tick that names the commit it covers.
func TestUncommittedFilesLeftOutAreACaveatInEveryView(t *testing.T) {
	for _, view := range []View{ViewFindings, ViewCompact, ViewActions} {
		d := dirtyData(dirtyAPI)
		d.View = view
		out := renderWith(t, consoleReporter{}, d)
		if !strings.Contains(out, "\n  uncommitted-files\n    2 uncommitted files  not in commit abc123de · --working-tree reads them\n") {
			t.Errorf("%s: no uncommitted-files caveat:\n%s", view, out)
		}
		if !strings.Contains(out, "\nNo findings in commit abc123de. ✓\n") {
			t.Errorf("%s: the tick does not name the commit:\n%s", view, out)
		}
	}
}

// With two repositories each row says which one, because two counts with nothing between them
// cannot be told apart. A working-tree scan read its uncommitted files and has no caveat.
func TestUncommittedFilesNameTheirRepositoryWhenThereAreTwo(t *testing.T) {
	web := RepositoryProvenance{URL: "https://github.com/acme/web", Revision: "fed987cba654", Uncommitted: 1}
	out := renderWith(t, consoleReporter{}, dirtyData(dirtyAPI, web))
	for _, want := range []string{
		"github.com/acme/api: 2 uncommitted files  not in commit abc123de",
		"github.com/acme/web: 1 uncommitted file   not in commit fed987cb",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	working := dirtyAPI
	working.WorkingTree = true
	if out := renderWith(t, consoleReporter{}, dirtyData(working, RepositoryProvenance{URL: "https://github.com/acme/web"})); strings.Contains(out, "uncommitted-files") {
		t.Errorf("a working-tree scan has a caveat for files it read:\n%s", out)
	}
}

// The kind is one gate.failOnCaveats accepts, and listing it fails the run on it, in the console
// and in the SARIF notification alike. The markdown report lists it under Caveats too.
func TestUncommittedFilesCanFailTheRun(t *testing.T) {
	d := dirtyData(dirtyAPI)
	if c := caveats(d); len(c) != 1 || c[0].fails(d) || c[0].heading() != "uncommitted-files" {
		t.Fatalf("caveats = %+v, want one uncommitted-files caveat that fails nothing", c)
	}
	d.FailOnCaveats = []saga.CaveatKind{saga.CaveatUncommittedFiles}
	if out := renderWith(t, consoleReporter{}, d); !strings.Contains(out, "1 fails the run") || !strings.Contains(out, "✗ uncommitted-files") {
		t.Errorf("the gate does not fail on it:\n%s", out)
	}
	ns := notifications(d)
	if len(ns) != 1 || ns[0].Kind != "uncommitted-files" || ns[0].Level != "error" ||
		ns[0].Message != "2 uncommitted files: not in commit abc123de · --working-tree reads them" {
		t.Errorf("notifications = %+v", ns)
	}
	if md := renderWith(t, markdownReporter{}, d); !strings.Contains(md, "2 uncommitted files") {
		t.Errorf("markdown leaves it out:\n%s", md)
	}
}

// The tick names what it covers in every human format, and goes where the gate fails on the
// uncommitted files or another caveat says part of the commit was not checked either.
func TestACleanRunWithUncommittedFilesTicksTheCommit(t *testing.T) {
	d := dirtyData(dirtyAPI)
	for name, r := range map[string]Reporter{"markdown": markdownReporter{}, "html": htmlReporter{}} {
		if out := renderWith(t, r, d); !strings.Contains(out, "No findings in commit abc123de. ✓") {
			t.Errorf("%s does not tick the commit:\n%s", name, out)
		}
	}
	web := RepositoryProvenance{URL: "https://github.com/acme/web", Revision: "fed987cba654", Uncommitted: 1}
	if line, tick := cleanRunLine(dirtyData(dirtyAPI, web)); !tick || line != "No findings in what is committed. ✓" {
		t.Errorf("two repositories: %q, %v", line, tick)
	}
	failing := dirtyData(dirtyAPI)
	failing.FailOnCaveats = []saga.CaveatKind{saga.CaveatUncommittedFiles}
	if line, tick := cleanRunLine(failing); tick || line != noFindingsWithCaveats {
		t.Errorf("gate fails on it: %q, %v", line, tick)
	}
	other := dirtyData(dirtyAPI)
	other.Uncovered = []Gap{{Component: "api", Surface: "host api.acme.test", Controls: []string{"tls"}}}
	if line, tick := cleanRunLine(other); tick || line != noFindingsWithCaveats {
		t.Errorf("another caveat beside it: %q, %v", line, tick)
	}
	if line, tick := cleanRunLine(goldenCleanData()); !tick || line != "No findings. ✓" {
		t.Errorf("no caveat: %q, %v", line, tick)
	}
}
