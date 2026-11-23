package diff

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

const demoRepository = "https://github.com/draugr-dev/draugr-demo"

// requestsAdvisory is one scanner's finding of the advisory in requests 2.19.1 that Trivy names
// CVE-2018-18074 and OSV-Scanner PYSEC-2018-28, as the engine writes it before correlation.
func requestsAdvisory(tool, rule, component, priority string) sarif.Result {
	return sarif.Result{
		Tool: tool, Scanner: tool, RuleID: rule, Level: sarif.LevelError, Priority: priority,
		Message:    rule + ": requests 2.19.1 sends credentials on a redirect to plain HTTP",
		Location:   sarif.Location{URI: component + "/requirements.txt", StartLine: 3},
		Component:  component,
		Repository: demoRepository,
		Package:    &sarif.Package{Name: "requests", Version: "2.19.1", FixedVersion: "2.20.0", PURL: "pkg:pypi/requests@2.19.1"},
	}
}

// countedWith marks counted as the copy a flaw is counted under, naming other, and other as counted
// under it, the way the engine's correlation leaves the two.
func countedWith(counted, other sarif.Result) (sarif.Result, sarif.Result) {
	counted.Correlation = &sarif.Correlation{AlsoFoundBy: []sarif.Observation{{
		Tool: other.Reporter(), RuleID: other.RuleID, Severity: sarif.SeverityHigh,
	}}}
	other.Correlation = &sarif.Correlation{CountedUnder: counted.Reporter()}
	return counted, other
}

// withOSVScanner is the head of a change that turns OSV-Scanner on beside Trivy in component: the
// flaw is counted under OSV-Scanner's copy, and Trivy's copy, which the base had, under it.
func withOSVScanner(component, priority string) []sarif.Result {
	osv, trivy := countedWith(
		requestsAdvisory("osv-scanner", "PYSEC-2018-28", component, priority),
		requestsAdvisory("trivy", "CVE-2018-18074", component, priority),
	)
	return []sarif.Result{osv, trivy}
}

// Turning a second scanner on changes which copy of a flaw is counted and nothing about the flaw. A
// diff that read the newly counted copy as new would fail the pull request that adds the scanner on
// a flaw the base already had.
func TestASecondScannersCountedCopyOfAKnownFlawIsNotNew(t *testing.T) {
	base := report(requestsAdvisory("trivy", "CVE-2018-18074", "api", "P1"))
	r := Compare(base, report(withOSVScanner("api", "P1")...))

	if len(r.New) != 0 {
		t.Fatalf("New = %+v, want nothing: the base had this flaw under Trivy", r.New)
	}
	if got := r.GateNew("", "P1"); len(got) != 0 {
		t.Errorf("the gate tripped on %+v, want nothing", got)
	}
	c := r.Counted()
	if len(c.Unchanged) != 1 || c.Unchanged[0].RuleID != "PYSEC-2018-28" {
		t.Errorf("Counted().Unchanged = %+v, want OSV-Scanner's counted copy alone", c.Unchanged)
	}
	if len(c.Fixed) != 0 || len(c.Changed()) != 0 {
		t.Errorf("fixed = %+v, changed = %+v, want nothing changed", c.Fixed, c.Changed())
	}
}

// The comparison reads both scans back from results.sarif, which does not record where each copy
// was, so what pairs the copies has to survive the file.
func TestACarriedOverFlawSurvivesTheSARIFFile(t *testing.T) {
	readBack := func(rep sarif.Report) sarif.Report {
		t.Helper()
		data, err := rep.MarshalSARIF()
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		back, err := sarif.FromSARIF(data)
		if err != nil {
			t.Fatalf("read back: %v", err)
		}
		return back
	}
	base := readBack(report(requestsAdvisory("trivy", "CVE-2018-18074", "api", "P1")))
	head := readBack(report(withOSVScanner("api", "P1")...))

	if r := Compare(base, head); len(r.New) != 0 {
		t.Errorf("New = %+v, want nothing", r.New)
	}
}

// kubernetesSetting is one IaC scanner's finding of a container allowed to escalate privileges, at
// file. KICS and Trivy write rule ids that share nothing, and the engine pairs them by the setting.
func kubernetesSetting(tool, rule, file string, line int, priority string) sarif.Result {
	return sarif.Result{
		Tool: tool, Scanner: tool, RuleID: rule, Level: sarif.LevelWarning, Priority: priority,
		Message:    rule + ": container allows privilege escalation",
		Location:   sarif.Location{URI: file, StartLine: line},
		Component:  "api",
		Repository: demoRepository,
	}
}

const (
	kicsEscalation  = "5572cc5e-1e4c-4113-92a6-7a8a3bd25e6d"
	trivyEscalation = "AVD-KSV-0001"
)

// withKICS is the head of a change that turns KICS on beside Trivy, where KICS rates the setting
// higher and so its copy is counted, for the container at file.
func withKICS(file, priority string) (kics, trivy sarif.Result) {
	return countedWith(
		kubernetesSetting("KICS", kicsEscalation, file, 13, priority),
		kubernetesSetting("Trivy", trivyEscalation, file, 9, priority),
	)
}

// The same for two tools whose rules are paired by the setting they check rather than by an
// advisory both name.
func TestAPairedRulesCountedCopyOfAKnownFlawIsNotNew(t *testing.T) {
	base := report(kubernetesSetting("Trivy", trivyEscalation, "deploy/pod.yaml", 9, "P2"))
	kics, trivy := withKICS("deploy/pod.yaml", "P2")
	r := Compare(base, report(kics, trivy))

	if len(r.New) != 0 || len(r.GateNew(sarif.SeverityLow, "")) != 0 {
		t.Fatalf("New = %+v, want nothing: the base had this setting under Trivy", r.New)
	}
	if c := r.Counted(); len(c.Unchanged) != 1 || c.Unchanged[0].Tool != "KICS" {
		t.Errorf("Counted().Unchanged = %+v, want KICS's counted copy alone", c.Unchanged)
	}
}

// A counted copy takes its band change from the base finding it stands in for, so a flaw ranked
// differently at the head is reranked, as it would be had the same scanner been counted in both.
func TestACarriedOverFlawRankedDifferentlyIsReranked(t *testing.T) {
	base := report(requestsAdvisory("trivy", "CVE-2018-18074", "api", "P2"))
	c := Compare(base, report(withOSVScanner("api", "P1")...)).Counted()

	if len(c.New) != 0 || len(c.Unchanged) != 0 {
		t.Fatalf("new = %+v, unchanged = %+v, want the flaw reranked alone", c.New, c.Unchanged)
	}
	if len(c.Reranked) != 1 || c.Reranked[0].RuleID != "PYSEC-2018-28" || c.Reranked[0].From != "P2" {
		t.Errorf("Counted().Reranked = %+v, want OSV-Scanner's copy raised from P2", c.Reranked)
	}
}

// A flaw neither scanner reported at the base is new however many scanners report it at the head,
// including beside a flaw whose count only moved to another scanner.
func TestAFlawNewToBothScannersIsStillNew(t *testing.T) {
	base := report(requestsAdvisory("trivy", "CVE-2018-18074", "api", "P1"))
	osv, trivy := countedWith(
		sarif.Result{
			Tool: "osv-scanner", Scanner: "osv-scanner", RuleID: "PYSEC-2023-74", Level: sarif.LevelError, Priority: "P1",
			Message:   "PYSEC-2023-74: requests 2.19.1 leaks a Proxy-Authorization header",
			Location:  sarif.Location{URI: "api/requirements.txt", StartLine: 3},
			Component: "api", Repository: demoRepository,
		},
		sarif.Result{
			Tool: "trivy", Scanner: "trivy", RuleID: "CVE-2023-32681", Level: sarif.LevelError, Priority: "P1",
			Message:   "CVE-2023-32681: requests 2.19.1 leaks a Proxy-Authorization header",
			Location:  sarif.Location{URI: "api/requirements.txt", StartLine: 3},
			Component: "api", Repository: demoRepository,
		},
	)
	// The new flaw first, so it is weighed against the known flaw's copy before that copy is taken.
	r := Compare(base, report(append([]sarif.Result{osv, trivy}, withOSVScanner("api", "P1")...)...))

	c := r.Counted()
	if len(c.New) != 1 || c.New[0].RuleID != "PYSEC-2023-74" {
		t.Fatalf("Counted().New = %+v, want the new flaw's counted copy alone", c.New)
	}
	if got := r.GateNew("", "P1"); len(got) != 1 || got[0].RuleID != "PYSEC-2023-74" {
		t.Errorf("the gate tripped on %+v, want the new flaw", got)
	}
}

// A copy speaks for its own component's flaw. Another component's copy of the same advisory, which
// the base had, does not make this component's flaw old.
func TestACopyInAnotherComponentCarriesNothingOver(t *testing.T) {
	base := report(requestsAdvisory("trivy", "CVE-2018-18074", "api", "P1"))
	// worker first, so its flaw is weighed against api's copy before api's flaw takes it.
	head := report(append(withOSVScanner("worker", "P1"), withOSVScanner("api", "P1")...)...)
	c := Compare(base, head).Counted()

	if len(c.New) != 1 || c.New[0].Component != "worker" {
		t.Errorf("Counted().New = %+v, want worker's flaw alone", c.New)
	}
	if len(c.Unchanged) != 1 || c.Unchanged[0].Component != "api" {
		t.Errorf("Counted().Unchanged = %+v, want api's flaw alone", c.Unchanged)
	}
}

// Two files breaking one rule are two flaws, each counted copy standing in for its own file's base
// finding. Paired across the files, each would take the other's band and read as reranked.
func TestEachCountedCopyStandsInForItsOwnFile(t *testing.T) {
	base := report(
		kubernetesSetting("Trivy", trivyEscalation, "deploy/a.yaml", 9, "P2"),
		kubernetesSetting("Trivy", trivyEscalation, "deploy/b.yaml", 9, "P3"),
	)
	kicsA, trivyA := withKICS("deploy/a.yaml", "P2")
	kicsB, trivyB := withKICS("deploy/b.yaml", "P3")
	// The copies are listed against the counted ones' order, so pairing by the first that fits
	// would cross the files.
	c := Compare(base, report(kicsA, kicsB, trivyB, trivyA)).Counted()

	if len(c.New) != 0 || len(c.Reranked) != 0 {
		t.Fatalf("new = %+v, reranked = %+v, want both files unchanged", c.New, c.Reranked)
	}
	if len(c.Unchanged) != 2 {
		t.Fatalf("Counted().Unchanged = %+v, want KICS's copy in each file", c.Unchanged)
	}
	for _, f := range c.Unchanged {
		if f.Tool != "KICS" {
			t.Errorf("unchanged holds %s's copy in %s, want KICS's", f.Tool, f.Location.URI)
		}
	}
}

// Where the base had the flaw only once, one counted copy stands in for it and a second, in another
// file, is still new.
func TestOneBaseFindingStandsInForOneCountedCopy(t *testing.T) {
	base := report(kubernetesSetting("Trivy", trivyEscalation, "deploy/a.yaml", 9, "P2"))
	kicsA, trivyA := withKICS("deploy/a.yaml", "P2")
	kicsB, trivyB := withKICS("deploy/b.yaml", "P2")
	c := Compare(base, report(kicsA, trivyA, kicsB, trivyB)).Counted()

	if len(c.New) != 1 || c.New[0].Location.URI != "deploy/b.yaml" {
		t.Errorf("Counted().New = %+v, want b.yaml's flaw alone", c.New)
	}
}

// A flaw excused in both scans stays a decision that did not change when the copy counted for it
// moves to another scanner, rather than reading as a new acceptance.
func TestACarriedOverExcusedFlawIsUnchanged(t *testing.T) {
	base := report(suppressed(requestsAdvisory("trivy", "CVE-2018-18074", "api", "P1")))
	head := withOSVScanner("api", "P1")
	for i := range head {
		head[i] = suppressed(head[i])
	}
	c := Compare(base, report(head...)).Counted()

	if len(c.Accepted) != 0 || len(c.Unchanged) != 1 || c.Unchanged[0].RuleID != "PYSEC-2018-28" {
		t.Errorf("accepted = %+v, unchanged = %+v, want OSV-Scanner's copy unchanged", c.Accepted, c.Unchanged)
	}
}

// Turning a scanner off moves the count of a flaw back to the copy the remaining scanner had, and
// nothing about the flaw changes. A diff that read the base's counted copy as fixed would report a
// fix nobody made, for a flaw the head still has.
func TestTurningAScannerOffFixesNothing(t *testing.T) {
	base := report(withOSVScanner("api", "P1")...)
	r := Compare(base, report(requestsAdvisory("trivy", "CVE-2018-18074", "api", "P1")))

	if len(r.Fixed) != 0 {
		t.Fatalf("Fixed = %+v, want nothing: Trivy still finds this flaw", r.Fixed)
	}
	c := r.Counted()
	if len(c.Unchanged) != 1 || c.Unchanged[0].RuleID != "CVE-2018-18074" {
		t.Errorf("Counted().Unchanged = %+v, want Trivy's copy alone", c.Unchanged)
	}
	if len(c.Changed()) != 0 {
		t.Errorf("changed = %+v, want nothing changed", c.Changed())
	}
}

// The same for two tools whose rules are paired by the setting they check.
func TestTurningAPairedRuleOffFixesNothing(t *testing.T) {
	kics, trivy := withKICS("deploy/pod.yaml", "P2")
	r := Compare(report(kics, trivy), report(kubernetesSetting("Trivy", trivyEscalation, "deploy/pod.yaml", 9, "P2")))

	if c := r.Counted(); len(c.Fixed) != 0 || len(c.Unchanged) != 1 || c.Unchanged[0].Tool != "Trivy" {
		t.Errorf("fixed = %+v, unchanged = %+v, want Trivy's copy unchanged alone", c.Fixed, c.Unchanged)
	}
}

// A flaw gone from every scanner's report is fixed, beside a flaw whose count only moved back to
// the scanner left on.
func TestAFlawGoneFromEveryScannerIsStillFixed(t *testing.T) {
	gone, goneCopy := withKICS("deploy/worker.yaml", "P2")
	kept, keptCopy := withKICS("deploy/pod.yaml", "P2")
	r := Compare(
		report(gone, goneCopy, kept, keptCopy),
		report(kubernetesSetting("Trivy", trivyEscalation, "deploy/pod.yaml", 9, "P2")),
	)

	c := r.Counted()
	if len(c.Fixed) != 1 || c.Fixed[0].Tool != "KICS" || c.Fixed[0].Location.URI != "deploy/worker.yaml" {
		t.Errorf("Counted().Fixed = %+v, want KICS's counted copy in worker.yaml alone", c.Fixed)
	}
}

// One copy at the head stands for one counted base finding. Where the base counted the flaw in two
// files and the head still has it in one, the other file's flaw is fixed, whichever order the base
// lists them in.
func TestOneHeadCopyKeepsOneCountedFlaw(t *testing.T) {
	kicsA, trivyA := withKICS("deploy/a.yaml", "P2")
	kicsB, trivyB := withKICS("deploy/b.yaml", "P2")
	// b.yaml's counted copy first, so pairing by the first copy that fits would take a.yaml's.
	r := Compare(
		report(kicsB, kicsA, trivyA, trivyB),
		report(kubernetesSetting("Trivy", trivyEscalation, "deploy/a.yaml", 9, "P2")),
	)

	if c := r.Counted(); len(c.Fixed) != 1 || c.Fixed[0].Location.URI != "deploy/b.yaml" {
		t.Errorf("Counted().Fixed = %+v, want b.yaml's flaw alone", c.Fixed)
	}
}
