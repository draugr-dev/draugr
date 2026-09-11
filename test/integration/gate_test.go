//go:build integration

package integration

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The gate is the answer Draugr exists to give, and nothing here ran it end to end. Every test
// above this one asserts what was *found*; none asserted what was *decided*, so the path from a
// real scanner's output through a threshold to an exit code had no coverage at all, which is the
// path three of this product's bugs lived on.
//
// Real scanners, a real repository, a real verdict. Gitleaks is the reliable producer (offline,
// regex-based, no vulnerability database to drift), so the gate is exercised against a leaked
// credential, whose severity and band are both stable in a way a CVE's are not.
//
// Counts are never asserted, only the decision. A test that pins how many findings a scanner
// returns fails on the scanner's release schedule rather than on ours.

// gateCase is one descriptor and the verdict it should produce.
type gateCase struct {
	name string
	// gate is the `config.gate` block, already indented for the descriptor below.
	gate string
	// component is the classification, which is what the band is computed from.
	exposure    string
	criticality string
	// noSecrets turns off the one control that declares a context floor. Whether a band is
	// reachable depends on it, so a case about reachability has to be able to say.
	noSecrets bool
	wantFail  bool
	// wantOut is a phrase the command has to say. The verdict alone does not prove the reader was
	// told which rule produced it.
	wantOut string
}

func TestTheGateDecidesAndSaysWhy(t *testing.T) {
	requireTool(t, "gitleaks", "the gate needs a real finding to judge")
	requireTool(t, "git", "the scan checks the repository out before scanning it")
	repo := newVulnRepo(t)

	for _, tc := range []gateCase{
		{
			// The default, with nothing named. An unclassified component ranks at the most
			// exposed tier, where a leaked credential is P1.
			name:     "the default gate fails on the band",
			exposure: "public", criticality: "critical",
			wantFail: true,
			wantOut:  "FAIL",
		},
		{
			// The same finding, judged on its severity instead. A private key is error-level, so
			// a gate set to critical does not catch it, and that is the point: the two questions
			// give different answers about one finding.
			name:     "a severity gate asks the other question",
			gate:     "    failOn: critical\n",
			exposure: "public", criticality: "critical",
			wantFail: false,
			wantOut:  "fails on critical severity",
		},
		{
			name:     "a severity gate set where the finding reaches it",
			gate:     "    failOn: high\n",
			exposure: "public", criticality: "critical",
			wantFail: true,
			wantOut:  "fails on high severity",
		},
		{
			// A per-control threshold refines the global one, and the report names which control
			// was exempted rather than counting them.
			name:     "a per-control threshold overrides the global one",
			gate:     "    failOn: low\n    controls:\n      secrets: critical\n",
			exposure: "public", criticality: "critical",
			wantFail: false,
			wantOut:  "except secrets on critical",
		},
		{
			// `secrets` declares a context floor, so a leaked credential reaches P1 on a
			// component classified well below where P1 would otherwise be reachable. Without the
			// floor this descriptor would have no gate at all.
			name:     "a control's floor reaches the band on a restricted component",
			exposure: "restricted", criticality: "supporting",
			wantFail: true,
			wantOut:  "FAIL",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, failed := scanWithGate(t, repo, tc)
			if failed != tc.wantFail {
				t.Errorf("failed = %v, want %v\n%s", failed, tc.wantFail, out)
			}
			if !strings.Contains(out, tc.wantOut) {
				t.Errorf("output does not say %q:\n%s", tc.wantOut, out)
			}
		})
	}
}

// TestAGateThatCannotFireIsRefusedBeforeScanning: the default gate is a band, so a descriptor
// classifying every component below where that band is reachable has no gate rather than a weak
// one. Refused before a scanner runs, because the answer does not depend on what they find.
func TestAGateThatCannotFireIsRefusedBeforeScanning(t *testing.T) {
	requireTool(t, "git", "the descriptor names a repository")
	repo := newVulnRepo(t)
	// Without the one control that declares a floor, so the classification stands on its own.
	out, failed := scanWithGate(t, repo, gateCase{
		gate:     "    failOnPriority: P1\n",
		exposure: "restricted", criticality: "important",
		noSecrets: true,
	})
	if !failed {
		t.Errorf("a gate that cannot fire was accepted:\n%s", out)
	}
	for _, want := range []string{"cannot fire", "restricted", "C4", "P2"} {
		if !strings.Contains(out, want) {
			t.Errorf("the refusal does not say %q:\n%s", want, out)
		}
	}
}

// TestASuppressedFindingIsNotJudged: an excluded finding stays in the report with the reason
// somebody gave, and the gate does not count it. Both halves matter, and only one of them is
// visible from the verdict.
func TestASuppressedFindingIsNotJudged(t *testing.T) {
	requireTool(t, "gitleaks", "the gate needs a real finding to suppress")
	requireTool(t, "git", "the scan checks the repository out before scanning it")
	repo := newVulnRepo(t)

	dir := t.TempDir()
	descriptor := filepath.Join(dir, "draugr.saga.yaml")
	body := `project: gate-fixture
release: {version: "1.0.0"}
config:
  exclude:
    - reason: "Fixture key, not a live credential."
      acceptedBy: test@draugr.dev
      paths: ["id_rsa"]
  controllers:
    secrets: {enabled: true}
components:
  - name: api
    exposure: public
    criticality: critical
    repositories:
      - url: ` + repo + `
`
	if err := os.WriteFile(descriptor, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()
	// #nosec G204 -- the binary under test, a descriptor this test wrote, and t.TempDir() paths.
	cmd := exec.Command(draugrBin(t), "scan", descriptor, "--output", outDir, "--log-level", "warn")
	combined, err := cmd.CombinedOutput()
	t.Logf("exit=%v\n%s", err, combined)
	if err != nil {
		t.Errorf("a suppressed finding failed the gate: %v", err)
	}
	if !strings.Contains(string(combined), "suppressed by config.exclude") {
		t.Errorf("the report does not say what was set aside:\n%s", combined)
	}

	// And the control it belongs to reports nothing to judge, which is what "not counted" means
	// where a machine reads it.
	raw, err := os.ReadFile(filepath.Join(outDir, "report.json")) //#nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Verdict  string `json:"verdict"`
		Controls []struct {
			Name    string `json:"name"`
			Verdict string `json:"verdict"`
			Highest string `json:"highest"`
		} `json:"controls"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Verdict != "pass" {
		t.Errorf("verdict = %q, want pass", doc.Verdict)
	}
	for _, c := range doc.Controls {
		if c.Name == "secrets" && c.Highest != "" {
			t.Errorf("secrets reports %q as its worst, so a suppressed finding reached the gate", c.Highest)
		}
	}
}

// scanWithGate writes a descriptor for one case, scans, and reports whether the gate failed.
func scanWithGate(t *testing.T, repo string, tc gateCase) (string, bool) {
	t.Helper()
	dir := t.TempDir()
	descriptor := filepath.Join(dir, "draugr.saga.yaml")
	gate := ""
	if tc.gate != "" {
		gate = "  gate:\n" + tc.gate
	}
	// `iac` produces nothing on this fixture and declares no floor, which is what makes it the
	// right stand-in where the point is that nothing lifts the band.
	controls := "    secrets: {enabled: true}\n"
	if tc.noSecrets {
		controls = "    iac: {enabled: true}\n"
	}
	body := `project: gate-fixture
release: {version: "1.0.0"}
config:
` + gate + `  controllers:
` + controls + `components:
  - name: api
    exposure: ` + tc.exposure + `
    criticality: ` + tc.criticality + `
    repositories:
      - url: ` + repo + `
`
	if err := os.WriteFile(descriptor, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	// #nosec G204 -- the binary under test and a descriptor this test wrote into t.TempDir().
	cmd := exec.Command(draugrBin(t), "scan", descriptor, "--log-level", "warn", "--evidence")
	combined, err := cmd.CombinedOutput()
	t.Logf("%s: exit=%v\n%s", tc.name, err, combined)
	return string(combined), err != nil
}

// TestTheTwoGatesDisagreeOnOneScan is the case every test above it cannot be: proof that the
// default is the band rather than the severity.
//
// Everything judged through `secrets` gives the same verdict under either gate, because that
// control declares a context floor and its findings reach P1 from any classification. So this uses
// `sca`, which declares none, on a component classified where a high finding ranks P2: the default
// gate passes it and a severity gate set to high does not.
//
// The two runs are compared against each other rather than against fixed verdicts. Which CVEs a
// dependency carries and what each is rated move on the scanner's schedule, and a test that pins
// them fails on somebody else's release. That the two questions give different answers about one
// scan is the property, and it does not drift.
func TestTheTwoGatesDisagreeOnOneScan(t *testing.T) {
	requireTool(t, "trivy", "this needs a control that declares no priority floor")
	requireTool(t, "git", "the scan checks the repository out before scanning it")
	repo := newVulnRepo(t)

	dir := t.TempDir()
	descriptor := filepath.Join(dir, "draugr.saga.yaml")
	body := `project: gate-fixture
release: {version: "1.0.0"}
config:
  controllers:
    sca: {enabled: true}
components:
  - name: api
    exposure: public
    criticality: supporting
    repositories:
      - url: ` + repo + `
`
	if err := os.WriteFile(descriptor, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	run := func(args ...string) (string, bool) {
		t.Helper()
		full := append([]string{"scan", descriptor, "--log-level", "warn"}, args...)
		// #nosec G204 -- the binary under test and a descriptor this test wrote into t.TempDir().
		out, err := exec.Command(draugrBin(t), full...).CombinedOutput()
		t.Logf("draugr %v: exit=%v\n%s", args, err, out)
		return string(out), err != nil
	}

	byBand, bandFailed := run()
	bySeverity, severityFailed := run("--fail-on", "high")

	if !strings.Contains(byBand, "P2") {
		t.Skip("this fixture's dependencies no longer rank P2 here; the case cannot discriminate")
	}
	if bandFailed == severityFailed {
		t.Errorf("both gates gave the same verdict, so this proves nothing about which is the "+
			"default.\n--- by band ---\n%s\n--- by severity ---\n%s", byBand, bySeverity)
	}
	if bandFailed {
		t.Error("the default gate failed on a scan whose worst band is P2")
	}
	if !severityFailed {
		t.Error("a gate set to high severity passed a high finding")
	}
}

// TestPriorityCountsAreWhatTheGateJudged is the arithmetic two real matchers make visible.
//
// A flaw both tools report is one flaw. Counting both copies means enabling the opt-in second
// matcher doubles a project's reported P1 count with nothing new wrong, which reads as a
// regression caused by improving coverage. Measured by scanning once and then again with the
// second matcher on, and requiring the counts to hold.
func TestPriorityCountsAreWhatTheGateJudged(t *testing.T) {
	requireTool(t, "trivy", "the first matcher")
	requireTool(t, "grype", "the second matcher is what makes a flaw appear twice")
	requireTool(t, "git", "the scan checks the repository out before scanning it")
	repo := newVulnRepo(t)

	counts := func(second bool) (p1 int, results int) {
		t.Helper()
		dir := t.TempDir()
		grype := ""
		if second {
			grype = "      grypeFs: {enabled: true}\n"
		}
		body := `project: counts-fixture
release: {version: "1.0.0"}
config:
  gate: {failOn: critical}
  controllers:
    sca:
      enabled: true
` + grype + `components:
  - name: api
    exposure: public
    criticality: critical
    repositories:
      - url: ` + repo + `
`
		descriptor := filepath.Join(dir, "draugr.saga.yaml")
		if err := os.WriteFile(descriptor, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		out := t.TempDir()
		// #nosec G204 -- the binary under test and a descriptor this test wrote into t.TempDir().
		cmd := exec.Command(draugrBin(t), "scan", descriptor, "--output", out, "--log-level", "warn")
		combined, err := cmd.CombinedOutput()
		t.Logf("second=%v exit=%v\n%s", second, err, combined)

		raw, err := os.ReadFile(filepath.Join(out, "report.json")) //#nosec G304 -- under t.TempDir()
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Priorities struct {
				P1 int `json:"p1"`
			} `json:"priorities"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		sarifRaw, err := os.ReadFile(filepath.Join(out, "results.sarif")) //#nosec G304 -- under t.TempDir()
		if err != nil {
			t.Fatal(err)
		}
		var report struct {
			Runs []struct {
				Results []json.RawMessage `json:"results"`
			} `json:"runs"`
		}
		if err := json.Unmarshal(sarifRaw, &report); err != nil {
			t.Fatal(err)
		}
		for _, r := range report.Runs {
			results += len(r.Results)
		}
		return doc.Priorities.P1, results
	}

	alone, aloneResults := counts(false)
	both, bothResults := counts(true)
	if alone == 0 {
		t.Skip("this fixture's dependencies no longer produce a P1; the case cannot discriminate")
	}
	if bothResults <= aloneResults {
		t.Skip("the second matcher found nothing the first did not report; nothing to correlate")
	}
	// The point. More results in the document, the same count of work.
	if both != alone {
		t.Errorf("P1 went from %d to %d when the second matcher was enabled, over %d results "+
			"against %d. A flaw two tools report is one flaw.",
			alone, both, bothResults, aloneResults)
	}
}
