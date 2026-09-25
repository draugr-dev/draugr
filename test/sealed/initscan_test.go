package sealed

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestForInitScan(t *testing.T) {
	exp := Expected{
		Findings: []FindingExpectation{
			{Control: "sca", Tool: "trivy", Rule: "CVE-1", Location: "a:1"},
			{Control: "sca", Tool: "trivy", Rule: "CVE-2", Location: "b:1"},
		},
		Errors: []ErrorExpectation{{Control: "sca", Contains: "stale"}},
	}

	got, err := exp.ForInitScan()
	if err != nil || len(got.Findings) != 2 || len(got.Errors) != 1 {
		t.Errorf("with nothing to depart from, ForInitScan changed the expectation: %+v (%v)", got, err)
	}

	none := []ErrorExpectation{}
	exp.InitScan = InitScanExpectation{Unreported: []string{"CVE-2"}, Errors: &none}
	got, err = exp.ForInitScan()
	if err != nil || len(got.Findings) != 1 || got.Findings[0].Rule != "CVE-1" || len(got.Errors) != 0 {
		t.Errorf("ForInitScan = %+v (%v), want CVE-1 alone and no errors", got, err)
	}
	if len(exp.Findings) != 2 {
		t.Error("ForInitScan changed the scenario's own findings")
	}

	exp.InitScan.Unreported = []string{"CVE-3"}
	if _, err := exp.ForInitScan(); err == nil || !strings.Contains(err.Error(), "CVE-3") {
		t.Errorf("an unreported rule no finding has was accepted: %v", err)
	}

	exp.InitScan = InitScanExpectation{Skip: "the options are the subject", Unreported: []string{"CVE-1"}}
	if _, err := exp.ForInitScan(); err == nil || !strings.Contains(err.Error(), "skip") {
		t.Errorf("a skipped init scan with departures that would never be checked was accepted: %v", err)
	}
}

// init names no Semgrep ruleset, so an offline scan of its descriptor has the sast control refuse
// the default pack: no Semgrep finding, and the refusal added to whichever errors apply.
func TestForInitScanExpectsSemgrepToRefuseOffline(t *testing.T) {
	exp := Expected{
		Init: InitExpectation{Controls: []string{"sast", "sca"}},
		Findings: []FindingExpectation{
			{Control: "sast", Tool: "semgrep", Rule: "draugr-fixture-eval", Location: "a.js:2"},
			{Control: "sast", Tool: "gosec", Rule: "G204", Location: "main.go:9"},
		},
		Errors: []ErrorExpectation{{Control: "sca", Contains: "stale"}},
	}
	if !exp.InitRefusesSemgrep() {
		t.Fatal("an offline scan of a descriptor enabling sast with no ruleset should refuse Semgrep")
	}
	got, err := exp.ForInitScan()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Findings) != 1 || got.Findings[0].Tool != "gosec" {
		t.Errorf("findings = %+v, want gosec's alone", got.Findings)
	}
	want := []ErrorExpectation{{Control: "sca", Contains: "stale"}, {Control: "sast", Contains: SemgrepDefaultRefusal}}
	if !slices.Equal(got.Errors, want) {
		t.Errorf("errors = %+v, want %+v", got.Errors, want)
	}
	if len(exp.Errors) != 1 {
		t.Error("ForInitScan changed the scenario's own errors")
	}

	none := []ErrorExpectation{}
	exp.InitScan.Errors = &none
	if got, _ := exp.ForInitScan(); !slices.Equal(got.Errors, want[1:]) {
		t.Errorf("errors = %+v, want the refusal added to the replacement", got.Errors)
	}

	for name, e := range map[string]Expected{
		"no sast":         {Init: InitExpectation{Controls: []string{"sca"}}},
		"without semgrep": {Init: exp.Init, Sealed: RunOptions{WithoutTool: "semgrep"}},
		"online":          {Init: exp.Init, Sealed: RunOptions{WithoutOffline: true}},
	} {
		if e.InitRefusesSemgrep() {
			t.Errorf("%s: InitRefusesSemgrep = true, want Semgrep to run or be absent", name)
		}
	}
}

func TestWithoutRules(t *testing.T) {
	anns := []Annotation{{File: "a.py", Line: 2, Rule: "draugr-fixture-os-popen", Want: true}, {File: "b.go", Line: 3, Rule: "G204", Want: true}}
	got := WithoutRules(anns, []string{"draugr-fixture-os-popen", "draugr-fixture-eval"})
	if len(got) != 1 || got[0].Rule != "G204" {
		t.Errorf("WithoutRules = %+v, want G204 alone", got)
	}
}

func TestSemgrepRuleIDs(t *testing.T) {
	ids, err := SemgrepRuleIDs(filepath.Join("..", "integration", "testdata", "ecosystems", "semgrep.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(ids, "draugr-fixture-os-popen") || !slices.Contains(ids, "draugr-fixture-eval") {
		t.Errorf("ids = %v, want the sealed rules", ids)
	}
	if _, err := SemgrepRuleIDs(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Error("a missing rules file was read as declaring no rules")
	}
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("rules: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := SemgrepRuleIDs(bad); err == nil {
		t.Error("an unparseable rules file was read as declaring no rules")
	}
}
