package mcp

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// movedFindings is one finding for each way a ranked severity can differ from the scanner's rating,
// and one where nothing moved it, spread over two repositories and two components so nothing here
// passes by collapsing them into one.
func movedFindings() map[string]sarif.Result {
	return map[string]sarif.Result{
		// A secret its scanner scored medium, which the secrets control holds at high. The level is
		// error because the control sets every secret's level to error; the score is what rates it.
		"floored": {
			RuleID: "generic-api-key", Tool: "gitleaks", Control: "secrets", Priority: "P1",
			Level: sarif.LevelError, HasScore: true, Score: 5.5, SeverityFloor: sarif.SeverityHigh,
			Component: "api", Repository: "api-repo",
			Location: sarif.Location{URI: "deploy/app.env", StartLine: 1},
		},
		// A CVE scored high that KEV raised to critical.
		"escalated": {
			RuleID: "CVE-2026-0103", Tool: "trivy", Control: "sca", Priority: "P1",
			Level: sarif.LevelError, HasScore: true, Score: 7.5,
			Component: "worker", Repository: "worker-repo",
			Location:   sarif.Location{URI: "go.mod", StartLine: 7},
			Escalation: &sarif.Escalation{From: sarif.SeverityHigh, To: sarif.SeverityCritical, Signal: "kev", Detail: "on KEV"},
		},
		// A CVE scored critical that a call graph showed nothing reaches.
		"unreachable": {
			RuleID: "CVE-2026-0104", Tool: "govulncheck", Control: "sca", Priority: "P2",
			Level: sarif.LevelError, HasScore: true, Score: 9.1,
			Component: "api", Repository: "api-repo",
			Location: sarif.Location{URI: "go.mod", StartLine: 9},
			Reachability: &sarif.Reachability{
				State: sarif.ReachabilityUnreachable, Analyzer: "govulncheck",
				Method: sarif.MethodCallGraph, RankedAs: sarif.SeverityHigh,
			},
		},
		// A medium nothing moved.
		"unmoved": {
			RuleID: "CVE-2026-0105", Tool: "trivy", Control: "sca", Priority: "P3",
			Level: sarif.LevelWarning, HasScore: true, Score: 5.3,
			Component: "worker", Repository: "worker-repo",
			Location: sarif.Location{URI: "go.mod", StartLine: 11},
		},
	}
}

// resultsOf lists the fixture in a fixed order.
func resultsOf(fx map[string]sarif.Result, names ...string) []sarif.Result {
	out := make([]sarif.Result, 0, len(names))
	for _, n := range names {
		out = append(out, fx[n])
	}
	return out
}

var movedNames = []string{"floored", "escalated", "unreachable", "unmoved"}

// assertBothSeverities checks every finding against the result it came from: rankedSeverity is the
// accessor's value, severity is still the scanner's rating, and severityFloor travels where the
// result has one.
func assertBothSeverities(t *testing.T, tool string, fx map[string]sarif.Result, got []Finding) {
	t.Helper()
	byRule := map[string]Finding{}
	for _, f := range got {
		byRule[f.RuleID] = f
	}
	for _, name := range movedNames {
		res := fx[name]
		f, ok := byRule[res.RuleID]
		if !ok {
			t.Errorf("%s: the %s finding did not come back: %+v", tool, name, got)
			continue
		}
		if want := string(res.RankedSeverity()); f.RankedSeverity != want {
			t.Errorf("%s: %s rankedSeverity = %q, want %q", tool, name, f.RankedSeverity, want)
		}
		if want := string(res.Severity("")); f.Severity != want {
			t.Errorf("%s: %s severity = %q, want the scanner's %q", tool, name, f.Severity, want)
		}
		if f.SeverityFloor != string(res.SeverityFloor) {
			t.Errorf("%s: %s severityFloor = %q, want %q", tool, name, f.SeverityFloor, res.SeverityFloor)
		}
	}
	// The fixture is only a test of anything if the two severities differ where something moved.
	for _, name := range []string{"floored", "escalated", "unreachable"} {
		if f := byRule[fx[name].RuleID]; f.Severity == f.RankedSeverity {
			t.Errorf("%s: %s should have moved, got %+v", tool, name, f)
		}
	}
}

// TestSummaryCarriesTheRankedSeverity: a finding read from summarize_report says the severity it was
// ranked at beside the scanner's rating, and the counts tally the ranked one, as the report does.
func TestSummaryCarriesTheRankedSeverity(t *testing.T) {
	fx := movedFindings()
	path := writeSARIF(t, sarif.Report{Results: resultsOf(fx, movedNames...)})
	_, out, err := SummarizeReportTool(context.Background(), nil, SummarizeInput{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	assertBothSeverities(t, "summarize_report", fx, out.Findings)

	// Ranked: escalated critical; floored and unreachable high; unmoved medium. The scanner's ratings
	// would give one critical, one high and two mediums.
	if want := (Counts{Critical: 1, High: 2, Medium: 1}); out.Counts != want {
		t.Errorf("counts = %+v, want %+v, by ranked severity", out.Counts, want)
	}
	// Priority first, then ranked severity within a band. The band where the two severities disagree
	// on the order is TestSummarySortsByRankedSeverityWithinABand.
	order := make([]string, 0, len(out.Findings))
	for _, f := range out.Findings {
		order = append(order, f.RuleID)
	}
	if want := []string{"CVE-2026-0103", "generic-api-key", "CVE-2026-0104", "CVE-2026-0105"}; fmt.Sprint(order) != fmt.Sprint(want) {
		t.Errorf("order = %v, want %v", order, want)
	}
}

// TestSummarySortsByRankedSeverityWithinABand: two findings in one band, where the scanner's ratings
// and the ranked severities put them in opposite orders.
func TestSummarySortsByRankedSeverityWithinABand(t *testing.T) {
	floored := sarif.Result{RuleID: "aws-access-token", Control: "secrets", Priority: "P1",
		Level: sarif.LevelNote, SeverityFloor: sarif.SeverityHigh, Location: sarif.Location{URI: "a"}}
	unreachable := sarif.Result{RuleID: "CVE-2026-0200", Control: "sca", Priority: "P1",
		HasScore: true, Score: 7.0, Location: sarif.Location{URI: "b"},
		Reachability: &sarif.Reachability{State: sarif.ReachabilityUnreachable, RankedAs: sarif.SeverityMedium}}
	out := summarized(sarif.Report{Results: []sarif.Result{unreachable, floored}}, "", 0)
	if out.Findings[0].RuleID != "aws-access-token" {
		t.Errorf("the floored high should lead the unreachable medium: %+v", out.Findings)
	}
}

// TestCountsAgreeWithTheVerdict: the counts a summary returns and the verdict a severity gate reaches
// read the same severity, so a summary that says nothing is high cannot sit beside a gate at high
// that failed.
func TestCountsAgreeWithTheVerdict(t *testing.T) {
	fx := movedFindings()
	rep := sarif.Report{Results: resultsOf(fx, "floored", "unmoved")}
	out := summarized(rep, "", 0)
	failed := norn.Policy{FailOn: sarif.SeverityHigh}.Evaluate(map[string]sarif.Report{"": rep}).Verdict == norn.Fail
	atOrAboveHigh := out.Counts.Critical+out.Counts.High > 0
	if !failed || !atOrAboveHigh {
		t.Errorf("verdict failed = %v, counts at or above high = %v (%+v); both should be true",
			failed, atOrAboveHigh, out.Counts)
	}
}

// TestDiffCarriesTheRankedSeverity: new and fixed findings from diff_reports carry both severities,
// and wouldFail on a severity agrees with the rankedSeverity the new findings carry.
func TestDiffCarriesTheRankedSeverity(t *testing.T) {
	fx := movedFindings()
	gone := map[string]sarif.Result{}
	for name, res := range fx {
		res.RuleID += "-OLD"
		gone[name] = res
	}
	base := writeSARIF(t, sarif.Report{Results: resultsOf(gone, movedNames...)})
	head := writeSARIF(t, sarif.Report{Results: resultsOf(fx, movedNames...)})

	_, out, err := DiffReportsTool(context.Background(), nil,
		DiffInput{BasePath: base, HeadPath: head, FailOnNew: "high"})
	if err != nil {
		t.Fatal(err)
	}
	assertBothSeverities(t, "diff_reports new", fx, out.New)
	assertBothSeverities(t, "diff_reports fixed", gone, out.Fixed)
	if !out.WouldFail {
		t.Errorf("new findings ranked high and critical should fail a gate at high: %+v", out)
	}

	// The floored secret alone: medium by its scanner, high as ranked, and the gate judges high.
	secretOnly := writeSARIF(t, sarif.Report{Results: resultsOf(fx, "floored")})
	_, alone, err := DiffReportsTool(context.Background(), nil,
		DiffInput{BasePath: writeSARIF(t, sarif.Report{}), HeadPath: secretOnly, FailOnNew: "high"})
	if err != nil {
		t.Fatal(err)
	}
	if len(alone.New) != 1 || !alone.WouldFail {
		t.Fatalf("a floored secret should fail a gate at high: %+v", alone)
	}
	gated := sarif.Severity(alone.New[0].RankedSeverity).AtLeast(sarif.SeverityHigh)
	if gated != alone.WouldFail {
		t.Errorf("wouldFail = %v but the new finding's rankedSeverity %q says %v",
			alone.WouldFail, alone.New[0].RankedSeverity, gated)
	}
}

// TestFixListRanksAFlooredSecretAtTheFloor: the action that clears a floored secret says it ranked
// at high and that its scanner said medium.
func TestFixListRanksAFlooredSecretAtTheFloor(t *testing.T) {
	fx := movedFindings()
	_, out, err := FixListTool(context.Background(), nil,
		FixListInput{Path: writeSARIF(t, sarif.Report{Results: resultsOf(fx, movedNames...)})})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range allActions(out) {
		if a.Control != "secrets" {
			continue
		}
		if a.Severity != sarif.SeverityHigh || a.SeverityFrom != sarif.SeverityMedium {
			t.Errorf("secret action severity = %q from %q, want high from medium", a.Severity, a.SeverityFrom)
		}
		return
	}
	t.Errorf("no action for the secret: %+v", out.Lists)
}

// TestAcceptedCarriesTheRankedSeverity: an accepted finding says the severity the report prints for
// it, and the accepted list is ordered by that.
func TestAcceptedCarriesTheRankedSeverity(t *testing.T) {
	accept := func(res sarif.Result) sarif.Result {
		res.Suppression = &sarif.Suppression{Kind: "external", Justification: "test fixture", Origin: sarif.OriginSaga}
		return res
	}
	fx := movedFindings()
	// Raw high, ranked high; and raw medium, ranked high by the floor. Then a raw high KEV raised to
	// critical under a rule id that sorts last, which leads only by ranked severity.
	plain := sarif.Result{RuleID: "A-RULE", Level: sarif.LevelError, Location: sarif.Location{URI: "x"}}
	escalated := fx["escalated"]
	escalated.RuleID = "Z-RULE"
	rep := sarif.Report{Results: []sarif.Result{accept(plain), accept(fx["floored"]), accept(escalated)}}
	out := summarized(rep, "", 0)
	if len(out.Accepted) != 3 {
		t.Fatalf("accepted = %+v", out.Accepted)
	}
	if out.Accepted[0].RuleID != "Z-RULE" || out.Accepted[0].RankedSeverity != "critical" {
		t.Errorf("the finding ranked critical should lead: %+v", out.Accepted)
	}
	for _, a := range out.Accepted {
		if a.RuleID == "generic-api-key" && (a.Severity != "medium" || a.RankedSeverity != "high") {
			t.Errorf("floored accepted finding = %+v, want medium as rated and high as ranked", a)
		}
	}
}

// TestScanRanksAnImportedSecretAtTheFloor drives the scan tool end to end on a secret two components
// import, each from its own file, scored medium by the tool that wrote it. The control's floor holds
// both at high, the verdict at the default gate fails on them, and the findings and counts say why.
func TestScanRanksAnImportedSecretAtTheFloor(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"api", "worker"} {
		log := `{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Gitleaks", "version": "8.0.0",
  "rules": [{"id": "generic-api-key", "properties": {"security-severity": "5.5"}}]}},
  "results": [{"ruleId": "generic-api-key", "level": "warning",
  "message": {"text": "Detected a Generic API Key"}, "locations": [{"physicalLocation":
  {"artifactLocation": {"uri": "` + name + `/app.env"}, "region": {"startLine": 1}}}]}]}]}`
		if err := os.WriteFile(filepath.Join(dir, name+".sarif"), []byte(log), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	saga := fmt.Sprintf(`project: shop
components:
  - name: api
    exposure: public
    criticality: critical
    imports:
      - control: secrets
        file: %[1]s/api.sarif
  - name: worker
    exposure: internal
    criticality: supporting
    imports:
      - control: secrets
        file: %[1]s/worker.sarif
`, dir)
	path := filepath.Join(dir, "draugr.saga.yaml")
	if err := os.WriteFile(path, []byte(saga), 0o600); err != nil {
		t.Fatal(err)
	}

	_, out, err := scanTool(builtins.Registry(), ScanAlways, nil)(context.Background(), nil, ScanInput{Path: path})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(out.Findings) != 2 {
		t.Fatalf("want one finding per component, got %+v", out.Findings)
	}
	components := map[string]bool{}
	for _, f := range out.Findings {
		components[f.Component] = true
		if f.Severity != "medium" || f.RankedSeverity != "high" || f.SeverityFloor != "high" {
			t.Errorf("finding = severity %q, rankedSeverity %q, severityFloor %q; want medium, high, high",
				f.Severity, f.RankedSeverity, f.SeverityFloor)
		}
	}
	if len(components) != 2 {
		t.Errorf("findings collapsed onto %v", components)
	}
	if out.Verdict != "fail" || out.Counts.High != 2 || out.Counts.Medium != 0 {
		t.Errorf("verdict %q with counts %+v; a gate at high fails on two secrets ranked high", out.Verdict, out.Counts)
	}
}
