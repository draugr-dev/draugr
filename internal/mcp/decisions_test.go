package mcp

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// decisionsReport is two components, each with a live finding and an accepted one, one accepted by
// the descriptor and one by a supplier's VEX statement, plus a flaw two scanners both reported.
func decisionsReport() sarif.Report {
	return sarif.Report{
		Consulted: []sarif.Consulted{
			{Signal: "epss", AsOf: "2026-09-01", Stale: true, Entries: 2, Threshold: 0.5},
			{Signal: "kev", AsOf: "2026-09-24", Entries: 1},
		},
		Results: []sarif.Result{
			{RuleID: "CVE-2021-44228", Tool: "trivy-fs", Level: sarif.LevelError, Priority: "P1",
				Component: "api", Location: sarif.Location{URI: "api/pom.xml", StartLine: 12},
				Package: &sarif.Package{Name: "log4j-core", Version: "2.14.1", FixedVersion: "2.17.1"},
				Escalation: &sarif.Escalation{
					From: sarif.SeverityHigh, To: sarif.SeverityCritical, Signal: "kev",
					Detail: "on CISA's Known Exploited Vulnerabilities list", AsOf: "2026-09-24",
				},
				Correlation: &sarif.Correlation{AlsoFoundBy: []sarif.Observation{{Tool: "grype"}}}},
			{RuleID: "CVE-2021-44228", Tool: "grype", Level: sarif.LevelError, Priority: "P1",
				Component: "api", Correlation: &sarif.Correlation{CountedUnder: "trivy-fs"}},
			{RuleID: "GO-2024-2687", Tool: "govulncheck", Level: sarif.LevelWarning, Priority: "P3",
				Component: "worker", Location: sarif.Location{URI: "worker/go.mod"},
				Package: &sarif.Package{Name: "golang.org/x/net", Version: "0.21.0"},
				Reachability: &sarif.Reachability{
					State: sarif.ReachabilityReachable, Analyzer: "govulncheck", Method: "symbol",
					Symbols: []string{"http2.Server.ServeConn"},
					Paths: []sarif.CallPath{{Frames: []sarif.CallFrame{
						{Function: "main", Package: "worker", File: "main.go", Line: 9},
						{Function: "Server.ServeConn", Package: "http2"},
					}}},
				}},
			{RuleID: "CVE-2023-0001", Tool: "trivy-fs", Level: sarif.LevelWarning, Component: "api",
				Location: sarif.Location{URI: "api/pom.xml"},
				Suppression: &sarif.Suppression{
					Kind: "external", Justification: "test scope only", AcceptedBy: "sec@example.com",
					Expires: "2026-12-31", Origin: "saga", Source: "fragments/api.saga.yaml",
				}},
			{RuleID: "CVE-2023-0002", Tool: "trivy-fs", Level: sarif.LevelError, Component: "worker",
				Package: &sarif.Package{Name: "openssl", Version: "3.0.1"},
				Suppression: &sarif.Suppression{
					Kind: "external", Justification: "vulnerable_code_not_in_execute_path",
					Origin: "vex", Author: "Example Inc", Asserted: "2026-06-01",
					Source: "vex/worker.openvex.json", VEXStatus: "not_affected",
					VEXJustification: "vulnerable_code_not_in_execute_path",
				}},
		},
	}
}

// The decision travels with the finding it took out of the ranking, and never as work: who
// accepted it, why, until when, and whether the analysis was this project's or a supplier's.
func TestSummarizeReturnsEachAcceptedFindingWithItsDecision(t *testing.T) {
	out := summarize(decisionsReport(), "", 20)

	for _, f := range out.Findings {
		if strings.HasPrefix(f.RuleID, "CVE-2023-") {
			t.Errorf("accepted finding %s returned as work", f.RuleID)
		}
	}
	if out.Suppressed != 2 || len(out.Accepted) != 2 {
		t.Fatalf("suppressed=%d accepted=%d, want 2 and 2", out.Suppressed, len(out.Accepted))
	}
	// Most severe first: the error-level VEX claim before the warning-level descriptor rule.
	want := []Accepted{
		{RuleID: "CVE-2023-0002", Severity: "high", Component: "worker", Package: "openssl",
			Version: "3.0.1", Justification: "vulnerable_code_not_in_execute_path", Origin: "vex",
			Author: "Example Inc", Asserted: "2026-06-01", Source: "vex/worker.openvex.json",
			VEXStatus: "not_affected", VEXJustification: "vulnerable_code_not_in_execute_path"},
		{RuleID: "CVE-2023-0001", Severity: "medium", Component: "api", Location: "api/pom.xml",
			Justification: "test scope only", AcceptedBy: "sec@example.com", Expires: "2026-12-31",
			Origin: "saga", Source: "fragments/api.saga.yaml"},
	}
	if !reflect.DeepEqual(out.Accepted, want) {
		t.Errorf("accepted =\n %+v\nwant\n %+v", out.Accepted, want)
	}
}

// The list is capped like the findings, and the count stays whole, so a truncated list reads as
// truncated rather than as everything that was decided.
func TestAcceptedIsCappedAndTheCountIsNot(t *testing.T) {
	out := summarize(decisionsReport(), "", 1)
	if out.Suppressed != 2 || len(out.Accepted) != 1 || out.Accepted[0].RuleID != "CVE-2023-0002" {
		t.Errorf("suppressed=%d accepted=%+v, want 2 counted and the most severe returned",
			out.Suppressed, out.Accepted)
	}
}

func TestFindingsCarryReachabilityAndEscalation(t *testing.T) {
	out := summarize(decisionsReport(), "", 20)
	byRule := map[string]Finding{}
	for _, f := range out.Findings {
		byRule[f.RuleID] = f
	}

	log4j := byRule["CVE-2021-44228"]
	wantEsc := &Escalation{From: "high", To: "critical", Signal: "kev",
		Detail: "on CISA's Known Exploited Vulnerabilities list", AsOf: "2026-09-24"}
	if !reflect.DeepEqual(log4j.Escalation, wantEsc) {
		t.Errorf("escalation = %+v, want %+v", log4j.Escalation, wantEsc)
	}

	net := byRule["GO-2024-2687"]
	wantReach := &Reachability{State: "reachable", Analyzer: "govulncheck", Method: "symbol",
		Symbols: []string{"http2.Server.ServeConn"},
		Path:    []string{"worker.main (main.go:9)", "http2.Server.ServeConn"}}
	if !reflect.DeepEqual(net.Reachability, wantReach) {
		t.Errorf("reachability = %+v, want %+v", net.Reachability, wantReach)
	}
	if log4j.Reachability != nil || net.Escalation != nil {
		t.Error("a decision that was never made was reported")
	}
}

// Two scanners reporting one flaw is one finding, as the gate counts it, and the second scanner is
// named on it rather than dropped.
func TestACorrelatedCopyIsCountedOnceAndNamed(t *testing.T) {
	out := summarize(decisionsReport(), "", 20)
	if out.Total != 2 || out.Counts.High != 1 {
		t.Errorf("total=%d counts=%+v, want the grype copy counted under trivy-fs", out.Total, out.Counts)
	}
	for _, f := range out.Findings {
		if f.Scanner == "grype" {
			t.Error("the correlated copy was returned as its own finding")
		}
		if f.RuleID == "CVE-2021-44228" && !reflect.DeepEqual(f.AlsoFoundBy, []string{"grype"}) {
			t.Errorf("alsoFoundBy = %v, want [grype]", f.AlsoFoundBy)
		}
	}
}

// Feeds survive the trip through results.sarif, staleness included, because summarize_report reads
// a file somebody else's scan wrote and the scan is the only thing that knew its maxAge.
func TestSummarizeReportReadsFeedStalenessFromTheFile(t *testing.T) {
	data, err := decisionsReport().MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "results.sarif")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	_, out, err := SummarizeReportTool(context.Background(), nil, SummarizeInput{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	want := []Feed{
		{Signal: "epss", AsOf: "2026-09-01", Stale: true, Entries: 2, Threshold: 0.5},
		{Signal: "kev", AsOf: "2026-09-24", Entries: 1},
	}
	if !reflect.DeepEqual(out.Feeds, want) {
		t.Errorf("feeds =\n %+v\nwant\n %+v", out.Feeds, want)
	}
	if len(out.Accepted) != 2 || out.Accepted[1].Source != "fragments/api.saga.yaml" {
		t.Errorf("the decisions did not survive the file: %+v", out.Accepted)
	}
}

func TestNoFeedsMeansNoneWereConsulted(t *testing.T) {
	out := summarize(sarif.Report{Results: []sarif.Result{{RuleID: "r", Level: sarif.LevelError}}}, "", 0)
	if out.Feeds != nil {
		t.Errorf("feeds = %+v, want none for a scan that loaded no exploitability data", out.Feeds)
	}
}

func TestNextNamesTheFirstFindingAndWhatToDo(t *testing.T) {
	finding := func(p *sarif.Package, mod func(*sarif.Result)) sarif.Report {
		r := sarif.Result{RuleID: "R-1", Level: sarif.LevelError, Package: p,
			Location: sarif.Location{URI: "go.mod", StartLine: 3}}
		if mod != nil {
			mod(&r)
		}
		return sarif.Report{Results: []sarif.Result{r}}
	}
	for name, tc := range map[string]struct {
		rep  sarif.Report
		min  string
		want string
	}{
		"upgrade": {rep: finding(&sarif.Package{Name: "x/net", FixedVersion: "0.23.0"}, nil),
			want: "Start with R-1 in go.mod:3: upgrade x/net to 0.23.0. Then scan again to confirm it is gone."},
		"upstream": {rep: finding(nil, func(r *sarif.Result) { r.OSEndOfLife = true }),
			want: "Start with R-1 in go.mod:3: move to a supported operating system release, which fixes every finding in that layer. Then scan again to confirm it is gone."},
		"external": {rep: finding(nil, func(r *sarif.Result) { r.ProviderOperated = true }),
			want: "Start with R-1 in go.mod:3: report it to whoever operates the surface; nothing in this project changes it. Then scan again to confirm it is gone."},
		"none": {rep: finding(nil, nil),
			want: "Start with R-1 in go.mod:3: no fix is published; remove the dependency or record an acceptance with an expiry. Then scan again to confirm it is gone."},
		"filtered": {rep: finding(nil, func(r *sarif.Result) { r.Priority = "P4" }), min: "p1",
			want: "Nothing at or above P1. Lower minPriority to see the 1 below it."},
		"clean": {rep: sarif.Report{},
			want: "Nothing to fix in the controls that ran."},
	} {
		t.Run(name, func(t *testing.T) {
			if got := summarize(tc.rep, tc.min, 0).Next; got != tc.want {
				t.Errorf("next =\n %s\nwant\n %s", got, tc.want)
			}
		})
	}
}
