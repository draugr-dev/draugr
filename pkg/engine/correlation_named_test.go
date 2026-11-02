package engine

import (
	"reflect"
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// dompurify is one DOMPurify advisory in one component's repository, as retire.js reports it in a
// vendored copy, under its CVE with the GitHub advisory id beside it, or as Trivy reports it in the
// lockfile, under the GitHub advisory id alone.
func dompurify(tool, component, repo, cve, ghsa string, level sarif.Level, score float64) sarif.Result {
	r := sarif.Result{
		Tool: tool, RuleID: ghsa, Level: level, Score: score, HasScore: true,
		Component: component, Repository: repo,
		Location: sarif.Location{URI: "package-lock.json", StartLine: 15},
		Package: &sarif.Package{Name: "dompurify", Version: "3.4.16", FixedVersion: "3.4.17",
			Ecosystem: "npm", PURL: "pkg:npm/dompurify@3.4.16"},
	}
	if tool == "retirejs" {
		r.RuleID, r.Aliases = cve, []string{ghsa}
		r.Location = sarif.Location{URI: "static/purify.js"}
	}
	return r
}

// counted is each finding correlation counts, by component, as "tool rule".
func counted(results []sarif.Result) map[string][]string {
	out := map[string][]string{}
	for _, r := range results {
		if !r.Correlated() {
			out[r.Component] = append(out[r.Component], r.Tool+" "+r.RuleID)
		}
	}
	return out
}

// retire.js keys a vendored DOMPurify's flaw on its CVE and names the GitHub advisory id beside it;
// Trivy keys the lockfile's copy on the GitHub id. The finding's own alias makes them one flaw,
// counted under the stronger reading, which names the other copy by its rule id. Over two
// components in two repositories, each counts its own.
func TestCorrelationJoinsTheIdentifiersAScannerReportedForOneFinding(t *testing.T) {
	const cve, ghsa = "CVE-2026-116804", "GHSA-cg2g-xh64-v4q7"
	ctrls := controlsWith(
		dompurify("retirejs", "api", "repo-api", cve, ghsa, sarif.LevelError, 9.5),
		dompurify("trivy", "api", "repo-api", cve, ghsa, sarif.LevelError, 9.2),
		dompurify("retirejs", "web", "repo-web", cve, ghsa, sarif.LevelError, 9.5),
		dompurify("trivy", "web", "repo-web", cve, ghsa, sarif.LevelError, 9.2),
	)
	if groups, _ := applyCorrelation(ctrls); groups != 2 {
		t.Fatalf("groups = %d, want one flaw per component", groups)
	}
	want := map[string][]string{"api": {"retirejs " + cve}, "web": {"retirejs " + cve}}
	if got := counted(ctrls["sca"].Report.Results); !reflect.DeepEqual(got, want) {
		t.Errorf("counted = %v, want %v", got, want)
	}
	for _, r := range ctrls["sca"].Report.Results {
		if r.Correlated() {
			if r.Correlation.CountedUnder != "retirejs" {
				t.Errorf("%s %s: counted under %q, want retirejs", r.Component, r.Tool, r.Correlation.CountedUnder)
			}
			continue
		}
		if also := r.Correlation.AlsoFoundBy; len(also) != 1 || also[0].Tool != "trivy" || also[0].RuleID != ghsa {
			t.Errorf("%s: alsoFoundBy = %+v, want trivy under %s", r.Component, also, ghsa)
		}
	}
}

// The alias joins in either direction: the finding naming the other identifier may be the weaker
// copy, and the counted one is still the stronger reading.
func TestCorrelationCountsTheStrongerReadingAcrossIdentifiers(t *testing.T) {
	const cve, ghsa = "CVE-2026-116803", "GHSA-mrv2-3pqr-j5jr"
	ctrls := controlsWith(
		dompurify("trivy", "api", "repo-api", cve, ghsa, sarif.LevelError, 7.6),
		dompurify("retirejs", "api", "repo-api", cve, ghsa, sarif.LevelWarning, 5.0),
	)
	if groups, _ := applyCorrelation(ctrls); groups != 1 {
		t.Fatalf("groups = %d, want 1", groups)
	}
	if got := counted(ctrls["sca"].Report.Results); !reflect.DeepEqual(got, map[string][]string{"api": {"trivy " + ghsa}}) {
		t.Errorf("counted = %v, want trivy's stronger reading", got)
	}
}

// An identifier is joined only where the finding itself names it, in the same component, repository
// and package. Another package's advisory under that identifier, or the same package in another
// repository, stays its own finding.
func TestCorrelationJoinsAnIdentifierOnlyWithinTheFindingsSubject(t *testing.T) {
	const cve, ghsa = "CVE-2026-116802", "GHSA-c6gr-qvv4-5v3f"
	elsewhere := dompurify("trivy", "api", "repo-other", cve, ghsa, sarif.LevelNote, 2.0)
	otherPackage := dompurify("trivy", "api", "repo-api", cve, ghsa, sarif.LevelNote, 2.0)
	otherPackage.Package = &sarif.Package{Name: "isomorphic-dompurify", Version: "2.0.0", PURL: "pkg:npm/isomorphic-dompurify@2.0.0"}
	unnamed := dompurify("retirejs", "api", "repo-api", cve, ghsa, sarif.LevelNote, 2.0)
	unnamed.Aliases = nil
	ctrls := controlsWith(
		dompurify("retirejs", "api", "repo-api", cve, ghsa, sarif.LevelNote, 2.0),
		elsewhere, otherPackage,
	)
	if groups, _ := applyCorrelation(ctrls); groups != 0 {
		t.Errorf("groups = %d, want none outside the finding's own repository and package", groups)
	}
	// A finding that names no other identifier is keyed on its rule id alone, as before.
	ctrls = controlsWith(unnamed, dompurify("trivy", "api", "repo-api", cve, ghsa, sarif.LevelNote, 2.0))
	if groups, _ := applyCorrelation(ctrls); groups != 0 {
		t.Errorf("groups = %d, want none without an alias", groups)
	}
}

// retire.js lists two CVEs on one entry, and Trivy reports them as two findings. Trivy has said the
// two are two flaws, so retire.js's entry joins the one its rule id names and the other stays counted.
func TestCorrelationDoesNotJoinTwoFindingsOneScannerReportedApart(t *testing.T) {
	retire := dompurify("retirejs", "api", "repo-api", "CVE-2026-10001", "", sarif.LevelError, 8.0)
	retire.Aliases = []string{"CVE-2026-10002"}
	first := dompurify("trivy", "api", "repo-api", "", "CVE-2026-10001", sarif.LevelError, 8.0)
	second := dompurify("trivy", "api", "repo-api", "", "CVE-2026-10002", sarif.LevelError, 8.0)
	ctrls := controlsWith(retire, first, second)
	if groups, _ := applyCorrelation(ctrls); groups != 1 {
		t.Fatalf("groups = %d, want retire.js's finding joined with one of Trivy's", groups)
	}
	if got := counted(ctrls["sca"].Report.Results)["api"]; len(got) != 2 {
		t.Errorf("counted = %v, want both of Trivy's flaws", got)
	}
}

// The reachability summary groups findings as correlation does. A verdict on Trivy's copy of a flaw
// retire.js's stronger copy is counted under is that flaw's verdict, counted once.
func TestReachabilityIsRecountedOverTheJoinedFlaw(t *testing.T) {
	const cve, ghsa = "CVE-2026-116804", "GHSA-cg2g-xh64-v4q7"
	trivy := dompurify("trivy", "api", "repo-api", cve, ghsa, sarif.LevelWarning, 5.0)
	trivy.Reachability = &sarif.Reachability{State: sarif.ReachabilityUnreachable, Analyzer: "analyzer", Method: "call-graph"}
	ctrls := controlsWith(dompurify("retirejs", "api", "repo-api", cve, ghsa, sarif.LevelError, 9.5), trivy)
	applyCorrelation(ctrls)
	got := recountReachability(ctrls, ReachabilitySummary{Analyzers: []AnalyzerReachability{{Analyzer: "analyzer"}}})
	if got.Unreachable != 1 || got.Reachable+got.Unknown != 0 {
		t.Errorf("summary = %+v, want the one flaw counted unreachable", got)
	}
}
