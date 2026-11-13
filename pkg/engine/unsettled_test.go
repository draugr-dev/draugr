package engine

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// referred is a check a scanner left for a person on one cluster.
func referred(tool, rule, cluster string) sarif.Result {
	r := checked(tool, rule, sarif.LevelWarning, cluster)
	r.Message = rule + ", requires manual review"
	r.Undecided = true
	return r
}

func TestAChecksLeftForAPersonAreNotFindings(t *testing.T) {
	// Two clusters, so a list keyed on the cluster is seen not to collapse them.
	rules := map[string]sarif.Rule{
		"draugr/cis/5.1.1":  cisRule("5.1.1", "cis-1.12"),
		"draugr/cis/5.1.10": {ShortDescription: "Minimize access to the proxy sub-resource of nodes", Taxa: cisRule("5.1.10", "cis-1.12").Taxa},
	}
	failing := checked("draugr-k8s-policies", "draugr/cis/5.1.1", sarif.LevelWarning, "staging")
	ctrls := kubernetesControl(rules,
		failing,
		referred("draugr-k8s-policies", "draugr/cis/5.1.10", "staging"),
		referred("draugr-k8s-policies", "draugr/cis/5.1.10", "production"),
	)
	if n := setUnsettledApart(ctrls); n != 0 {
		t.Errorf("left suppressed = %d, want 0", n)
	}
	rep := ctrls["kubernetes"].Report
	if len(rep.Results) != 1 || rep.Results[0].RuleID != "draugr/cis/5.1.1" {
		t.Fatalf("results = %+v, want only the failing check", rep.Results)
	}
	if ctrls["kubernetes"].Summary.Warnings != 1 {
		t.Errorf("summary warnings = %d, want the failing check alone", ctrls["kubernetes"].Summary.Warnings)
	}
	if len(rep.UnsettledChecks) != 2 {
		t.Fatalf("unsettled = %+v, want the check on each cluster", rep.UnsettledChecks)
	}
	for i, cluster := range []string{"kubernetes/staging", "kubernetes/production"} {
		u := rep.UnsettledChecks[i]
		if u.Location != cluster || u.RuleID != "draugr/cis/5.1.10" || u.Kind != sarif.UnsettledManual || u.Control != "kubernetes" ||
			u.Title != "Minimize access to the proxy sub-resource of nodes" || u.Scanner != "draugr-k8s-policies" {
			t.Errorf("unsettled[%d] = %+v, want 5.1.10 on %s with its title", i, u, cluster)
		}
	}
}

func TestACheckLeftForAPersonIsListedOnceWhateverReportedIt(t *testing.T) {
	// Both scanners left 5.1.10 for a person: one entry, under the copy correlation counted.
	rules := bothScanners("5.1.10")
	ctrls := kubernetesControl(rules,
		referred("draugr-k8s-policies", "draugr/cis/5.1.10", "kind"),
		referred("kube-bench", "kube-bench/cis/5.1.10", "kind"),
	)
	applyCorrelation(ctrls)
	setUnsettledApart(ctrls)
	rep := ctrls["kubernetes"].Report
	if len(rep.Results) != 0 || len(rep.UnsettledChecks) != 1 {
		t.Fatalf("results %d, unsettled %+v; want none and one", len(rep.Results), rep.UnsettledChecks)
	}
}

func TestAReferralOfACheckAnotherScannerDecidedIsNotListed(t *testing.T) {
	// Draugr's scanner decided 5.2.10 and it passed, so it reported nothing; kube-bench referred it.
	kb := cisRule("5.2.10", "cis-1.12")
	ctrls := kubernetesControl(map[string]sarif.Rule{"kube-bench/cis/5.2.10": kb},
		referred("kube-bench", "kube-bench/cis/5.2.10", "kind"))
	cr := ctrls["kubernetes"]
	cr.Report.Decided = kb.Taxa
	ctrls["kubernetes"] = cr
	setUnsettledApart(ctrls)
	if rep := ctrls["kubernetes"].Report; len(rep.Results) != 0 || len(rep.UnsettledChecks) != 0 {
		t.Errorf("results %d, unsettled %+v; want neither", len(rep.Results), rep.UnsettledChecks)
	}
}

func TestAnExcludedCheckLeftForAPersonKeepsItsReason(t *testing.T) {
	// Excluding a manual check is how its review is recorded. It keeps the reason, and leaves the
	// count of suppressed findings, which it never was.
	reviewed := referred("draugr-k8s-policies", "draugr/cis/5.1.10", "kind")
	reviewed.Suppression = &sarif.Suppression{Kind: "external", Justification: "reviewed 2026-11-13"}
	ctrls := map[string]plugin.ControlResult{"kubernetes": {Control: "kubernetes", Report: sarif.Report{
		Results: []sarif.Result{reviewed},
		Rules:   map[string]sarif.Rule{"draugr/cis/5.1.10": cisRule("5.1.10", "cis-1.12")},
	}}}
	if n := setUnsettledApart(ctrls); n != 1 {
		t.Errorf("left suppressed = %d, want the excluded check", n)
	}
	u := ctrls["kubernetes"].Report.UnsettledChecks
	if len(u) != 1 || u[0].Suppression == nil || u[0].Suppression.Justification != "reviewed 2026-11-13" {
		t.Errorf("unsettled = %+v, want the check with its reason", u)
	}
	// The title falls back to the finding's message where the rule gives none.
	if u[0].Title != "draugr/cis/5.1.10, requires manual review" {
		t.Errorf("title = %q, want the message", u[0].Title)
	}
}

func TestAControlWithNothingLeftForAPersonIsUntouched(t *testing.T) {
	ctrls := controlsWith(found("trivy", "CVE-2024-11111", "pkg:pypi/flask@0.12.2", sarif.LevelError, 8.7))
	before := ctrls["sca"].Summary
	setUnsettledApart(ctrls)
	if len(ctrls["sca"].Report.Results) != 1 || ctrls["sca"].Summary != before {
		t.Errorf("a control with no unsettled check changed: %+v", ctrls["sca"])
	}
}
