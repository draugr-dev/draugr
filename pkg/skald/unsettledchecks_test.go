package skald

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// report.json lists each check left for a person apart from the findings, over two components on
// two clusters, and an excluded one with the reason somebody gave.
func TestReportJSONListsTheChecksLeftForAPerson(t *testing.T) {
	check := func(component, cluster string, s *sarif.Suppression) sarif.UnsettledCheck {
		return sarif.UnsettledCheck{Scanner: "draugr-k8s-policies", RuleID: "draugr/cis/5.1.10",
			Title: "Minimize access to the proxy sub-resource of nodes", Component: component,
			Location: "kubernetes/" + cluster, Kind: sarif.UnsettledManual, Suppression: s}
	}
	reviewed := &sarif.Suppression{Kind: "external", Justification: "reviewed 2026-11-13", Source: "draugr.saga.yaml"}
	run := engine.Result{Controls: map[string]plugin.ControlResult{"kubernetes": {Control: "kubernetes", Report: sarif.Report{
		Tool: "draugr-k8s-policies",
		UnsettledChecks: []sarif.UnsettledCheck{
			check("api", "staging", nil),
			check("web", "production", reviewed),
		},
	}}}}
	doc := renderJSON(t, run, "P4")
	if findings, _ := doc["findings"].([]any); len(findings) != 0 {
		t.Errorf("findings = %v, want none: a check left for a person is not a finding", findings)
	}
	entries, ok := doc["unsettledChecks"].([]any)
	if !ok || len(entries) != 2 {
		t.Fatalf("unsettledChecks = %v, want both", doc["unsettledChecks"])
	}
	first := entries[0].(map[string]any)
	for key, want := range map[string]string{
		"component": "api", "control": "kubernetes", "scanner": "draugr-k8s-policies", "ruleId": "draugr/cis/5.1.10",
		"title": "Minimize access to the proxy sub-resource of nodes", "location": "kubernetes/staging", "kind": "manual",
	} {
		if first[key] != want {
			t.Errorf("first[%s] = %v, want %q", key, first[key], want)
		}
	}
	if _, present := first["suppressed"]; present {
		t.Errorf("a check still waiting on a person carries suppressed: %v", first)
	}
	second := entries[1].(map[string]any)
	sup, _ := second["suppressed"].(map[string]any)
	if second["location"] != "kubernetes/production" || sup["justification"] != "reviewed 2026-11-13" || sup["source"] != "draugr.saga.yaml" {
		t.Errorf("second = %v, want production's check with its exclusion", second)
	}
}
