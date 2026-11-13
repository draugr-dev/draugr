package report

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// leftForAPerson is a run whose kubernetes control left checks for a person on two clusters, one of
// them excluded as reviewed, beside a scanner that states no coverage.
func leftForAPerson(evidence bool) Data {
	reviewed := &sarif.Suppression{Kind: "external", Justification: "reviewed 2026-11-13: only system roles hold these"}
	check := func(rule, title, cluster string, s *sarif.Suppression) sarif.UnsettledCheck {
		return sarif.UnsettledCheck{Scanner: "draugr-k8s-policies", RuleID: rule, Title: title,
			Location: "kubernetes/" + cluster, Kind: sarif.UnsettledManual, Suppression: s}
	}
	return Data{Evidence: evidence, Run: engine.Result{Controls: map[string]plugin.ControlResult{
		"kubernetes": {Control: "kubernetes", Report: sarif.Report{
			Provenance: []sarif.Provenance{
				{Tool: "draugr-k8s-policies", Fields: []sarif.Field{
					{Key: "benchmark", Value: "cis-1.12"}, {Key: "coverage", Value: "20 of 34 checks decided"},
				}},
				{Tool: "kube-bench", Fields: []sarif.Field{{Key: "benchmark", Value: "cis-1.12"}}},
			},
			UnsettledChecks: []sarif.UnsettledCheck{
				check("draugr/cis/5.1.8", "Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster", "staging", nil),
				check("draugr/cis/5.1.10", "Minimize access to the proxy sub-resource of nodes", "staging", reviewed),
				check("draugr/cis/5.1.8", "Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster", "production", nil),
				{Scanner: "kube-bench", RuleID: "kube-bench/cis/5.4.2", Title: "Consider external secret storage",
					Location: "kubernetes/production", Kind: sarif.UnsettledManual},
			},
		}},
	}}}
}

func TestTheCoverageLineCountsWhatWasLeftForAPerson(t *testing.T) {
	// Every format: the count beside the coverage, or as its own fact where a scanner states none.
	lines := provenanceLines(leftForAPerson(false))
	draugr := "benchmark: cis-1.12 · coverage: 20 of 34 checks decided, 2 left for a person, 1 excluded"
	kube := "benchmark: cis-1.12 · 1 left for a person"
	if len(lines) != 2 || lines[0].Detail != draugr || lines[1].Detail != kube {
		t.Fatalf("got %+v\nwant %q and %q", lines, draugr, kube)
	}
	// The console says where they are listed, except under --evidence, where the list is on the screen.
	lines[0].Detail += " · scope: whole cluster"
	if got := measuredText(lines[0], false); !strings.HasSuffix(got, ", 2 left for a person, 1 excluded · --evidence lists them · scope: whole cluster") {
		t.Errorf("console row = %q, want it to say --evidence lists them", got)
	}
	if got := measuredText(lines[1], true); strings.Contains(got, "--evidence") {
		t.Errorf("console row under --evidence = %q, want no pointer", got)
	}
}

func TestEvidenceListsWhatWasLeftForAPersonByCluster(t *testing.T) {
	t.Setenv("COLUMNS", "80")
	var buf bytes.Buffer
	writeEvidence(&buf, tui.Plain(), leftForAPerson(true), "  ")
	out := buf.String()
	for _, want := range []string{
		"  unsettled   kubernetes/production · 2 left for a person\n",
		"                draugr/cis/5.1.8      Limit use of the Bind, Impersonate and Es…\n",
		"                kube-bench/cis/5.4.2  Consider external secret storage\n",
		"              kubernetes/staging · 1 left for a person, 1 excluded\n",
		"                draugr/cis/5.1.10     excluded · reviewed 2026-11-13: only syst…\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("evidence lacks %q:\n%s", want, out)
		}
	}
	// Production before staging: the list is by location, so one cluster's checks sit together.
	if strings.Index(out, "kubernetes/production") > strings.Index(out, "kubernetes/staging") {
		t.Errorf("clusters out of order:\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if n := utf8.RuneCountInString(line); n > 80 {
			t.Errorf("line is %d columns at 80: %q", n, line)
		}
	}
}

func TestARunWithNothingLeftForAPersonSaysNothingAboutIt(t *testing.T) {
	d := leftForAPerson(false)
	cr := d.Run.Controls["kubernetes"]
	cr.Report.UnsettledChecks = nil
	d.Run.Controls["kubernetes"] = cr
	lines := provenanceLines(d)
	if len(lines) != 2 || strings.Contains(lines[0].Detail, "person") || lines[1].Detail != "benchmark: cis-1.12" {
		t.Errorf("lines = %+v, want the provenance as the scanners stated it", lines)
	}
	var buf bytes.Buffer
	writeEvidence(&buf, tui.Plain(), d, "  ")
	if strings.Contains(buf.String(), "unsettled") {
		t.Errorf("evidence lists an empty unsettled block:\n%s", buf.String())
	}
}
