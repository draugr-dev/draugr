package sarif

import (
	"strings"
	"testing"
)

// The checks left for a person survive the file, outside the results, with the rules they report
// under, so `draugr explain` can say what a check asks.
func TestUnsettledChecksSurviveTheFileOutsideTheResults(t *testing.T) {
	t.Parallel()
	reviewed := &Suppression{Kind: "external", Justification: "reviewed 2026-11-13", Source: "draugr.saga.yaml"}
	in := Merge(
		Report{Tool: "draugr-k8s-policies", Rules: map[string]Rule{
			"draugr/cis/5.1.10": {ShortDescription: "Minimize access to the proxy sub-resource of nodes"},
		}, UnsettledChecks: []UnsettledCheck{
			{Scanner: "draugr-k8s-policies", RuleID: "draugr/cis/5.1.10", Title: "Minimize access to the proxy sub-resource of nodes",
				Control: "kubernetes", Component: "api", Location: "kubernetes/staging", Kind: UnsettledManual},
		}},
		Report{Tool: "kube-bench", Rules: map[string]Rule{
			"kube-bench/cis/5.1.11": {ShortDescription: "Minimize access to the approval sub-resource"},
		}, UnsettledChecks: []UnsettledCheck{
			{Scanner: "kube-bench", RuleID: "kube-bench/cis/5.1.11", Component: "web", Location: "kubernetes/production",
				Kind: UnsettledManual, Suppression: reviewed},
		}},
	)
	data, err := in.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"results": [
        {`) {
		t.Errorf("a check left for a person was written as a result:\n%s", data)
	}
	out, err := FromSARIF(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Results) != 0 || len(out.UnsettledChecks) != 2 {
		t.Fatalf("read back %d results and %+v, want none and both checks", len(out.Results), out.UnsettledChecks)
	}
	if out.UnsettledChecks[0] != in.UnsettledChecks[0] {
		t.Errorf("first check read back as %+v, want %+v", out.UnsettledChecks[0], in.UnsettledChecks[0])
	}
	second := out.UnsettledChecks[1]
	if second.Suppression == nil || second.Suppression.Justification != "reviewed 2026-11-13" || second.Location != "kubernetes/production" {
		t.Errorf("second check read back as %+v, want its exclusion kept", second)
	}
	for _, id := range []string{"draugr/cis/5.1.10", "kube-bench/cis/5.1.11"} {
		if _, ok := out.Rules[id]; !ok {
			t.Errorf("rule %s was not written, so explain cannot read it", id)
		}
	}
	if got := out.Rules["draugr/cis/5.1.10"].ShortDescription; got != "Minimize access to the proxy sub-resource of nodes" {
		t.Errorf("rule description = %q", got)
	}
}
