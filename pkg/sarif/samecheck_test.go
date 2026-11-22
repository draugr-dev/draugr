package sarif

import (
	"strings"
	"testing"
)

func TestSameCheckAsNamesTheOtherToolsRule(t *testing.T) {
	t.Parallel()
	taxon := SameCheckAs("Trivy", "KSV-0017", "Privileged")
	if taxon.Taxonomy != "Trivy rules" || taxon.ID != "KSV-0017" || taxon.Name != "Privileged" {
		t.Errorf("taxon = %+v", taxon)
	}
	tool, id, ok := taxon.SameCheck()
	if !ok || tool != "Trivy" || id != "KSV-0017" {
		t.Errorf("SameCheck = %q %q %v", tool, id, ok)
	}
	for _, other := range []Taxon{
		{Taxonomy: "CWE", ID: "269"},
		{Taxonomy: "CIS-Kubernetes", ID: "5.2.1", Version: "cis-1.12"},
		{Taxonomy: " rules", ID: "x"},
		{Taxonomy: "Trivy rules"},
	} {
		if _, _, ok := other.SameCheck(); ok {
			t.Errorf("%+v read as a statement of the same check", other)
		}
	}
}

// Trivy gives a Kubernetes container's check the region of the whole container. The end is read so
// another tool's finding inside it can be recognized, and Draugr's own SARIF does not write it back.
func TestTheRegionsEndLineIsReadAndNotWritten(t *testing.T) {
	t.Parallel()
	rep, err := FromSARIF([]byte(`{"runs":[{"tool":{"driver":{"name":"Trivy"}},"results":[
	  {"ruleId":"KSV-0017","level":"error","message":{"text":"m"},
	   "locations":[{"physicalLocation":{"artifactLocation":{"uri":"web.yaml"},"region":{"startLine":17,"endLine":22}}}]},
	  {"ruleId":"DS-0002","level":"error","message":{"text":"m"},
	   "locations":[{"physicalLocation":{"artifactLocation":{"uri":"Dockerfile"},"region":{"startLine":4,"endLine":4}}}]}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := rep.Results[0].Location; got != (Location{URI: "web.yaml", StartLine: 17, EndLine: 22}) {
		t.Errorf("location = %+v", got)
	}
	if got := rep.Results[1].Location; got.EndLine != 0 {
		t.Errorf("a one-line region kept an end line: %+v", got)
	}
	a, b := rep.Results[0], rep.Results[0]
	b.Location.EndLine = 0
	if a.Fingerprint() != b.Fingerprint() {
		t.Error("the end line moved the fingerprint, which has always keyed on the start")
	}
	out, err := rep.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "endLine") {
		t.Errorf("Draugr's SARIF wrote an end line:\n%s", out)
	}
}
