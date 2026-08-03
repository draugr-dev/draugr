package sarif

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"
)

// Two scanners, two namespaced rule ids, one shared taxon — the whole point of taxa.
//
// Namespacing the rule ids removed the accidental correspondence between draugr-draugr-k8s-policies and
// kube-bench; this is what puts it back at the layer where it belongs. A consumer that has never
// heard of Draugr can group these two findings by the CIS control they both implement, and it
// does so from a published vocabulary rather than from two ids happening to collide.
func TestTaxaCorrelateTwoScannersOnOneControl(t *testing.T) {
	rep := Report{Tool: "draugr-draugr-k8s-policies", Rules: map[string]Rule{
		"draugr/cis/5.1.1": {Name: "CIS 5.1.1", Taxa: []Taxon{
			{Taxonomy: "CIS-Kubernetes", ID: "5.1.1", Name: "Minimize wildcard use", Version: "cis-1.12"}}},
		"kube-bench/cis/5.1.1": {Name: "5.1.1", Taxa: []Taxon{
			{Taxonomy: "CIS-Kubernetes", ID: "5.1.1", Name: "Minimize wildcard use", Version: "cis-1.12"}}},
	}, Results: []Result{
		{Tool: "draugr-draugr-k8s-policies", RuleID: "draugr/cis/5.1.1", Level: LevelWarning, Message: "a"},
		{Tool: "kube-bench", RuleID: "kube-bench/cis/5.1.1", Level: LevelWarning, Message: "b"},
	}}
	data, err := rep.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	var log map[string]any
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatal(err)
	}
	run := log["runs"].([]any)[0].(map[string]any)
	tx := run["taxonomies"].([]any)
	if len(tx) != 1 {
		t.Fatalf("want one taxonomy, got %d", len(tx))
	}
	first := tx[0].(map[string]any)
	if first["name"] != "CIS-Kubernetes" || len(first["taxa"].([]any)) != 1 {
		t.Errorf("both rules should reference one shared taxon: %+v", first)
	}
	rules := run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)
	for _, r := range rules {
		rel := r.(map[string]any)["relationships"]
		if rel == nil {
			t.Errorf("rule %v has no relationship to the taxon", r.(map[string]any)["id"])
		}
	}
}

func TestNoTaxonomiesWhenNothingReferencesOne(t *testing.T) {
	// A run that classifies nothing should not carry an empty array claiming it tried.
	rep := Report{Tool: "gitleaks", Rules: map[string]Rule{"aws-key": {Name: "aws-key"}},
		Results: []Result{{Tool: "gitleaks", RuleID: "aws-key", Level: LevelError, Message: "x"}}}
	data, err := rep.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("taxonomies")) {
		t.Errorf("nothing declared a taxon:\n%s", data)
	}
}

func TestAHalfDeclaredTaxonIsIgnored(t *testing.T) {
	// A taxonomy with no id, or an id with no taxonomy, would emit a relationship pointing at
	// nothing — a dangling reference is worse than an absent one.
	rep := Report{Tool: "x", Rules: map[string]Rule{
		"r": {Name: "r", Taxa: []Taxon{{Taxonomy: "CWE"}, {ID: "79"}}},
	}, Results: []Result{{Tool: "x", RuleID: "r", Level: LevelError, Message: "m"}}}
	data, err := rep.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("relationships")) {
		t.Errorf("neither taxon was complete:\n%s", data)
	}
}

func TestTaxonKeyDistinguishesBenchmarkRevisions(t *testing.T) {
	// A check number means a different thing between revisions, so a key without one would
	// correlate findings about two different controls.
	a := Taxon{Taxonomy: "CIS-Kubernetes", ID: "5.1.1", Version: "cis-1.12"}
	b := Taxon{Taxonomy: "CIS-Kubernetes", ID: "5.1.1", Version: "cis-1.9"}
	if a.Key() == b.Key() {
		t.Errorf("revisions must not collide: %q", a.Key())
	}
	if got := (Taxon{Taxonomy: "CWE", ID: "79"}).Key(); got != "CWE/79" {
		t.Errorf("an unversioned taxonomy should key plainly, got %q", got)
	}
}

func TestMergeUnionsWhatEachScannerSettled(t *testing.T) {
	// The point of recording it: after merging, a consumer can ask which controls anybody reached
	// a verdict on — and by elimination, which nobody examined.
	cis := func(id string) Taxon {
		return Taxon{Taxonomy: "CIS-Kubernetes", ID: id, Version: "cis-1.12"}
	}
	ours := Report{Tool: "draugr-draugr-k8s-policies", Decided: []Taxon{cis("5.1.1"), cis("5.1.5")}}
	theirs := Report{Tool: "kube-bench", Decided: []Taxon{cis("5.1.1"), cis("5.2.4")}}

	merged := Merge(ours, theirs)
	var ids []string
	for _, t := range merged.Decided {
		ids = append(ids, t.ID)
	}
	slices.Sort(ids)
	if !slices.Equal(ids, []string{"5.1.1", "5.1.5", "5.2.4"}) {
		t.Errorf("got %v, want the union with 5.1.1 counted once", ids)
	}
}

func TestDecidedDedupesOnTheKeyNotTheLabel(t *testing.T) {
	// Two scanners naming one control will label it differently, and the label is not what makes
	// it the same control.
	a := Report{Decided: []Taxon{{Taxonomy: "CIS-Kubernetes", ID: "5.1.1", Name: "Minimize wildcard use"}}}
	b := Report{Decided: []Taxon{{Taxonomy: "CIS-Kubernetes", ID: "5.1.1", Name: "5.1.1 Minimize wildcard use of roles"}}}
	if got := len(Merge(a, b).Decided); got != 1 {
		t.Errorf("got %d, want one control", got)
	}
}

func TestDecidedKeepsRevisionsApart(t *testing.T) {
	// A check number means a different thing between benchmark revisions.
	a := Report{Decided: []Taxon{{Taxonomy: "CIS-Kubernetes", ID: "5.1.1", Version: "cis-1.12"}}}
	b := Report{Decided: []Taxon{{Taxonomy: "CIS-Kubernetes", ID: "5.1.1", Version: "cis-1.9"}}}
	if got := len(Merge(a, b).Decided); got != 2 {
		t.Errorf("got %d, want both revisions", got)
	}
}

func TestDecidedReachesSARIF(t *testing.T) {
	// It has to leave the process, or only Draugr's own reporters can use it — and the consumer
	// this matters most to is the one aggregating across runs.
	rep := Report{Tool: "draugr-draugr-k8s-policies",
		Decided: []Taxon{{Taxonomy: "CIS-Kubernetes", ID: "5.1.1", Version: "cis-1.12"}}}
	data, err := rep.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"decided"`, `"CIS-Kubernetes"`, `"5.1.1"`, `"cis-1.12"`} {
		if !bytes.Contains(data, []byte(want)) {
			t.Errorf("missing %s in:\n%s", want, data)
		}
	}
}
