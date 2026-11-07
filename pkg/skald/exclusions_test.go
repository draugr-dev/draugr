package skald

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// Each exclusion reaches report.json with the file and line it is written at and git's record of
// that line, reliable or not, in the order the merged descriptor lists them.
func TestDescriptorCarriesEachExclusionsFileLineAndHistory(t *testing.T) {
	reliable := &saga.LineHistory{
		Path: "draugr.saga.yaml", Commit: "4f2a9c1e0b3d5f7a9c1e0b3d5f7a9c1e0b3d5f7a",
		Author: "Ada Lovelace", Date: "2026-09-14T10:00:00+02:00",
	}
	shallow := &saga.LineHistory{Path: "draugr.saga.yaml", Unavailable: "the line is older than the shallow clone's history; fetch full history"}
	model := &saga.Model{Project: "p", Config: saga.Config{Exclude: []saga.ExcludeRule{
		{Rules: []string{"a"}, Reason: "first", Source: "draugr.saga.yaml", Line: 12, History: reliable},
		{Rules: []string{"b"}, Reason: "second", Source: "draugr.saga.yaml", Line: 18, History: shallow},
		{Rules: []string{"c"}, Reason: "third", Source: "https://example.com/platform.git@v1 policy.saga-fragment.yaml", Line: 3},
	}}}
	desc := DescriptorFrom(&saga.Resolved{Model: model, Sources: []saga.Source{{Path: "draugr.saga.yaml", Root: true}}})

	doc := renderWith(t, Provenance{Descriptor: desc})
	raw, err := json.Marshal(doc["descriptor"].(map[string]any)["exclusions"])
	if err != nil {
		t.Fatal(err)
	}
	want := `[{"gitHistory":{"author":"Ada Lovelace","commit":"4f2a9c1e0b3d5f7a9c1e0b3d5f7a9c1e0b3d5f7a",` +
		`"date":"2026-09-14T10:00:00+02:00","path":"draugr.saga.yaml"},"line":12,"reason":"first","rules":["a"],"source":"draugr.saga.yaml"},` +
		`{"gitHistory":{"path":"draugr.saga.yaml","unavailable":"the line is older than the shallow clone's history; fetch full history"},` +
		`"line":18,"reason":"second","rules":["b"],"source":"draugr.saga.yaml"},` +
		`{"line":3,"reason":"third","rules":["c"],"source":"https://example.com/platform.git@v1 policy.saga-fragment.yaml"}]`
	if string(raw) != want {
		t.Errorf("descriptor.exclusions\n got %s\nwant %s", raw, want)
	}

	// A copy, so a later change to the rule cannot rewrite what the report already says.
	reliable.Author = "changed"
	if desc.Exclusions[0].GitHistory.Author != "Ada Lovelace" {
		t.Error("the report shares the rule's history rather than holding its own")
	}
}

// Every field an entry sets reaches report.json, so a reader holding the report and not the
// descriptor can check a reason against what it matches.
func TestEachExclusionCarriesEveryFieldItSets(t *testing.T) {
	rule := saga.ExcludeRule{
		Rules: []string{"gitleaks.generic-api-key"}, Paths: []string{"testdata/", "*.md"},
		Reason: "fixtures", Expires: "2026-12-31",
		VEX:    &saga.VEXDecision{Status: "not_affected", Justification: "vulnerable_code_not_present"},
		Source: "draugr.saga.yaml", Line: 9,
	}
	got := ExclusionsFrom([]saga.ExcludeRule{rule})
	want := `[{"source":"draugr.saga.yaml","line":9,"rules":["gitleaks.generic-api-key"],"paths":["testdata/","*.md"],` +
		`"reason":"fixtures","expires":"2026-12-31","vex":{"status":"not_affected","justification":"vulnerable_code_not_present"}}]`
	if raw := mustJSON(t, got); raw != want {
		t.Errorf("exclusions\n got %s\nwant %s", raw, want)
	}
	// A copy, as the history is, so a later change to the rule cannot rewrite the report.
	rule.Rules[0], rule.Paths[0], rule.VEX.Status = "changed", "changed", "changed"
	if got[0].Rules[0] != "gitleaks.generic-api-key" || got[0].Paths[0] != "testdata/" || got[0].VEX.Status != "not_affected" {
		t.Errorf("the report shares the rule's fields rather than holding its own: %+v", got[0])
	}
	// What an entry leaves out stays out of the document.
	if raw := mustJSON(t, ExclusionsFrom([]saga.ExcludeRule{{Rules: []string{"R"}, Reason: "r"}})); strings.Contains(raw, "paths") ||
		strings.Contains(raw, "expires") || strings.Contains(raw, "vex") {
		t.Errorf("an unset field was written: %s", raw)
	}
}

// A finding an exclusion set aside names the exclusion's file and line, the same pair its
// descriptor.exclusions entry carries, so the two join inside report.json.
func TestASuppressedFindingNamesItsExclusionsLine(t *testing.T) {
	note := suppressionOf(sarif.Result{RuleID: "R", Level: sarif.LevelError, Suppression: &sarif.Suppression{
		Kind: "external", Justification: "fixture", Origin: sarif.OriginSaga, Source: "draugr.saga.yaml", Line: 12,
	}})
	if note == nil || note.Source != "draugr.saga.yaml" || note.Line != 12 {
		t.Errorf("suppressed = %+v, want draugr.saga.yaml and line 12", note)
	}
}

// A descriptor with no exclusions writes no block, rather than an empty list claiming one was read.
func TestNoExclusionsIsNoBlock(t *testing.T) {
	if got := ExclusionsFrom(nil); got != nil {
		t.Errorf("ExclusionsFrom(nil) = %+v", got)
	}
	desc := DescriptorFrom(&saga.Resolved{Model: &saga.Model{Project: "p"}, Sources: []saga.Source{{Path: "a", Root: true}}})
	doc := renderWith(t, Provenance{Descriptor: desc})
	if strings.Contains(mustJSON(t, doc["descriptor"]), "exclusions") {
		t.Errorf("descriptor = %v, want no exclusions key", doc["descriptor"])
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
