package report

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/saga"
)

func renderedJSON(t *testing.T, d Data) map[string]any {
	t.Helper()
	a, err := Build(saga.ReportConfig{Format: "json"}, d)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(a.Bytes, &doc); err != nil {
		t.Fatalf("unreadable report: %v", err)
	}
	return doc
}

// Two components, one labeled and one not, on a run narrowed to the labeled one. Every declared
// component is listed whatever the scope, because a consumer grouping stored runs by team reads
// the labels of a component that did not run as well as one that did, and `scope` already says
// which ran. The values are the organization's vocabulary, so they arrive exactly as written.
func TestReportJSONListsEveryDeclaredComponentsLabels(t *testing.T) {
	d := sampleData()
	d.Run.Scope = engine.Scope{Components: []string{"storefront"}}
	d.Labels = map[string]map[string]string{
		"storefront": {"team": "web", "Data-Class": "PII"},
		"worker":     nil,
	}
	doc := renderedJSON(t, d)

	got, ok := doc["componentLabels"].(map[string]any)
	if !ok {
		t.Fatalf("componentLabels = %#v, want an object", doc["componentLabels"])
	}
	want := map[string]any{
		"storefront": map[string]any{"team": "web", "Data-Class": "PII"},
		"worker":     map[string]any{},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("componentLabels\n got %#v\nwant %#v", got, want)
	}

	scope, _ := doc["scope"].(map[string]any)
	if comps, _ := scope["components"].([]any); len(comps) != 1 || comps[0] != "storefront" {
		t.Errorf("scope = %#v, want the run narrowed to storefront", doc["scope"])
	}
}

// A document written by a caller that knew no components has no key, rather than an empty object
// that would claim the descriptor declared none.
func TestReportJSONOmitsComponentLabelsItWasNotGiven(t *testing.T) {
	if _, ok := renderedJSON(t, sampleData())["componentLabels"]; ok {
		t.Error("componentLabels is present on a run given no labels")
	}
}
