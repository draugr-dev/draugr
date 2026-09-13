package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
)

// The id names the product, and names what the run was narrowed to when it was narrowed.
//
// GitHub splits it on the last "/" into a category and a run id and replaces the last upload under
// that category, so every case here is a case where two analyses of one commit either coexist or
// erase each other.
func TestAutomationID(t *testing.T) {
	for _, tc := range []struct {
		name    string
		project string
		scope   engine.Scope
		want    string
	}{
		{"a whole project", "storefront", engine.Scope{}, "storefront/"},
		{
			"narrowed to a component",
			"storefront", engine.Scope{Components: []string{"web"}},
			"storefront/components:web/",
		},
		{
			"narrowed on both axes",
			"storefront", engine.Scope{Components: []string{"web"}, Controls: []string{"sca"}},
			"storefront/components:web/controls:sca/",
		},
		{
			// Two spellings of one matrix leg are one category, or half its alerts disappear
			// whenever somebody reorders a list in a pipeline file.
			"the order a scope was written in",
			"storefront", engine.Scope{Components: []string{"web", "api"}},
			"storefront/components:api,web/",
		},
		{
			// The split is made on the last "/" in the whole id, so a name carrying one would
			// move the boundary and take part of itself into the run id.
			"a name containing a slash",
			"acme/storefront", engine.Scope{},
			"acme-storefront/",
		},
		{
			// Nothing asked for is nothing to say. An id of "/" would be a category of "",
			// which is what every report used to be filed under.
			"a scan with no descriptor behind it",
			"", engine.Scope{}, "",
		},
		{
			"no project but a narrowing",
			"", engine.Scope{Controls: []string{"secrets"}},
			"controls:secrets/",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := AutomationID(tc.project, tc.scope); got != tc.want {
				t.Errorf("AutomationID(%q, %+v) = %q, want %q", tc.project, tc.scope, got, tc.want)
			}
		})
	}
}

// The scope a caller passed is left as they passed it. Sorting in place would reorder the list the
// console prints and the JSON report carries.
func TestAutomationIDDoesNotReorderTheCallersScope(t *testing.T) {
	scope := engine.Scope{Components: []string{"web", "api"}}
	AutomationID("storefront", scope)
	if scope.Components[0] != "web" {
		t.Errorf("scope was sorted in place: %v", scope.Components)
	}
}

// The rendered report carries it, which is the half that reaches GitHub: a publisher renders
// through this reporter, and so does `--format sarif`.
func TestSARIFCarriesTheAutomationID(t *testing.T) {
	d := sampleData()
	d.Run.Scope = engine.Scope{Controls: []string{"secrets"}}

	var b bytes.Buffer
	if err := (sarifReporter{}).Render(&b, d); err != nil {
		t.Fatalf("render: %v", err)
	}
	var doc struct {
		Runs []struct {
			AutomationDetails *struct {
				ID string `json:"id"`
			} `json:"automationDetails"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc.Runs[0].AutomationDetails == nil {
		t.Fatal("no automationDetails, so code scanning files this under the empty category")
	}
	if got, want := doc.Runs[0].AutomationDetails.ID, "app/controls:secrets/"; got != want {
		t.Errorf("automationDetails.id = %q, want %q", got, want)
	}
}

// Two products assembled from one repository are two categories, which is the whole point: with
// one, the second upload over a commit removes the first product's alerts.
func TestTwoProjectsOverOneCommitGetTwoIDs(t *testing.T) {
	azure, gcp := AutomationID("acme-azure", engine.Scope{}), AutomationID("acme-gcp", engine.Scope{})
	if azure == gcp {
		t.Fatalf("both products publish under %q, so one erases the other", azure)
	}
}

// The id comes from what was asked for, not from what was found, so the same product publishes
// under the same category on every push and an alert fixed in one run resolves in the next.
func TestAutomationIDIsStableAcrossRuns(t *testing.T) {
	scope := engine.Scope{Components: []string{"web"}}
	first := AutomationID("storefront", scope)
	// A later run of the same pipeline over a tree that has changed: different findings, and
	// Resolve has since filled in components this one leaves out.
	scope.SkippedComponents = []string{"api", "platform"}
	if second := AutomationID("storefront", scope); second != first {
		t.Errorf("id moved between runs: %q then %q", first, second)
	}
}
