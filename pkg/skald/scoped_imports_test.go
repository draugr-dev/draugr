package skald

import (
	"reflect"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// Each file a component's paths and ignore narrowed, or whose repeated findings were folded, is listed
// once, naming every control that read it, with the counts the import scanner recorded. A file with
// nothing left out, another scanner's account and a count that is not a number add nothing.
func TestScopedImportsAreListedOncePerComponentAndFile(t *testing.T) {
	imported := func(component, file string, detail ...sarif.Field) sarif.Provenance {
		return sarif.Provenance{Tool: sarif.ImportScanner, Detail: detail, Fields: []sarif.Field{
			{Key: "file", Value: file}, {Key: "component", Value: component}}}
	}
	api := imported("api", "reports/all.sarif",
		sarif.Field{Key: sarif.ImportOutsidePaths, Value: "3"}, sarif.Field{Key: sarif.ImportIgnored, Value: "1"})
	run := engine.Result{Controls: map[string]plugin.ControlResult{
		"sast": {Report: sarif.Report{Provenance: []sarif.Provenance{
			api,
			imported("web", "reports/all.sarif", sarif.Field{Key: sarif.ImportNotScoped, Value: "2"}),
			imported("web", "reports/clean.sarif"),
			imported("web", "reports/odd.sarif", sarif.Field{Key: sarif.ImportOutsidePaths, Value: "many"}),
			imported("web", "reports/twice.sarif", sarif.Field{Key: sarif.ImportFolded, Value: "1"}),
			{Tool: "semgrep", Detail: []sarif.Field{{Key: sarif.ImportOutsidePaths, Value: "9"}}},
		}}},
		"sca": {Report: sarif.Report{Provenance: []sarif.Provenance{api}}},
	}}
	want := []ScopedImport{
		{Component: "api", File: "reports/all.sarif", Controls: []string{"sast", "sca"}, OutsidePaths: 3, Ignored: 1},
		{Component: "web", File: "reports/all.sarif", Controls: []string{"sast"}, NotScoped: 2},
		{Component: "web", File: "reports/twice.sarif", Controls: []string{"sast"}, Folded: 1},
	}
	if got := scopedImportsOf(run); !reflect.DeepEqual(got, want) {
		t.Errorf("scopedImportsOf =\n%+v\nwant\n%+v", got, want)
	}
	if got := scopedImportsOf(engine.Result{}); got != nil {
		t.Errorf("a run with no imports lists %+v", got)
	}
}
