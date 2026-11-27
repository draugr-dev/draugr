package skald

import (
	"reflect"
	"testing"

	"github.com/draugr-dev/draugr/internal/fieldprobe"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// unsetOnAFullFinding are the fields of a report.json finding that stay empty on a finding with every
// field set, each with the reason. Any other field toFinding leaves empty fails
// TestEveryFindingFieldIsCarried.
var unsetOnAFullFinding = map[string]string{
	"NoLocation": "true only on a finding with no location, and a full finding has one",
}

// report.json's findings are a summary written field by field from a result, so a field the summary
// declares and toFinding never sets is absent from every report with no test failing. Each declared
// field is set from a result with every field set, and each one named like a field of the result
// holds that field's value.
func TestEveryFindingFieldIsCarried(t *testing.T) {
	var res sarif.Result
	fieldprobe.Fill(&res, map[string]any{"Level": sarif.LevelError})
	got := toFinding(res.Control, res)

	for _, field := range fieldprobe.Unset(got) {
		if _, listed := unsetOnAFullFinding[field]; !listed {
			t.Errorf("report.json's %s is never set from the result: set it in toFinding, or list it in unsetOnAFullFinding with the reason", field)
		}
	}

	sameNamed(t, reflect.ValueOf(res), reflect.ValueOf(got), "")
	sameNamed(t, reflect.ValueOf(*res.Suppression), reflect.ValueOf(*got.Suppressed), "Suppressed.")
}

// sameNamed fails for each field of to that from has under the same name and type and that holds a
// different value.
func sameNamed(t *testing.T, from, to reflect.Value, prefix string) {
	t.Helper()
	for i := range to.NumField() {
		name := to.Type().Field(i).Name
		src := from.FieldByName(name)
		if !src.IsValid() || src.Type() != to.Field(i).Type() {
			continue
		}
		if !reflect.DeepEqual(src.Interface(), to.Field(i).Interface()) {
			t.Errorf("report.json's %s%s = %v, want the result's %v", prefix, name, to.Field(i).Interface(), src.Interface())
		}
	}
}
