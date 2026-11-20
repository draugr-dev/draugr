package engine

import (
	"maps"
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A converter's labels join the component's, the component's value winning on a shared key, in a
// map of the finding's own; a finding no converter wrote carries the component's labels alone.
func TestAConvertersLabelsJoinTheComponentsOwn(t *testing.T) {
	component := map[string]string{"team": "payments"}
	conv := &sarif.Converter{Name: "acme-deps"}
	got := withLabels(component, map[string]string{"team": "other", "triage": "security"}, conv)
	if !maps.Equal(got, map[string]string{"team": "payments", "triage": "security"}) {
		t.Errorf("labels %v", got)
	}
	got["x"] = "y"
	if _, leaked := component["x"]; leaked {
		t.Error("the merged labels share the component's map")
	}
	if got := withLabels(component, map[string]string{"triage": "security"}, nil); !maps.Equal(got, component) {
		t.Errorf("labels %v on a finding no converter wrote, want the component's alone", got)
	}
}
