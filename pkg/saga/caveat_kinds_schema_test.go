package saga

import (
	"encoding/json"
	"os"
	"slices"
	"testing"
)

// The schema lists the kinds of caveat by hand, each with what it means, so an editor can explain
// them. Every kind Draugr accepts is in that list and nothing else is: a kind missing from it is one
// an editor flags in a descriptor Draugr runs.
func TestTheSchemaListsEveryCaveatKind(t *testing.T) {
	raw, err := os.ReadFile("draugr.saga.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Defs map[string]struct {
			Properties map[string]struct {
				Items struct {
					AnyOf []struct {
						Const       string `json:"const"`
						Description string `json:"description"`
					} `json:"anyOf"`
				} `json:"items"`
			} `json:"properties"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	var listed []CaveatKind
	for _, v := range schema.Defs["gateConfig"].Properties["failOnCaveats"].Items.AnyOf {
		if v.Description == "" {
			t.Errorf("%s has no description", v.Const)
		}
		listed = append(listed, CaveatKind(v.Const))
	}
	if !slices.Equal(listed, CaveatKinds) {
		t.Errorf("the schema lists %v, Draugr accepts %v, in this order", listed, CaveatKinds)
	}
}
