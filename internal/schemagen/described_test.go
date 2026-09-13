package schemagen

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

// bareEnumIsFine are the closed vocabularies an editor does not need to explain, each with the
// reason it does not.
//
// A list with a reason each, rather than a count or a silence: "this one explains itself" and
// "nobody got round to it" look identical otherwise, and only the first should survive review.
var bareEnumIsFine = map[string]string{
	"/$defs/gateConfig/properties/failOnPriority":                      "P1 to P4, the product's own ladder, defined wherever a band appears",
	"/$defs/reportConfig/properties/minPriority":                       "the same ladder",
	"/$defs/control_images/properties/trivy/properties/pkgTypes/items": "os and library, which are the words Trivy prints",
	"/$defs/control_sca/properties/trivyFs/properties/pkgTypes/items":  "the same two",
	"/$defs/hostSpec/properties/methods/items":                         "HTTP methods, which the reader typing one already knows",
	"/$defs/reachabilityConfig/properties/analyzers/items":             "a tool name, and the tool's own doc is what explains it",
}

// Every closed vocabulary in the schema explains each of its values, or says why it does not.
//
// The schema is what an editor reads, so a value that completes with no description is a value the
// reader has to go and look up somewhere else, at the moment they are typing it. `exposure`,
// `criticality` and the control names carry a sentence per value for exactly that reason, and the
// generator says so in its own comments. The shape that does it is `anyOf` of `const`; a plain
// `enum` list cannot, whatever description sits on the property above it.
//
// The cost is not even across fields. A wrong `exposure` mis-ranks a finding in a report its author
// reads; a wrong VEX justification is published to somebody who cannot check it.
func TestEveryClosedVocabularyExplainsItsValues(t *testing.T) {
	data, err := os.ReadFile(schemaPath())
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}

	var bare, undescribed []string
	var walk func(node any, path string)
	walk = func(node any, path string) {
		switch n := node.(type) {
		case map[string]any:
			if _, ok := n["enum"].([]any); ok {
				if _, excused := bareEnumIsFine[path]; !excused {
					bare = append(bare, path)
				}
			}
			if variants, ok := n["anyOf"].([]any); ok {
				allConst := len(variants) > 0
				for _, v := range variants {
					m, isMap := v.(map[string]any)
					if !isMap {
						allConst = false
						break
					}
					if _, has := m["const"]; !has {
						allConst = false
						break
					}
				}
				if allConst {
					for _, v := range variants {
						m := v.(map[string]any)
						if d, _ := m["description"].(string); strings.TrimSpace(d) == "" {
							undescribed = append(undescribed,
								fmt.Sprintf("%s → %v", path, m["const"]))
						}
					}
				}
			}
			for k, v := range n {
				walk(v, path+"/"+k)
			}
		case []any:
			for i, v := range n {
				walk(v, fmt.Sprintf("%s[%d]", path, i))
			}
		}
	}
	walk(doc, "")

	sort.Strings(bare)
	for _, p := range bare {
		t.Errorf("%s is a plain enum, so an editor lists its values and explains none", p)
	}
	if len(bare) > 0 {
		t.Log("  Use `anyOf` of `const` with a description on each variant, the shape `exposure`\n" +
			"  and `criticality` use. If the values genuinely explain themselves, add the path to\n" +
			"  bareEnumIsFine with the reason.")
	}
	sort.Strings(undescribed)
	for _, p := range undescribed {
		t.Errorf("%s completes with no description", p)
	}

	// An excuse for a field that no longer exists is an excuse nobody will notice is stale.
	for path := range bareEnumIsFine {
		if !strings.Contains(string(data), lastSegment(path)) {
			t.Errorf("bareEnumIsFine lists %s, which the schema no longer has", path)
		}
	}
}

// lastSegment is the property name a path ends in.
func lastSegment(path string) string {
	parts := strings.Split(strings.TrimSuffix(path, "/items"), "/")
	return parts[len(parts)-1]
}
