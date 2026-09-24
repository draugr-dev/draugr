package saga

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
	"gopkg.in/yaml.v3"
)

// resolvedSchema reads a checked-in schema and prepares it for validation.
func resolvedSchema(t *testing.T, file string) *jsonschema.Resolved {
	t.Helper()
	raw, err := os.ReadFile(file) // #nosec G304 -- a file in this package
	if err != nil {
		t.Fatal(err)
	}
	var s jsonschema.Schema
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	rs, err := s.Resolve(nil)
	if err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	return rs
}

// asJSON turns a YAML document into the JSON value a schema validates, the way an editor reads it.
func asJSON(t *testing.T, path string) any {
	t.Helper()
	raw, err := os.ReadFile(path) // #nosec G304 -- a file this test found in the repository
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestEveryExampleIsValidToAnEditor holds every descriptor and fragment in the repository to the
// JSON Schema an editor checks them against, beside `draugr validate`, which the examples test
// already runs.
//
// The two can disagree in either direction, and both are failures somebody meets: an editor
// underlining a descriptor Draugr runs teaches people to ignore the editor, and one accepting a
// descriptor Draugr refuses moves the error from the keyboard to the pipeline. Checking the files
// people copy against both is what keeps them agreeing.
func TestEveryExampleIsValidToAnEditor(t *testing.T) {
	saga := resolvedSchema(t, "draugr.saga.schema.json")
	fragment := resolvedSchema(t, "draugr.saga-fragment.schema.json")

	var files []string
	for _, pattern := range []string{"../../examples/*.saga.yaml", "../../examples/*/*.yaml", "../../.draugr/*.saga.yaml"} {
		found, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, found...)
	}
	if len(files) < 5 {
		t.Fatalf("found %d descriptors; the globs have stopped matching the examples", len(files))
	}
	for _, f := range files {
		schema := saga
		if strings.Contains(f, "fragment") && !strings.HasSuffix(f, "fragments.saga.yaml") {
			schema = fragment
		}
		if err := schema.Validate(asJSON(t, f)); err != nil {
			t.Errorf("%s: an editor rejects this file: %v", f, err)
		}
	}
}

// TestEveryPatternLeavesSubstitutionToTheLoader requires every pattern in both schemas to accept a
// value holding a ${{ VAR }} reference. An editor reads the file before substitution, so a pattern
// refusing the placeholder underlines a valid descriptor; the loader checks the substituted value.
func TestEveryPatternLeavesSubstitutionToTheLoader(t *testing.T) {
	for _, file := range []string{"draugr.saga.schema.json", "draugr.saga-fragment.schema.json"} {
		raw, err := os.ReadFile(file) // #nosec G304 -- a file in this package
		if err != nil {
			t.Fatal(err)
		}
		var doc any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		found := 0
		var walk func(n any)
		walk = func(n any) {
			switch x := n.(type) {
			case map[string]any:
				if p, ok := x["pattern"].(string); ok {
					found++
					re := regexp.MustCompile(p)
					for _, v := range []string{"${{ VALUE }}", "prefix-${{VALUE}}"} {
						if !re.MatchString(v) {
							t.Errorf("%s: pattern %s refuses %q", file, p, v)
						}
					}
					if re.MatchString("zz not a value") {
						t.Errorf("%s: pattern %s accepts anything", file, p)
					}
				}
				for _, v := range x {
					walk(v)
				}
			case []any:
				for _, v := range x {
					walk(v)
				}
			}
		}
		walk(doc)
		if found < 5 {
			t.Errorf("%s: found %d patterns; the walk has stopped seeing them", file, found)
		}
	}
}
