package saga

import (
	"encoding/json"
	"os"
	"path/filepath"
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
