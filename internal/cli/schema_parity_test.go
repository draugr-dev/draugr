package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/draugr-dev/draugr/internal/sagatest"
	"github.com/draugr-dev/draugr/pkg/publish"
)

// parityExceptions are the fields where `draugr validate` refuses a value the JSON Schema accepts,
// each for a reason no schema can express.
var parityExceptions = map[string]string{
	`^fragments\.\d+\.path$`: "a file that has to exist, which a schema cannot know",
}

// TestTheEditorAndDraugrAgreeOnEveryField holds the JSON Schema and `draugr validate` to the same
// answer for every field a descriptor can hold.
//
// Every example is changed one field at a time, each string into the wrong case, into a value
// nothing defines and into a number, each mapping given a key nothing defines, each label given a
// number, and both
// readers judge every change. They must agree. The examples between them write every field the
// model has (TestEveryDescriptorFieldAppearsInAnExample), so this covers the schema end to end, and
// a new field, a new vocabulary or a new scanner option that one reader enforces and the other does
// not fails here rather than in an editor months later.
func TestTheEditorAndDraugrAgreeOnEveryField(t *testing.T) {
	if testing.Short() {
		t.Skip("validates every example once per field")
	}
	files, err := filepath.Glob("../../examples/*.saga.yaml")
	if err != nil || len(files) < 5 {
		t.Fatalf("found %d examples: %v", len(files), err)
	}
	dir := t.TempDir()
	sagatest.CopyDir(t, "../../examples", dir)

	for _, f := range files {
		raw, err := os.ReadFile(f) // #nosec G304 -- an example in this repository
		if err != nil {
			t.Fatal(err)
		}
		var base any
		if err := yaml.Unmarshal(raw, &base); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(dir, filepath.Base(f))
		draugrAccepts := func(doc any) bool {
			b, err := yaml.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, b, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err = loadAndWarn(target)
			return err == nil
		}
		editorAccepts := func(doc any) bool { return sagatest.SchemaError(t, doc, false) == nil }

		if !draugrAccepts(base) || !editorAccepts(base) {
			t.Errorf("%s: the example itself is refused (draugr %v, editor %v)", f, draugrAccepts(base), editorAccepts(base))
			continue
		}
		for _, m := range sagatest.Mutations(base) {
			d, e := draugrAccepts(m.Doc), editorAccepts(m.Doc)
			if d == e || excepted(m.Path) {
				continue
			}
			t.Errorf("%s: %s %s: draugr validate accepts=%v, the schema accepts=%v; make them agree",
				filepath.Base(f), m.Kind, m.Path, d, e)
		}
	}
}

func excepted(path string) bool {
	for p := range parityExceptions {
		if regexp.MustCompile(p).MatchString(path) {
			return true
		}
	}
	return false
}

// TestTheEditorHoldsItemFieldsToTheKind holds the schema to itemReaders: every item key is
// accepted on the kinds that read it and refused on the others, which a one-field mutation of an
// example never tests, since it never moves a key onto another kind.
func TestTheEditorHoldsItemFieldsToTheKind(t *testing.T) {
	doc := func(kind string, item map[string]any) any {
		return map[string]any{
			"project":    "shop",
			"config":     map[string]any{"publishers": []any{map[string]any{"kind": kind, "item": item}}},
			"components": []any{map[string]any{"name": "web", "images": []any{map[string]any{"image": "alpine:3.19"}}}},
		}
	}
	values := map[string]any{
		"labels":        []any{"security"},
		"assignees":     []any{"octocat"},
		"milestone":     "Q3",
		"type":          "task",
		"confidential":  false,
		"tags":          []any{"security"},
		"assignedTo":    "dev@example.com",
		"areaPath":      `Shop\Payments`,
		"iterationPath": `Shop\Sprint 12`,
		"priority":      2,
		"fields":        map[string]any{"Microsoft.VSTS.Common.Severity": "2 - High"},
	}
	for key, readers := range itemReaders {
		value, ok := values[key]
		if !ok {
			t.Errorf("item.%s has no sample value here, so nothing holds the schema to its readers", key)
			continue
		}
		for _, kind := range publish.Kinds() {
			if !publish.IssueKind(kind) {
				continue
			}
			want := slices.Contains(readers, kind)
			if err := sagatest.SchemaError(t, doc(kind, map[string]any{key: value}), false); (err == nil) != want {
				t.Errorf("item.%s on %s: the schema accepts=%v, want %v (%v)", key, kind, err == nil, want, err)
			}
		}
	}
	for _, c := range []struct {
		name string
		doc  any
		ok   bool
	}{
		{"a GitHub type on gitlab-issue", doc("gitlab-issue", map[string]any{"type": "Bug"}), false},
		{"any type on github-issue", doc("github-issue", map[string]any{"type": "Bug"}), true},
		{"any type on azure-work-item", doc("azure-work-item", map[string]any{"type": "User Story"}), true},
		{"a field the publisher sets", doc("azure-work-item", map[string]any{"fields": map[string]any{"System.Title": "x"}}), false},
		{"priority 5", doc("azure-work-item", map[string]any{"priority": 5}), false},
	} {
		if err := sagatest.SchemaError(t, c.doc, false); (err == nil) != c.ok {
			t.Errorf("%s: the schema accepts=%v, want %v (%v)", c.name, err == nil, c.ok, err)
		}
	}
}
