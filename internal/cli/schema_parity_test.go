package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/draugr-dev/draugr/internal/sagatest"
	"github.com/draugr-dev/draugr/pkg/publish"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// parityExceptions are the fields where `draugr validate` refuses a value the JSON Schema accepts,
// each for a reason no schema can express.
var parityExceptions = map[string]string{
	`^fragments\.\d+\.path$`:                             "a file that has to exist, which a schema cannot know",
	`^components\.\d+\.kubernetes\.\d+\.cluster$`:        "a name the same descriptor declares under clusters:, which a schema cannot cross-reference",
	`^components\.\d+\.cloud\.\d+\.account$`:             "a name the same descriptor declares under accounts:, which a schema cannot cross-reference",
	`^components\.\d+\.images\.\d+\.signedBy$`:           "a signer the same descriptor declares under controls.provenance.signers, which a schema cannot cross-reference",
	`^config\.publishers\.\d+\.select\.components\.\d+$`: "a component the same descriptor declares, which a schema cannot cross-reference",
}

// referencedNames are the names testdata/parity/fields.saga.yaml declares and then refers to, so
// changing one breaks the reference rather than the field. The examples write the same fields
// without a reference to them, which is where their parity is held.
var referencedNames = map[string]string{
	"components.0.name":                         "named by select.components",
	"config.controls.provenance.signers.0.name": "named by an image's signedBy",
}

// parityDoc is one document the parity test changes: the file it edits, the file draugr loads to
// read it, and whether the fragment schema is the one it answers to. A fragment is loaded through
// the descriptor that collects it, which is the only way draugr reads one.
type parityDoc struct {
	name, edit, load string
	fragment         bool
}

// parityRoots are the directories whose documents the parity test changes: the examples, and
// testdata/parity, which writes the fields no example writes as a live key.
var parityRoots = []string{"../../examples", "testdata/parity"}

// parityCorpus copies each root into dir and lists its documents there: every descriptor at the
// top of the root, and every fragment under fragments/, loaded through fragments.saga.yaml.
func parityCorpus(t *testing.T, dir string) []parityDoc {
	t.Helper()
	var docs []parityDoc
	for i, root := range parityRoots {
		into := filepath.Join(dir, strconv.Itoa(i))
		sagatest.CopyDir(t, root, into)
		sagas, err := filepath.Glob(filepath.Join(root, "*.saga.yaml"))
		if err != nil || len(sagas) == 0 {
			t.Fatalf("%s holds no descriptors: %v", root, err)
		}
		for _, f := range sagas {
			rel, _ := filepath.Rel(root, f)
			docs = append(docs, parityDoc{filepath.Join(root, rel), filepath.Join(into, rel), filepath.Join(into, rel), false})
		}
		var frags []string
		_ = filepath.WalkDir(filepath.Join(root, "fragments"), func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() && strings.HasSuffix(p, ".saga-fragment.yaml") {
				frags = append(frags, p)
			}
			return nil
		})
		for _, f := range frags {
			rel, _ := filepath.Rel(root, f)
			docs = append(docs, parityDoc{filepath.Join(root, rel), filepath.Join(into, rel), filepath.Join(into, "fragments.saga.yaml"), true})
		}
	}
	return docs
}

// TestTheEditorAndDraugrAgreeOnEveryField holds the JSON Schema and `draugr validate` to the same
// answer for every field a descriptor can hold.
//
// Every document in the corpus is changed one field at a time, each string into the wrong case,
// into a value nothing defines and into a number, each mapping given a key nothing defines, each
// label given a number, and both readers judge every change. They must agree. Between them the
// documents write every field the model has as a live key (TestEveryFieldIsHeldToBothReaders), so
// this covers the schema end to end, and a new field, a new vocabulary or a new scanner option that
// one reader enforces and the other does not fails here rather than in an editor months later.
func TestTheEditorAndDraugrAgreeOnEveryField(t *testing.T) {
	if testing.Short() {
		t.Skip("validates every example once per field")
	}
	docs := parityCorpus(t, t.TempDir())
	if len(docs) < 5 {
		t.Fatalf("found %d documents", len(docs))
	}
	for _, doc := range docs {
		raw, err := os.ReadFile(doc.edit) // #nosec G304 -- a copy of a file in this repository
		if err != nil {
			t.Fatal(err)
		}
		var base any
		if err := yaml.Unmarshal(raw, &base); err != nil {
			t.Fatal(err)
		}
		draugrAccepts := func(d any) bool {
			b, err := yaml.Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(doc.edit, b, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err = loadAndWarn(doc.load)
			return err == nil
		}
		editorAccepts := func(d any) bool { return sagatest.SchemaError(t, d, doc.fragment) == nil }

		if !draugrAccepts(base) || !editorAccepts(base) {
			t.Errorf("%s: the document itself is refused (draugr %v, editor %v)", doc.name, draugrAccepts(base), editorAccepts(base))
			continue
		}
		for _, m := range sagatest.Mutations(base) {
			d, e := draugrAccepts(m.Doc), editorAccepts(m.Doc)
			if d == e || excepted(m.Path) {
				continue
			}
			if _, ok := referencedNames[m.Path]; ok && doc.name == "testdata/parity/fields.saga.yaml" {
				continue
			}
			t.Errorf("%s: %s %s: draugr validate accepts=%v, the schema accepts=%v; make them agree",
				doc.name, m.Kind, m.Path, d, e)
		}
		// Put the document back, so a fragment changed last does not break the next descriptor
		// that collects it.
		if err := os.WriteFile(doc.edit, raw, 0o600); err != nil { // #nosec G703 -- a copy in this test's temp dir
			t.Fatal(err)
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

// TestTheEditorAndDraugrHoldEveryPublisherFieldToItsKind sets every publisher field on every kind,
// one at a time, and requires the JSON Schema and `draugr validate` to accept it exactly where
// pkg/publish says the kind reads it. A one-field mutation of an example never moves a field onto
// another kind, so this is the half of the parity the examples cannot reach.
func TestTheEditorAndDraugrHoldEveryPublisherFieldToItsKind(t *testing.T) {
	if testing.Short() {
		t.Skip("validates one descriptor per kind and field")
	}
	samples := map[string]map[string]any{
		"dir":         {"dir": "out"},
		"repo":        {"repo": "acme/web"},
		"commit":      {"commit": "abc123"},
		"ref":         {"ref": "refs/heads/main"},
		"tokenEnv":    {"tokenEnv": "CI_TOKEN"},
		"pr":          {"pr": 3},
		"marker":      {"marker": "<!-- draugr -->"},
		"org":         {"org": "https://dev.azure.com/acme/"},
		"project":     {"project": "shop"},
		"url":         {"url": "https://plane.example"},
		"label":       {"label": "draugr"},
		"branches":    {"branches": []any{"main"}},
		"select":      {"select": map[string]any{"components": []any{"web"}}},
		"split":       {"split": "control"},
		"minPriority": {"minPriority": "P2"},
		"children":    {"children": "actions"},
		"maxChildren": {"children": "actions", "maxChildren": 5},
		"labelBy":     {"labelBy": []any{"priority"}},
		"item":        {"item": map[string]any{"type": "task"}},
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "draugr.saga.yaml")
	keys := saga.PublisherConfig{}.Keys()
	for _, kind := range publish.Kinds() {
		reads := publish.Reads(kind)
		formats, deliversOnly := publish.Accepts(kind)
		report := "sarif"
		if deliversOnly && len(formats) > 0 {
			report = formats[0]
		}
		for _, key := range keys {
			if key == "kind" {
				continue
			}
			entry := map[string]any{"kind": kind}
			if kind == "file" {
				entry["dir"], entry["reports"] = "out", []any{map[string]any{"format": "sarif"}}
			}
			if key == "reports" {
				entry["reports"] = []any{map[string]any{"format": report}}
			} else {
				sample, ok := samples[key]
				if !ok {
					t.Fatalf("publisher field %s has no sample value here, so nothing holds it to its kinds", key)
				}
				for k, v := range sample {
					entry[k] = v
				}
			}
			doc := map[string]any{
				"project":    "shop",
				"config":     map[string]any{"publishers": []any{entry}},
				"components": []any{map[string]any{"name": "web", "images": []any{map[string]any{"image": "alpine:3.19"}}}},
			}
			b, err := yaml.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, b, 0o600); err != nil {
				t.Fatal(err)
			}
			_, loadErr := loadAndWarn(path)
			schemaErr := sagatest.SchemaError(t, doc, false)
			want := slices.Contains(reads, key)
			if (loadErr == nil) != want || (schemaErr == nil) != want {
				t.Errorf("%s on %s: draugr validate accepts=%v, the schema accepts=%v, the kind reads it=%v\n  validate: %v\n  schema: %v",
					key, kind, loadErr == nil, schemaErr == nil, want, loadErr, schemaErr)
			}
		}
	}
}

// unreachedFields are the descriptor fields no document in the parity corpus may write live, each
// with why. Keyed by struct and yaml key, as TestEveryFieldIsHeldToBothReaders reports them.
var unreachedFields = map[string]string{
	"saga.FragmentRef.url":      "a remote fragment is fetched when the descriptor loads, which a test cannot do offline",
	"saga.FragmentRef.revision": "only a remote fragment takes a revision, and a remote fragment is fetched when the descriptor loads",
}

// TestEveryFieldIsHeldToBothReaders requires every field of the descriptor model to be written as
// a live key somewhere in the parity corpus, so TestTheEditorAndDraugrAgreeOnEveryField changes it.
//
// Counted by struct and key rather than by key name. A key name is shared across structs (repo,
// url, project, label, tokenEnv), so a name written in one place said nothing about the same name
// elsewhere, and a field nobody writes is a field whose schema nobody compares with the loader. A
// commented-out key in an example shows a reader the field and is changed by nothing.
func TestEveryFieldIsHeldToBothReaders(t *testing.T) {
	all := map[string]bool{}
	var fields func(reflect.Type)
	seenType := map[reflect.Type]bool{}
	fields = func(tp reflect.Type) {
		for tp.Kind() == reflect.Pointer || tp.Kind() == reflect.Slice || tp.Kind() == reflect.Map {
			tp = tp.Elem()
		}
		if tp.Kind() != reflect.Struct || seenType[tp] {
			return
		}
		seenType[tp] = true
		for i := range tp.NumField() {
			key, _, _ := strings.Cut(tp.Field(i).Tag.Get("yaml"), ",")
			if key == "" || key == "-" {
				continue
			}
			if !deprecatedKeys[key] {
				all[tp.String()+"."+key] = true
			}
			fields(tp.Field(i).Type)
		}
	}
	fields(reflect.TypeOf(saga.Model{}))
	fields(reflect.TypeOf(saga.Fragment{}))

	written := map[string]bool{}
	var walk func(any, reflect.Type)
	walk = func(v any, tp reflect.Type) {
		for tp.Kind() == reflect.Pointer {
			tp = tp.Elem()
		}
		switch tp.Kind() {
		case reflect.Struct:
			m, ok := v.(map[string]any)
			if !ok {
				return
			}
			for i := range tp.NumField() {
				key, _, _ := strings.Cut(tp.Field(i).Tag.Get("yaml"), ",")
				if val, ok := m[key]; ok && key != "" && key != "-" {
					written[tp.String()+"."+key] = true
					walk(val, tp.Field(i).Type)
				}
			}
		case reflect.Slice:
			if list, ok := v.([]any); ok {
				for _, e := range list {
					walk(e, tp.Elem())
				}
			}
		case reflect.Map:
			if m, ok := v.(map[string]any); ok {
				for _, e := range m {
					walk(e, tp.Elem())
				}
			}
		}
	}
	for _, doc := range parityCorpus(t, t.TempDir()) {
		raw, err := os.ReadFile(doc.edit) // #nosec G304 -- a copy of a file in this repository
		if err != nil {
			t.Fatal(err)
		}
		var v any
		if err := yaml.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		if doc.fragment {
			walk(v, reflect.TypeOf(saga.Fragment{}))
		} else {
			walk(v, reflect.TypeOf(saga.Model{}))
		}
	}

	var missing []string
	for f := range all {
		if _, excused := unreachedFields[f]; !written[f] && !excused {
			missing = append(missing, f)
		}
	}
	for f := range unreachedFields {
		if written[f] || !all[f] {
			t.Errorf("unreachedFields excuses %s, which is written or no longer exists; remove it", f)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("no document the parity test changes writes these fields as a live key: %s\n"+
			"Write each in testdata/parity/fields.saga.yaml (or a fragment beside it), so the schema "+
			"and draugr validate are compared on it.", strings.Join(missing, ", "))
	}
}
