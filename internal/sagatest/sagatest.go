// Package sagatest holds a descriptor to both of the readers that judge it: the JSON Schema an
// editor validates against, and the loader `draugr validate` runs.
//
// Anything that writes a descriptor for somebody, a surveyor, `draugr init`, a merge, is checked
// here in its tests. The two readers disagreeing in either direction is a failure somebody meets:
// an editor underlining a file Draugr runs teaches people to ignore the editor, and one accepting
// a file Draugr refuses moves the error from the keyboard to the pipeline.
package sagatest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
	"gopkg.in/yaml.v3"

	"github.com/draugr-dev/draugr/pkg/saga"
)

var (
	once             sync.Once
	sagaSchema, frag *jsonschema.Resolved
	errSaga, errFrag error
)

func resolve(raw []byte) (*jsonschema.Resolved, error) {
	var s jsonschema.Schema
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	return s.Resolve(nil)
}

func schemas(t testing.TB) (*jsonschema.Resolved, *jsonschema.Resolved) {
	t.Helper()
	once.Do(func() {
		sagaSchema, errSaga = resolve(saga.SchemaJSON)
		frag, errFrag = resolve(saga.FragmentSchemaJSON)
	})
	if errSaga != nil || errFrag != nil {
		t.Fatalf("the embedded schemas do not resolve: %v %v", errSaga, errFrag)
	}
	return sagaSchema, frag
}

// EditorAccepts fails the test when the JSON Schema rejects data, a descriptor or, with fragment,
// a fragment, read the way an editor reads YAML.
func EditorAccepts(t testing.TB, data []byte, fragment bool) {
	t.Helper()
	full, fr := schemas(t)
	var doc any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("not YAML: %v\n%s", err, data)
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("not representable as JSON: %v", err)
	}
	var value any
	if err := json.Unmarshal(b, &value); err != nil {
		t.Fatal(err)
	}
	schema := full
	if fragment {
		schema = fr
	}
	if err := schema.Validate(value); err != nil {
		t.Errorf("an editor rejects this descriptor: %v\n%s", err, data)
	}
	for _, key := range DeprecatedKeysIn(value) {
		t.Errorf("writes %s, a key Draugr still reads and no longer writes\n%s", key, data)
	}
}

// deprecatedKeys are the descriptor keys still read, so no descriptor breaks, and no longer
// written. "*" is every element of a list. A file Draugr writes teaches its reader the spelling in
// it, so a writer that emits one of these teaches the older one, and both readers accept it, so no
// other check objects.
var deprecatedKeys = [][]string{
	{"config", "controllers"},
	{"config", "gate", "failOnPriority"},
	{"components", "*", "controllers"},
}

// DeprecatedKeysIn returns the deprecated keys a decoded descriptor sets, as dotted paths.
func DeprecatedKeysIn(doc any) []string {
	var found []string
	for _, path := range deprecatedKeys {
		found = append(found, findKey(doc, path, "")...)
	}
	return found
}

func findKey(v any, path []string, at string) []string {
	if len(path) == 0 {
		return []string{strings.TrimPrefix(at, ".")}
	}
	switch t := v.(type) {
	case map[string]any:
		if child, ok := t[path[0]]; ok {
			return findKey(child, path[1:], at+"."+path[0])
		}
	case []any:
		if path[0] == "*" {
			var out []string
			for i, e := range t {
				out = append(out, findKey(e, path[1:], at+"["+strconv.Itoa(i)+"]")...)
			}
			return out
		}
	}
	return nil
}

// BothAccept fails the test unless the schema and the loader both accept data.
func BothAccept(t testing.TB, data []byte, fragment bool) {
	t.Helper()
	EditorAccepts(t, data, fragment)
	var err error
	if fragment {
		_, err = saga.LoadFragment(data, "surveyed.saga-fragment.yaml")
	} else {
		_, err = saga.Load(data)
	}
	if err != nil {
		t.Errorf("draugr validate rejects this descriptor: %v\n%s", err, data)
	}
}

// FragmentAccepted marshals a fragment the way Draugr writes one and holds it to both readers.
func FragmentAccepted(t testing.TB, f saga.Fragment) {
	t.Helper()
	data, err := saga.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	BothAccept(t, data, true)
}

// SchemaError is what the JSON Schema says about a decoded descriptor, nil when it accepts it.
func SchemaError(t testing.TB, doc any, fragment bool) error {
	t.Helper()
	full, fr := schemas(t)
	if fragment {
		return fr.Validate(JSONOf(doc))
	}
	return full.Validate(JSONOf(doc))
}

// Mutation is one change to a descriptor, and where it was made.
type Mutation struct {
	Kind, Path string
	Doc        any
}

// JSONOf turns a decoded YAML document into the JSON value a schema validates.
func JSONOf(doc any) any {
	b, err := json.Marshal(doc)
	if err != nil {
		return nil
	}
	var out any
	_ = json.Unmarshal(b, &out)
	return out
}

func deepCopy(v any) any {
	switch x := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, e := range x {
			m[k] = deepCopy(e)
		}
		return m
	case []any:
		s := make([]any, len(x))
		for i, e := range x {
			s[i] = deepCopy(e)
		}
		return s
	default:
		return v
	}
}

// at returns the node a path of keys and indexes names, in a copy it can be changed in.
func at(doc any, path []string) any {
	n := doc
	for _, p := range path {
		switch x := n.(type) {
		case map[string]any:
			n = x[p]
		case []any:
			i, _ := strconv.Atoi(p)
			n = x[i]
		}
	}
	return n
}

func set(doc any, path []string, v any) {
	parent := at(doc, path[:len(path)-1])
	last := path[len(path)-1]
	switch x := parent.(type) {
	case map[string]any:
		x[last] = v
	case []any:
		i, _ := strconv.Atoi(last)
		x[i] = v
	}
}

// Mutations lists every single change the parity test makes to a descriptor: each string in the
// wrong case and as a value nothing defines, an unknown key in each mapping, and each label as a
// number.
func Mutations(base any) []Mutation {
	var out []Mutation
	var walk func(n any, path []string)
	walk = func(n any, path []string) {
		switch x := n.(type) {
		case map[string]any:
			d := deepCopy(base)
			at(d, path).(map[string]any)["zzUnknownKey"] = "x"
			out = append(out, Mutation{"extra-key", strings.Join(path, "."), d})
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				here := append(append([]string{}, path...), k)
				if len(path) > 0 && path[len(path)-1] == "labels" {
					d := deepCopy(base)
					set(d, here, 1)
					out = append(out, Mutation{"label-int", strings.Join(here, "."), d})
					continue
				}
				walk(x[k], here)
			}
		case []any:
			for i, e := range x {
				walk(e, append(append([]string{}, path...), strconv.Itoa(i)))
			}
		case string:
			if up := strings.ToUpper(x); up != x {
				d := deepCopy(base)
				set(d, path, up)
				out = append(out, Mutation{"upper", strings.Join(path, "."), d})
			}
			d := deepCopy(base)
			set(d, path, "zz-not-a-value")
			out = append(out, Mutation{"unknown", strings.Join(path, "."), d})
		}
	}
	walk(base, nil)
	return out
}

// CopyDir copies a directory tree, so a mutated descriptor sits beside the files it refers to.
func CopyDir(t testing.TB, src, dst string) {
	t.Helper()
	var files, dirs []string
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			dirs = append(dirs, p)
		} else {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range dirs {
		rel, _ := filepath.Rel(src, d)
		if err := os.MkdirAll(filepath.Join(dst, rel), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range files {
		rel, _ := filepath.Rel(src, f)
		b, err := os.ReadFile(f) // #nosec G304 G703 -- a file under the test's own examples directory
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, rel), b, 0o600); err != nil { // #nosec G703 -- inside the test's temp dir
			t.Fatal(err)
		}
	}
}

// EditorAcceptsFile is EditorAccepts for a descriptor on disk.
func EditorAcceptsFile(t testing.TB, path string, fragment bool) {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- a file the calling test wrote
	if err != nil {
		t.Fatal(err)
	}
	EditorAccepts(t, data, fragment)
}
