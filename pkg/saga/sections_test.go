package saga

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

// decodableTypes lists every struct the strict decoder can be filling in when it meets an unknown
// key: everything reachable from the two roots through a yaml-tagged field.
//
// Reflection rather than a list, because a list is the thing that goes stale. A field added to the
// model brings its type here on its own, and the tests below then say what it still needs.
func decodableTypes() map[string]bool {
	found := map[string]bool{}
	var walk func(reflect.Type)
	walk = func(rt reflect.Type) {
		for rt.Kind() == reflect.Pointer || rt.Kind() == reflect.Slice {
			rt = rt.Elem()
		}
		if rt.Kind() != reflect.Struct || found[strings.ToLower(rt.Name())] {
			return
		}
		found[strings.ToLower(rt.Name())] = true
		for i := range rt.NumField() {
			tag := rt.Field(i).Tag.Get("yaml")
			if tag == "" || tag == "-" {
				continue
			}
			walk(rt.Field(i).Type)
		}
	}
	walk(reflect.TypeOf(Model{}))
	walk(reflect.TypeOf(Fragment{}))
	return found
}

// yamlKeys is every key a descriptor can contain. A type whose name is also a key, `config` and
// `release`, may map to itself; one whose name appears nowhere in a file may not.
func yamlKeys() map[string]bool {
	keys := map[string]bool{}
	var walk func(reflect.Type)
	walk = func(rt reflect.Type) {
		for rt.Kind() == reflect.Pointer || rt.Kind() == reflect.Slice {
			rt = rt.Elem()
		}
		if rt.Kind() != reflect.Struct {
			return
		}
		for i := range rt.NumField() {
			tag, _, _ := strings.Cut(rt.Field(i).Tag.Get("yaml"), ",")
			if tag == "" || tag == "-" {
				continue
			}
			if keys[strings.ToLower(tag)] {
				continue
			}
			keys[strings.ToLower(tag)] = true
			walk(rt.Field(i).Type)
		}
	}
	walk(reflect.TypeOf(Model{}))
	walk(reflect.TypeOf(Fragment{}))
	return keys
}

// A section added to the model reaches a reader under whatever the Go type is called, and nothing
// about that looks wrong: the decoder keeps working and the message keeps rendering. The only sign
// is a word nobody can search the reference for, in the one message that links to it.
func TestEverySectionHasAKeyPath(t *testing.T) {
	for name := range decodableTypes() {
		path, ok := sections[name]
		if !ok {
			t.Errorf("%s can hold an unknown key and has no entry in sections. Add the path a "+
				"reader writes, e.g. \"config.gate\"", name)
			continue
		}
		if path == name && !yamlKeys()[name] {
			t.Errorf("%s maps to its own type name, which is a word no descriptor contains", name)
		}
	}
}

func TestNoSectionSurvivesTheTypeItNamed(t *testing.T) {
	decodable := decodableTypes()
	var stale []string
	for name := range sections {
		if !decodable[name] {
			stale = append(stale, name)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("sections still names %v, which nothing decodes into any more", stale)
	}
}

// The removal explanations are keyed by the same path the message prints, so a renamed section
// silently stops explaining a removal and goes back to "unknown field".
func TestEveryRemovalIsKeyedToASectionThatExists(t *testing.T) {
	paths := map[string]bool{}
	for _, p := range sections {
		paths[p] = true
	}
	for key := range removedFields {
		cut := strings.LastIndex(key, ".")
		if cut < 0 || !paths[key[:cut]] {
			t.Errorf("removedFields[%q] is keyed to a section no message prints", key)
		}
	}
}

func TestTheMessageNamesTheKeyTheReaderWrote(t *testing.T) {
	for _, tc := range []struct {
		name, saga, want string
	}{
		{
			name: "a gate setting",
			saga: "project: p\nrelease:\n  version: \"1\"\nconfig:\n  gate:\n    failOnn: P1\n",
			want: `unknown field "failOnn" in config.gate`,
		},
		{
			name: "a repository setting",
			saga: "project: p\nrelease:\n  version: \"1\"\ncomponents:\n  - name: c\n    repositories:\n      - urll: .\n",
			want: `unknown field "urll" in components[].repositories`,
		},
		{
			name: "a suppression",
			saga: "project: p\nrelease:\n  version: \"1\"\nconfig:\n  exclude:\n    - reson: x\n",
			want: `unknown field "reson" in config.exclude`,
		},
		{
			name: "the top level",
			saga: "project: p\nrelease:\n  version: \"1\"\ncomponent: c\n",
			want: `unknown field "component" in the top level`,
		},
		{
			name: "a field that was removed, not misspelled",
			saga: "project: p\nrelease:\n  version: \"1\"\n  name: p\n",
			want: "release.name was removed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load([]byte(tc.saga))
			if err == nil {
				t.Fatal("expected the strict decoder to refuse this")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("got %q, want it to contain %q", err, tc.want)
			}
		})
	}
}
