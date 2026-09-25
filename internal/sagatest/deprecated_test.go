package sagatest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestEveryDeprecatedKeyIsRefused holds deprecatedKeys to the fields pkg/saga marks Deprecated. A
// field deprecated there and missing here is a spelling every writer could go on emitting with
// nothing to object.
func TestEveryDeprecatedKeyIsRefused(t *testing.T) {
	files, err := filepath.Glob("../../pkg/saga/*.go")
	if err != nil {
		t.Fatal(err)
	}
	var marked []string
	fset := token.NewFileSet()
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			field, ok := n.(*ast.Field)
			if !ok || field.Doc == nil || field.Tag == nil || !strings.Contains(field.Doc.Text(), "Deprecated:") {
				return true
			}
			tag, err := strconv.Unquote(field.Tag.Value)
			if err != nil {
				t.Fatal(err)
			}
			name, _, _ := strings.Cut(reflect.StructTag(tag).Get("yaml"), ",")
			marked = append(marked, name)
			return true
		})
	}
	var listed []string
	for _, path := range deprecatedKeys {
		listed = append(listed, path[len(path)-1])
	}
	slices.Sort(marked)
	slices.Sort(listed)
	if len(marked) == 0 || !slices.Equal(marked, listed) {
		t.Errorf("pkg/saga marks %v deprecated; deprecatedKeys lists %v", marked, listed)
	}
}

func TestDeprecatedKeysIn(t *testing.T) {
	doc := map[string]any{
		"config": map[string]any{
			"controllers": map[string]any{},
			"gate":        map[string]any{"failOn": "P1"},
		},
		"components": []any{
			map[string]any{"name": "a"},
			map[string]any{"name": "b", "controllers": map[string]any{}},
		},
	}
	got := DeprecatedKeysIn(doc)
	want := []string{"config.controllers", "components[1].controllers"}
	if !slices.Equal(got, want) {
		t.Errorf("found %v, want %v", got, want)
	}
	if got := DeprecatedKeysIn("not a descriptor"); len(got) != 0 {
		t.Errorf("found %v in a string", got)
	}
}
