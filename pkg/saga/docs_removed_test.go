package saga

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// yamlFence matches a fenced YAML block in markdown, capturing its body.
var yamlFence = regexp.MustCompile("(?ms)^```ya?ml\\n(.*?)^```")

// TestNoDocumentedExampleUsesARemovedField keeps the documentation from teaching a key the loader
// refuses.
//
// A block in a guide is copied more often than a file in examples/, and it is not loaded by any
// test that loads examples. A removed key left in one reads as current to everybody who meets it,
// and the reader who copies it is told by the loader that the documentation was wrong.
//
// Blocks are fragments as often as descriptors, so only the paths in removedFields are looked for;
// a block that does not parse as YAML is not a descriptor anybody can copy whole, and is skipped.
func TestNoDocumentedExampleUsesARemovedField(t *testing.T) {
	t.Parallel()

	var docs []string
	err := filepath.WalkDir("../../docs", func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(path, ".md") {
			docs = append(docs, path)
		}
		return err
	})
	if err != nil {
		t.Fatalf("walk docs: %v", err)
	}
	docs = append(docs, "../../README.md")

	blocks := 0
	for _, path := range docs {
		text, err := os.ReadFile(path) //nolint:gosec // a fixed tree under the repository
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, m := range yamlFence.FindAllSubmatch(text, -1) {
			var doc any
			if yaml.Unmarshal(m[1], &doc) != nil {
				continue
			}
			blocks++
			for key, why := range removedFields {
				if hasPath(doc, strings.Split(key, ".")) {
					t.Errorf("%s shows %s, which was removed: %s", path, key, why)
				}
			}
		}
	}
	if blocks == 0 {
		t.Fatal("no YAML blocks found under docs/, this guard has been checking nothing")
	}
}

// hasPath reports whether doc holds the key path, where a segment ending in [] is a list whose
// every element is searched.
func hasPath(doc any, path []string) bool {
	if len(path) == 0 {
		return true
	}
	m, ok := doc.(map[string]any)
	if !ok {
		return false
	}
	name, list := strings.CutSuffix(path[0], "[]")
	next, ok := m[name]
	if !ok {
		return false
	}
	if !list {
		return hasPath(next, path[1:])
	}
	items, _ := next.([]any)
	for _, item := range items {
		if hasPath(item, path[1:]) {
			return true
		}
	}
	return false
}
