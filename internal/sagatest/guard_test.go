package sagatest

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestEveryDescriptorWriterIsHeldToTheSchema requires every package that writes a descriptor to
// check what it writes with this package.
//
// saga.Marshal is how Draugr renders a descriptor for somebody to keep: `init`, a survey, a merge,
// `classify`, the MCP survey tool. A package calling it writes YAML a person will open in an
// editor, so its tests hold that YAML to the schema the editor uses. A new writer with no such
// check could emit a field the schema refuses, and nothing would notice until an editor did.
func TestEveryDescriptorWriterIsHeldToTheSchema(t *testing.T) {
	writes := regexp.MustCompile(`\bsaga\.Marshal\(`)
	checks := regexp.MustCompile(`\bsagatest\.(EditorAccepts|EditorAcceptsFile|BothAccept|FragmentAccepted)\(`)
	writers := map[string]bool{}
	checked := map[string]bool{}
	var paths []string
	err := filepath.WalkDir("../..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "node_modules" || d.Name() == ".claude") {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(path, ".go") {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		body, err := os.ReadFile(path) // #nosec G304 -- a source file this test found in the repository
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Dir(path)
		switch {
		case strings.HasSuffix(path, "_test.go"):
			if checks.Match(body) {
				checked[dir] = true
			}
		case writes.Match(body) && !strings.HasSuffix(dir, filepath.Join("pkg", "saga")) && !strings.HasSuffix(dir, "sagatest"):
			writers[dir] = true
		}
	}
	if len(writers) < 2 {
		t.Fatalf("found %d packages writing descriptors; the walk has stopped seeing them", len(writers))
	}
	for dir := range writers {
		if !checked[dir] {
			t.Errorf("%s writes descriptors with saga.Marshal, and none of its tests holds the output to "+
				"the schema: call sagatest.EditorAccepts on what it writes", dir)
		}
	}
}
