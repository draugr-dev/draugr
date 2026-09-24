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

// No example a reader can copy uses a key the parser refuses.
//
// A removed key is refused with the sentence in removedFields, so a descriptor copied from the
// documentation fails on its first run, and the page it came from still reads as correct. The
// parser and the pages are held to one table here, so removing a key is what makes every page
// still showing it fail.
func TestNoExampleUsesARemovedKey(t *testing.T) {
	const root = "../.."
	var sources []string
	for _, dir := range []string{"docs", "examples"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && (strings.HasSuffix(path, ".md") || strings.HasSuffix(path, ".yaml")) {
				sources = append(sources, path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	sources = append(sources, filepath.Join(root, "README.md"))
	if len(sources) < 10 {
		t.Fatalf("found %d documents under %s; the walk is not reading the tree", len(sources), root)
	}

	for _, path := range sources {
		// #nosec G304 -- every path is one the walk above found under this repository's own docs
		// and examples; nothing comes from input.
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		where, _ := filepath.Rel(root, path)
		for _, block := range yamlIn(path, string(content)) {
			var doc yaml.Node
			// A block that is not YAML on its own, such as one with an ellipsis standing for the
			// rest of a file, has no keys to check.
			if yaml.Unmarshal([]byte(block.text), &doc) != nil {
				continue
			}
			for _, key := range keyPaths(&doc, "") {
				if why, ok := removedFields[key]; ok {
					t.Errorf("%s:%d shows %s, which the parser refuses: %s", where, block.line, key, why)
				}
			}
		}
	}
}

type yamlBlock struct {
	text string
	line int
}

var fence = regexp.MustCompile("(?m)^```ya?ml[^\\n]*\\n")

// yamlIn returns each YAML block in a Markdown file, or the whole of a YAML file.
func yamlIn(path, content string) []yamlBlock {
	if strings.HasSuffix(path, ".yaml") {
		return []yamlBlock{{text: content, line: 1}}
	}
	var out []yamlBlock
	for _, loc := range fence.FindAllStringIndex(content, -1) {
		rest := content[loc[1]:]
		end := strings.Index(rest, "\n```")
		if end < 0 {
			continue
		}
		out = append(out, yamlBlock{text: rest[:end], line: strings.Count(content[:loc[1]], "\n") + 1})
	}
	return out
}

// keyPaths names every mapping key the way removedFields does: dotted, with `[]` for a list.
func keyPaths(n *yaml.Node, prefix string) []string {
	var out []string
	switch n.Kind {
	case yaml.DocumentNode:
		for _, c := range n.Content {
			out = append(out, keyPaths(c, prefix)...)
		}
	case yaml.SequenceNode:
		for _, c := range n.Content {
			out = append(out, keyPaths(c, prefix+"[]")...)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			key := n.Content[i].Value
			if prefix != "" {
				key = prefix + "." + key
			}
			out = append(out, key)
			out = append(out, keyPaths(n.Content[i+1], key)...)
		}
	}
	return out
}
