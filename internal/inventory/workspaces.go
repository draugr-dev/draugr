package inventory

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// workspace is a JavaScript workspace root and the member globs it declares, relative to it.
// npm, pnpm, Yarn and Bun write one lockfile at the root for every member.
type workspace struct {
	dir      string
	patterns []string
}

// workspaces reads the workspace roots among files, the slash-separated paths of the tree's JSON
// and YAML documents: a package.json with a workspaces field, as an array or as an object holding
// packages (npm, Yarn, Bun), and a pnpm-workspace.yaml with a packages list.
func workspaces(root string, files []string) []workspace {
	var out []workspace
	for _, rel := range files {
		var patterns []string
		switch path.Base(rel) {
		case "package.json":
			patterns = packageJSONWorkspaces(readFile(root, rel))
		case "pnpm-workspace.yaml", "pnpm-workspace.yml":
			var doc struct {
				Packages []string `yaml:"packages"`
			}
			if yaml.Unmarshal(readFile(root, rel), &doc) == nil {
				patterns = doc.Packages
			}
		}
		if len(patterns) > 0 {
			out = append(out, workspace{dir: path.Dir(rel), patterns: patterns})
		}
	}
	return out
}

// packageJSONWorkspaces reads a package.json's workspaces field, in either of its two shapes.
func packageJSONWorkspaces(content []byte) []string {
	var doc struct {
		Workspaces json.RawMessage `json:"workspaces"`
	}
	if json.Unmarshal(content, &doc) != nil || len(doc.Workspaces) == 0 {
		return nil
	}
	var list []string
	if json.Unmarshal(doc.Workspaces, &list) == nil {
		return list
	}
	var obj struct {
		Packages []string `json:"packages"`
	}
	if json.Unmarshal(doc.Workspaces, &obj) == nil {
		return obj.Packages
	}
	return nil
}

// member reports whether dir is a member of a workspace in wss: beneath its root, matched by one
// of its globs and excluded by none of its `!` globs.
func member(dir string, wss []workspace) bool {
	for _, ws := range wss {
		rel, ok := beneathDir(dir, ws.dir)
		if !ok {
			continue
		}
		in := false
		for _, p := range ws.patterns {
			if negated, ok := strings.CutPrefix(p, "!"); ok {
				if globMatch(negated, rel) {
					in = false
					break
				}
				continue
			}
			in = in || globMatch(p, rel)
		}
		if in {
			return true
		}
	}
	return false
}

// beneathDir is dir relative to root, and whether dir lies strictly beneath it.
func beneathDir(dir, root string) (string, bool) {
	if root == "." {
		return dir, dir != "."
	}
	rel, ok := strings.CutPrefix(dir, root+"/")
	return rel, ok && rel != ""
}

// globMatch matches a workspace glob against a slash-separated directory: `*` within one path
// segment, `**` across any number of them. A leading `./` and a trailing `/` are dropped.
func globMatch(pattern, dir string) bool {
	pattern = strings.TrimSuffix(strings.TrimPrefix(pattern, "./"), "/")
	return matchSegments(strings.Split(pattern, "/"), strings.Split(dir, "/"))
}

func matchSegments(pattern, name []string) bool {
	if len(pattern) == 0 {
		return len(name) == 0
	}
	if pattern[0] == "**" {
		for i := 0; i <= len(name); i++ {
			if matchSegments(pattern[1:], name[i:]) {
				return true
			}
		}
		return false
	}
	if len(name) == 0 {
		return false
	}
	ok, err := path.Match(pattern[0], name[0])
	return err == nil && ok && matchSegments(pattern[1:], name[1:])
}

func readFile(root, rel string) []byte {
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel))) // #nosec G304 -- a file under the tree being initialized
	if err != nil {
		return nil
	}
	return content
}
