package saga

import (
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Each exclusion knows the line it starts at in the file it was written in, and that file on disk,
// whether it is the root, a local fragment, or a fragment fetched from another repository.
func TestResolveRecordsWhereEachExclusionIsWritten(t *testing.T) {
	dir := t.TempDir()
	root := write(t, dir, "draugr.saga.yaml", rootHeader+`components: [{ name: web, repositories: [{ url: "." }] }]
config:
  exclude:
    - rules: ["ROOT-1"]
      reason: "first"

    - paths: ["fixtures/"]
      reason: "second"
fragments:
  - path: "excl/*.saga-fragment.yaml"
  - url: https://github.com/acme/platform.git
    revision: v2.4.0
    path: "policy/shared.saga-fragment.yaml"
`)
	local := write(t, dir, "excl/legacy.saga-fragment.yaml", `# a comment line
config:
  exclude:
    - rules: ["FRAG-1"]
      reason: "from a fragment"
`)
	remote := t.TempDir()
	fetched := write(t, remote, "policy/shared.saga-fragment.yaml", "config:\n  exclude:\n    - { rules: [REMOTE-1], reason: upstream }\n")

	res, err := ResolveFile(root, &fakeFetcher{dir: remote, resolved: "a1b3f9c0d2e4f6a8b0c2"})
	if err != nil {
		t.Fatalf("ResolveFile: %v", err)
	}
	want := []struct {
		line int
		file string
	}{
		{6, root}, {9, root}, {4, local}, {3, fetched},
	}
	rules := res.Model.Config.Exclude
	if len(rules) != len(want) {
		t.Fatalf("exclusions = %d, want %d", len(rules), len(want))
	}
	for i, w := range want {
		if rules[i].Line != w.line || filepath.Clean(rules[i].File) != filepath.Clean(w.file) {
			t.Errorf("exclusion %d (%s) at %s:%d, want %s:%d", i, rules[i].Reason, rules[i].File, rules[i].Line, w.file, w.line)
		}
	}
	// The remote one is named by its repository and read from the checkout, two different paths.
	if rules[3].Source == rules[3].File {
		t.Errorf("a fetched fragment's source should name its repository, not the checkout: %q", rules[3].Source)
	}
}

// Each image knows the file and the line of its `image:` key, whether the descriptor or a local
// fragment declares it, and with a digest written beside it or into it. An image a fragment from
// another repository declares has a line and no file: that file is not in this repository.
func TestResolveRecordsWhereEachImageIsDeclared(t *testing.T) {
	dir := t.TempDir()
	root := write(t, dir, "draugr.saga.yaml", rootHeader+`components:
  - name: api
    images:
      - image: registry.example.com/api:1.2
        digest: sha256:`+strings.Repeat("a", 64)+`

      - builtBy: upstream
        image: postgres:16
fragments:
  - path: "saga/*.saga-fragment.yaml"
  - url: https://github.com/acme/platform.git
    revision: v2.4.0
    path: "shared.saga-fragment.yaml"
`)
	local := write(t, dir, "saga/worker.saga-fragment.yaml", `# the worker
components:
  - name: worker
    images: [{ image: "debian@sha256:`+strings.Repeat("b", 64)+`" }]
  - name: api
    images:
      - image: postgres:16
      - image: redis:7
`)
	remote := t.TempDir()
	write(t, remote, "shared.saga-fragment.yaml", "components:\n  - name: cache\n    images:\n      - image: memcached:1.6\n")

	res, err := ResolveFile(root, &fakeFetcher{dir: remote, resolved: "a1b3f9c0d2e4f6a8b0c2"})
	if err != nil {
		t.Fatalf("ResolveFile: %v", err)
	}
	type at struct {
		file string
		line int
	}
	want := map[string]map[string]at{
		// postgres:16 is declared in the root first, and the fragment's second mention adds nothing.
		"api":    {"registry.example.com/api:1.2": {root, 6}, "postgres:16": {root, 10}, "redis:7": {local, 8}},
		"worker": {"debian@sha256:" + strings.Repeat("b", 64): {local, 4}},
		"cache":  {"memcached:1.6": {"", 4}},
	}
	for _, c := range res.Model.Components {
		for _, img := range c.Images {
			w, ok := want[c.Name][img.Image]
			if !ok {
				t.Errorf("%s: unexpected image %q", c.Name, img.Image)
				continue
			}
			if filepath.Clean(img.File) != filepath.Clean(w.file) || img.Line != w.line {
				t.Errorf("%s %s: declared at %s:%d, want %s:%d", c.Name, img.Image, img.File, img.Line, w.file, w.line)
			}
			delete(want[c.Name], img.Image)
		}
	}
	for comp, left := range want {
		for ref := range left {
			t.Errorf("%s: image %q missing", comp, ref)
		}
	}
	if !filepath.IsAbs(res.Model.Components[0].Images[0].File) {
		t.Errorf("file %q: want an absolute path, which a later change of directory does not move", res.Model.Components[0].Images[0].File)
	}
}

// Images that do not line up one to one with the document's entries, such as a list a merge key
// supplied, are left without lines rather than given another entry's.
func TestStampImageLinesLeavesAMismatchAlone(t *testing.T) {
	stampImageLines(nil, nil)
	parse := func(doc string) *yaml.Node {
		t.Helper()
		var root yaml.Node
		if err := yaml.Unmarshal([]byte(doc), &root); err != nil {
			t.Fatal(err)
		}
		return &root
	}
	one := parse("components:\n  - name: web\n    images: [{ image: a }]\n")

	extra := []Component{{Name: "web", Images: []Image{{Image: "a"}, {Image: "built in code"}}}}
	stampImageLines(one, extra)
	if extra[0].Images[0].Line != 0 || extra[0].Images[1].Line != 0 {
		t.Errorf("an image list longer than the document's: lines = %d, %d, want none", extra[0].Images[0].Line, extra[0].Images[1].Line)
	}
	two := []Component{{Name: "web", Images: []Image{{Image: "a"}}}, {Name: "built in code"}}
	stampImageLines(one, two)
	if two[0].Images[0].Line != 0 {
		t.Errorf("a component list longer than the document's: line = %d, want none", two[0].Images[0].Line)
	}
	merged := []Component{{Name: "web", Images: []Image{{Image: "a"}}}}
	stampImageLines(parse("base: &base\n  images: [{ image: a }]\ncomponents:\n  - name: web\n    <<: *base\n"), merged)
	if merged[0].Images[0].Line != 0 {
		t.Errorf("a list a merge key supplied: line = %d, want none", merged[0].Images[0].Line)
	}
}

// An entry written once under an anchor and repeated by alias is written where the anchor is.
func TestLoadStampsTheLineAnAliasPointsAt(t *testing.T) {
	m, err := loadModel([]byte(`config:
  exclude:
    - &fixture
      paths: ["fixtures/"]
      reason: "fixtures"
    - *fixture
    - rules: [x]
      reason: "x"
`), false)
	if err != nil {
		t.Fatal(err)
	}
	got := m.Config.Exclude
	if got[0].Line != 3 || got[1].Line != 3 || got[2].Line != 7 {
		t.Errorf("lines = %d, %d, %d, want 3, 3, 7", got[0].Line, got[1].Line, got[2].Line)
	}
}

// Rules that do not line up one to one with the document's entries are left alone rather than
// stamped with lines that belong to other entries.
func TestStampExcludeLinesLeavesAMismatchAlone(t *testing.T) {
	stampExcludeLines(nil, nil)
	var root yaml.Node
	if err := yaml.Unmarshal([]byte("config:\n  exclude:\n    - { rules: [a], reason: a }\n"), &root); err != nil {
		t.Fatal(err)
	}
	rules := []ExcludeRule{{Reason: "a"}, {Reason: "built in code"}}
	stampExcludeLines(&root, rules)
	if rules[0].Line != 0 || rules[1].Line != 0 {
		t.Errorf("lines = %d, %d, want none", rules[0].Line, rules[1].Line)
	}
}

// The console line names the commit as the last to change the line, which is what blame reports;
// a table cell already labeled as git history carries the same facts without the verb.
func TestLineHistoryString(t *testing.T) {
	cases := []struct {
		h             LineHistory
		line, summary string
	}{
		{LineHistory{Commit: "4f2a9c1e0b3d5f7a9c1e0b3d5f7a9c1e0b3d5f7a", Author: "Ada Lovelace", Date: "2026-09-14T10:00:00+02:00"},
			"last changed in 4f2a9c1e0b3d by Ada Lovelace, 2026-09-14", "4f2a9c1e0b3d by Ada Lovelace, 2026-09-14"},
		{LineHistory{Commit: "4f2a9c1", Author: "Ada Lovelace", Date: "2026-09-14"},
			"last changed in 4f2a9c1 by Ada Lovelace, 2026-09-14", "4f2a9c1 by Ada Lovelace, 2026-09-14"},
		{LineHistory{Path: "draugr.saga.yaml", Unavailable: "the line is not committed"},
			"git history unavailable: the line is not committed", "unavailable: the line is not committed"},
	}
	for _, c := range cases {
		if got := c.h.String(); got != c.line {
			t.Errorf("String() = %q, want %q", got, c.line)
		}
		if got := c.h.Summary(); got != c.summary {
			t.Errorf("Summary() = %q, want %q", got, c.summary)
		}
	}
}
