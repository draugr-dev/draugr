package saga

import (
	"path/filepath"
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
      acceptedBy: someone
`), false)
	if err != nil {
		t.Fatal(err)
	}
	got := m.Config.Exclude
	if got[0].Line != 3 || got[1].Line != 3 || got[2].Line != 7 {
		t.Errorf("lines = %d, %d, %d, want 3, 3, 7", got[0].Line, got[1].Line, got[2].Line)
	}
	if got[2].acceptedByLine != 9 || got[0].acceptedByLine != 0 {
		t.Errorf("acceptedBy lines = %d, %d, want 9 and none", got[2].acceptedByLine, got[0].acceptedByLine)
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

func TestLineHistoryString(t *testing.T) {
	cases := []struct {
		h    LineHistory
		want string
	}{
		{LineHistory{Commit: "4f2a9c1e0b3d5f7a9c1e0b3d5f7a9c1e0b3d5f7a", Author: "Ada Lovelace", Date: "2026-09-14T10:00:00+02:00"},
			"applied in 4f2a9c1e0b3d by Ada Lovelace, 2026-09-14 (git history)"},
		{LineHistory{Commit: "4f2a9c1", Author: "Ada Lovelace", Date: "2026-09-14"},
			"applied in 4f2a9c1 by Ada Lovelace, 2026-09-14 (git history)"},
		{LineHistory{Path: "draugr.saga.yaml", Unavailable: "the line is not committed"},
			"git history unavailable: the line is not committed"},
	}
	for _, c := range cases {
		if got := c.h.String(); got != c.want {
			t.Errorf("String() = %q, want %q", got, c.want)
		}
	}
}
