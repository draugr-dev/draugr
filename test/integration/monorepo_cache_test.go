//go:build integration

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Components scoped with paths: on one repository are each cached against the content they read,
// not the repository's commit. That is what keeps a commit to one component from re-scanning every
// other, and it is only safe while the key still moves for everything a scoped checkout holds: a
// root file a component's paths name, and the scanners' configuration kept at the root for every
// component. A key blind to either keeps serving a result computed before the file changed, and the
// direction that costs something is a clean answer for a commit that introduced a finding.
//
// Only a run can prove it. The key is assembled from the revision the engine resolves on disk, the
// paths the descriptor declares and the root files git reports, and a unit test supplies all three
// itself. One repository, one cache directory and one descriptor, with a commit before every scan.
func TestAScopedCacheEntryMovesWithEveryFileItsCheckoutHolds(t *testing.T) {
	requireTool(t, "git", "the scan checks the repository out before scanning it")
	requireTool(t, "gitleaks", "the scan needs a scanner whose result is worth caching")

	repo := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		// #nosec G204 -- a fixed binary and argument lists this test wrote.
		c := exec.Command("git", args...)
		c.Dir = repo
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	commit := func(name, body string) {
		t.Helper()
		path := filepath.Join(repo, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		git("add", name)
		git("commit", "--quiet", "-m", "edit "+name)
	}

	git("init", "--quiet")
	git("config", "user.email", "test@draugr.dev")
	git("config", "user.name", "test")
	commit("api/main.go", "package main\n")
	commit("web/index.js", "module.exports = {};\n")
	commit("shared.env", "REGION=eu-west-1\n")
	commit("README.md", "two services\n")

	dir := t.TempDir()
	descriptor := filepath.Join(dir, "draugr.saga.yaml")
	if err := os.WriteFile(descriptor, []byte(`project: monorepo-cache
release: {version: "1.0.0"}
config:
  controls:
    secrets: {enabled: true}
components:
  - name: api
    repositories:
      - url: `+repo+`
        paths: [api, shared.env]
  - name: web
    repositories:
      - url: `+repo+`
        paths: [web, shared.env]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(dir, "cache")

	// hits scans and returns the components whose job was answered from the cache. The debug line
	// carries the key, and each key names its component's own subtree.
	hits := func() []string {
		t.Helper()
		// #nosec G204 -- the binary under test and paths this test made.
		out, _ := exec.Command(draugrBin(t), "scan", descriptor,
			"--cache-dir", cache, "--no-gate", "--log-level", "debug").CombinedOutput()
		// The revision part of a key lists each declared path as path=id, joined by ";" after "@".
		names := func(line, path string) bool {
			return strings.Contains(line, "@"+path+"=") || strings.Contains(line, ";"+path+"=")
		}
		var got []string
		for line := range strings.SplitSeq(string(out), "\n") {
			if !strings.Contains(line, "cache hit") {
				continue
			}
			switch {
			case names(line, "api"):
				got = append(got, "api")
			case names(line, "web"):
				got = append(got, "web")
			default:
				t.Errorf("a cache hit whose key names neither component's subtree, so it was keyed "+
					"on the commit:\n%s", line)
			}
		}
		slices.Sort(got)
		return got
	}

	for _, step := range []struct {
		name string
		// edit is the file committed before the scan, or empty for none.
		edit, body string
		want       []string
	}{
		{name: "a cold cache", want: nil},
		{name: "the same commit", want: []string{"api", "web"}},
		{name: "a root file neither component names", edit: "README.md", body: "two services, one repository\n",
			want: []string{"api", "web"}},
		{name: "a file inside api's paths", edit: "api/main.go", body: "package main\n\nfunc main() {}\n",
			want: []string{"web"}},
		{name: "a root file both components name", edit: "shared.env", body: "REGION=us-east-1\n",
			want: nil},
		{name: "scanner configuration at the root", edit: ".gitleaksignore", body: "# no entries\n",
			want: nil},
		{name: "the same commit again", want: []string{"api", "web"}},
	} {
		if step.edit != "" {
			commit(step.edit, step.body)
		}
		if got := hits(); !slices.Equal(got, step.want) {
			t.Errorf("after %s: served from the cache %v, want %v", step.name, got, step.want)
		}
	}
}
