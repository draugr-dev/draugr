//go:build integration

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A cache entry has to describe the commit it was computed from, and only a run can prove it does.
// A unit test builds a target and asks what key it produces, which never asks the question this
// turns on: what revision a repository on disk actually has. A cache keyed on anything that moves
// answers about a commit nobody scanned, and the direction that costs something is a clean result
// for a commit that introduced a finding.
//
// Two commits, one cache directory, one descriptor, and no revision declared, which is what
// `url: .` writes and what most descriptors say.
func TestACachedResultDoesNotOutliveItsCommit(t *testing.T) {
	requireTool(t, "git", "the scan checks the repository out before scanning it")
	requireTool(t, "gitleaks", "the second commit has to introduce something a scanner finds")

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
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(repo, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	write("README.md", "nothing to find here\n")
	git("init", "--quiet")
	git("config", "user.email", "test@draugr.dev")
	git("config", "user.name", "test")
	git("add", ".")
	git("commit", "--quiet", "-m", "clean")

	dir := t.TempDir()
	descriptor := filepath.Join(dir, "draugr.saga.yaml")
	if err := os.WriteFile(descriptor, []byte(`project: cache-fixture
release: {version: "1.0.0"}
config:
  controls:
    secrets: {enabled: true}
components:
  - name: api
    exposure: public
    criticality: critical
    repositories:
      - url: `+repo+`
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(dir, "cache")

	scan := func() string {
		t.Helper()
		// #nosec G204 -- the binary under test and paths this test made.
		cmd := exec.Command(draugrBin(t), "scan", descriptor,
			"--cache-dir", cache, "--no-gate", "--log-level", "warn")
		out, err := cmd.CombinedOutput()
		t.Logf("exit=%v\n%s", err, out)
		return string(out)
	}

	if out := scan(); strings.Contains(out, "P1 1") {
		t.Fatalf("the first commit has nothing to find, so the fixture is wrong:\n%s", out)
	}

	// The commit the gate exists to catch.
	write("id_rsa", fakePrivateKey)
	git("add", ".")
	git("commit", "--quiet", "-m", "leak a credential")

	out := scan()
	if !strings.Contains(out, "FAIL") {
		t.Errorf("the second commit introduced a leaked credential and the scan reported no "+
			"finding, so it was served the first commit's result:\n%s", out)
	}
}

// And the saving survives, or the fix above is just caching switched off. An unchanged commit is
// answered from the cache rather than re-scanned.
func TestAnUnchangedCommitIsStillServedFromTheCache(t *testing.T) {
	requireTool(t, "git", "the scan checks the repository out before scanning it")
	requireTool(t, "gitleaks", "the scan needs a scanner whose result is worth caching")

	repo := newVulnRepo(t)
	dir := t.TempDir()
	descriptor := filepath.Join(dir, "draugr.saga.yaml")
	if err := os.WriteFile(descriptor, []byte(`project: cache-hit
release: {version: "1.0.0"}
config:
  controls:
    secrets: {enabled: true}
components:
  - name: api
    exposure: public
    criticality: critical
    repositories:
      - url: `+repo+`
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(dir, "cache")

	scan := func() string {
		t.Helper()
		// #nosec G204 -- the binary under test and paths this test made.
		cmd := exec.Command(draugrBin(t), "scan", descriptor,
			"--cache-dir", cache, "--no-gate", "--log-level", "debug")
		out, _ := cmd.CombinedOutput()
		return string(out)
	}

	if out := scan(); strings.Contains(out, "cache hit") {
		t.Fatalf("the first scan of a cold cache cannot be a hit:\n%s", out)
	}
	if out := scan(); !strings.Contains(out, "cache hit") {
		t.Errorf("the same commit was re-scanned rather than answered from the cache, so the "+
			"cache is keyed on something that moves when nothing has:\n%s", out)
	}
}
