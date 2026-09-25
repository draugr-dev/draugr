//go:build integration

package integration

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
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

	if out := scan(); regexp.MustCompile(`\b[1-9]\d* P1\b`).MatchString(out) {
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

// A reused finding is a claim about a scan that did not happen, and the report has to say enough
// for somebody to judge it. Only a run can prove it does: the fields are assembled from the cache
// the engine was handed, the entry it read, and the flags the CLI parsed, and a unit test supplies
// all three itself.
//
// Two scans against one cache directory, then the second run's report read as JSON.
func TestTheReportSaysWhatItTookFromTheCache(t *testing.T) {
	requireTool(t, "git", "the scan checks the repository out before scanning it")
	requireTool(t, "gitleaks", "the scan needs a scanner whose result is worth caching")

	repo := newVulnRepo(t)
	dir := t.TempDir()
	descriptor := filepath.Join(dir, "draugr.saga.yaml")
	if err := os.WriteFile(descriptor, []byte(`project: cache-reported
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
	cacheDir := filepath.Join(dir, "cache")

	var stats struct {
		CacheHits int `json:"cacheHits"`
		Cache     struct {
			Enabled   bool       `json:"enabled"`
			Dir       string     `json:"dir"`
			TTL       string     `json:"ttl"`
			ReadOnly  bool       `json:"readOnly"`
			Hits      int        `json:"hits"`
			OldestHit *time.Time `json:"oldestHit"`
		} `json:"cache"`
	}
	scan := func(outDir string, args ...string) {
		t.Helper()
		full := append([]string{"scan", descriptor, "-o", outDir, "--no-gate"}, args...)
		// #nosec G204 -- the binary under test and paths this test made.
		if out, err := exec.Command(draugrBin(t), full...).CombinedOutput(); err != nil {
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatalf("scan: %v\n%s", err, out)
			}
		}
		raw, err := os.ReadFile(filepath.Join(outDir, "report.json")) // #nosec G304 -- this test's dir.
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Stats json.RawMessage `json:"stats"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		stats.Cache.OldestHit = nil
		if err := json.Unmarshal(doc.Stats, &stats); err != nil {
			t.Fatal(err)
		}
	}

	// No cache at all. The one case the counts cannot express, and the reason `enabled` exists.
	scan(filepath.Join(dir, "out-nocache"))
	if stats.Cache.Enabled {
		t.Error("no --cache-dir was given and the report says a cache was in use")
	}

	scan(filepath.Join(dir, "out-cold"), "--cache-dir", cacheDir, "--cache-ttl", "2h")
	if !stats.Cache.Enabled || stats.Cache.Dir != cacheDir {
		t.Errorf("a cache was given and the report does not name it: %+v", stats.Cache)
	}
	if stats.Cache.TTL != "2h0m0s" {
		t.Errorf("ttl = %q, want the flag's value", stats.Cache.TTL)
	}
	if stats.Cache.OldestHit != nil {
		t.Errorf("a cold run reused nothing and reported an age: %v", stats.Cache.OldestHit)
	}

	before := time.Now()
	scan(filepath.Join(dir, "out-warm"), "--cache-dir", cacheDir, "--cache-ttl", "2h")
	if stats.Cache.Hits == 0 || stats.Cache.Hits != stats.CacheHits {
		t.Fatalf("hits = %d, cacheHits = %d, want a hit and the two to agree",
			stats.Cache.Hits, stats.CacheHits)
	}
	if stats.Cache.OldestHit == nil {
		t.Fatal("something was reused and the report does not say how old it is")
	}
	// Written by the cold run, so before this one started and not in the future.
	if stats.Cache.OldestHit.After(before) {
		t.Errorf("oldestHit %v is after the run that read it began (%v)", stats.Cache.OldestHit, before)
	}

	scan(filepath.Join(dir, "out-ro"), "--cache-dir", cacheDir, "--cache-ttl", "2h", "--cache-read-only")
	if !stats.Cache.ReadOnly {
		t.Error("the run was told not to write and the report does not say so")
	}
}
