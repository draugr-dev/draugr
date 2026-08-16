package ciguard

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestTheSelfScanCachesWhatItPaysFor keeps a saving from being undone without anyone noticing.
//
// The self-scan is the slowest check on a pull request, and almost all of it was work already
// done: provisioning four scanners that had not changed, and re-scanning a tree that had barely
// moved. Both are cached now, and a cache is the kind of thing that survives being deleted —
// nothing fails, the job simply goes back to taking four minutes, and by then the reason is
// somewhere in a diff nobody is looking at.
//
// The pairing is what this asserts, because either half alone does nothing: a cache step whose
// path the action never writes, or a cache-dir the workflow never restores.
func TestTheSelfScanCachesWhatItPaysFor(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("../../.github/workflows/selfscan.yml")
	if err != nil {
		t.Fatal(err)
	}
	var wf struct {
		Jobs map[string]struct {
			Steps []struct {
				Name string         `yaml:"name"`
				Uses string         `yaml:"uses"`
				With map[string]any `yaml:"with"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatal(err)
	}
	job, ok := wf.Jobs["selfscan"]
	if !ok {
		t.Fatal("selfscan.yml has no selfscan job")
	}

	cached := map[string]bool{}
	var scanCacheDir string
	for _, s := range job.Steps {
		if s.Uses != "" && len(s.Uses) >= len("actions/cache@") && s.Uses[:len("actions/cache@")] == "actions/cache@" {
			if p, ok := s.With["path"].(string); ok {
				cached[p] = true
			}
		}
		if s.Uses == "./" {
			if d, ok := s.With["cache-dir"].(string); ok {
				scanCacheDir = d
			}
		}
	}

	if scanCacheDir == "" {
		t.Error("the self-scan runs without cache-dir, so every run re-scans a tree that has not " +
			"changed — and the content-hash caching Draugr offers users goes untested here")
	}
	if scanCacheDir != "" && !cached[scanCacheDir] {
		t.Errorf("the scan writes its cache to %q and no cache step restores it, so it is "+
			"rebuilt from nothing on every run", scanCacheDir)
	}
	if !cached["~/.draugr/bin"] {
		t.Error("the provisioned scanners are not cached, so every run re-downloads four tools " +
			"that only change when the release does")
	}
}
