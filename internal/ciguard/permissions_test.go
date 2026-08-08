package ciguard

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestCallersGrantEveryPermissionTheCalledWorkflowDeclares catches a failure with no diagnostic.
//
// A reusable workflow cannot request a permission its caller did not grant. When it does, the
// whole run fails at startup: no jobs, no logs, no annotation naming the scope that was missing.
// The workflow file is valid, actionlint is clean, and the only symptom is a run that produced
// nothing — which on a tag looks identical to a release that was never triggered.
//
// The two drift apart naturally, because a job added to the called workflow is a change to a file
// the caller does not mention.
func TestCallersGrantEveryPermissionTheCalledWorkflowDeclares(t *testing.T) {
	dir := "../../.github/workflows"
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read workflows: %v", err)
	}

	declared := map[string]map[string]bool{} // workflow file → permission scopes any job asks for
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name())) // #nosec G304 -- this repository's own workflow directory
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		declared[e.Name()] = writeScopes(string(data))
	}

	for name, data := range mustReadAll(t, dir, entries) {
		for _, job := range jobBlocks(data) {
			called := calledWorkflow(job)
			if called == "" {
				continue
			}
			granted := writeScopes(job)
			for scope := range declared[called] {
				if !granted[scope] {
					t.Errorf("%s calls %s, which declares %q on one of its jobs, but grants only "+
						"%v — the run fails at startup with no job and no message naming the scope",
						name, called, scope, keys(granted))
				}
			}
		}
	}
}

// jobBlocks splits a workflow into one string per job.
//
// Whole blocks rather than what follows the `uses:` line, because YAML job keys have no order: a
// caller may declare `permissions:` above its `uses:` or below it, and a check that only looked
// one way would report a call that is correct.
func jobBlocks(data string) []string {
	lines := strings.Split(data, "\n")
	start := -1
	for i, l := range lines {
		if strings.TrimSpace(l) == "jobs:" {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return nil
	}
	var blocks []string
	var cur []string
	for _, l := range lines[start:] {
		trimmed := strings.TrimSpace(l)
		// A job key: two spaces of indent, ending in a colon. Anything less is out of `jobs:`.
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") && indent(l) == 2 && strings.HasSuffix(trimmed, ":") {
			if len(cur) > 0 {
				blocks = append(blocks, strings.Join(cur, "\n"))
			}
			cur = []string{l}
			continue
		}
		if trimmed != "" && indent(l) == 0 && !strings.HasPrefix(trimmed, "#") {
			break // back out to a top-level key
		}
		if len(cur) > 0 {
			cur = append(cur, l)
		}
	}
	if len(cur) > 0 {
		blocks = append(blocks, strings.Join(cur, "\n"))
	}
	return blocks
}

// calledWorkflow returns the local workflow a job calls, or "" when it calls none.
func calledWorkflow(job string) string {
	m := regexp.MustCompile(`(?m)^\s*uses:\s*\./\.github/workflows/([\w.-]+)\s*$`).FindStringSubmatch(job)
	if m == nil {
		return ""
	}
	return m[1]
}

// writeScopes collects every `<scope>: write` a workflow's YAML asks for. Deliberately textual:
// the question is which scopes appear, and a parser would buy precision this does not need.
func writeScopes(yaml string) map[string]bool {
	out := map[string]bool{}
	re := regexp.MustCompile(`(?m)^\s*([a-z-]+):\s*write\b`)
	for _, m := range re.FindAllStringSubmatch(yaml, -1) {
		out[m[1]] = true
	}
	return out
}

func indent(s string) int { return len(s) - len(strings.TrimLeft(s, " ")) }

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func mustReadAll(t *testing.T, dir string, entries []os.DirEntry) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name())) // #nosec G304 -- this repository's own workflow directory
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		out[e.Name()] = string(data)
	}
	return out
}
