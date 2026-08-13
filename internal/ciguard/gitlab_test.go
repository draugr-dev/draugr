package ciguard

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/draugr-dev/draugr/pkg/report"
)

const gitlabTemplate = "../../gitlab-ci/draugr.yml"

// A CI file is data to everything in this repository: nothing compiles it, nothing type-checks it,
// and a mistake in it produces no diagnostics at all until somebody runs a pipeline.
func readGitLabTemplate(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(gitlabTemplate)
	if err != nil {
		t.Fatalf("read the template: %v", err)
	}
	// KnownFields is off — GitLab's own keys are what they are — but yaml.v3 still rejects a
	// duplicate mapping key, which is the failure worth catching: most parsers accept one and keep
	// the last value, and GitLab refuses the file outright.
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("GitLab would refuse this file: %v", err)
	}
	return doc
}

func TestTheGitLabTemplateParses(t *testing.T) {
	doc := readGitLabTemplate(t)
	job, ok := doc["draugr"].(map[string]any)
	if !ok {
		t.Fatal("the template defines no `draugr` job, so including it adds nothing to a pipeline")
	}
	for _, key := range []string{"script", "artifacts", "rules"} {
		if _, ok := job[key]; !ok {
			t.Errorf("the draugr job has no %q", key)
		}
	}
}

// Every format the template hands to GitLab has to be one Draugr can render.
//
// A template naming a format that was renamed is invisible to every other test here: the file is
// data, the name is a string, and the first sign of trouble is a pipeline that reports an empty
// artifact. GitLab then warns and carries on, which is a green job with no findings in it.
func TestTheGitLabTemplateNamesFormatsThatExist(t *testing.T) {
	doc := readGitLabTemplate(t)
	job := doc["draugr"].(map[string]any)
	artifacts, ok := job["artifacts"].(map[string]any)
	if !ok {
		t.Fatal("the draugr job publishes no artifacts, so GitLab receives nothing")
	}
	reports, ok := artifacts["reports"].(map[string]any)
	if !ok {
		t.Fatal("the draugr job declares no `artifacts: reports:`, so nothing reaches GitLab's own surfaces")
	}

	// GitLab's report type -> the Draugr format that fills it.
	want := map[string]string{ // #nosec G101 -- GitLab report type names, not credentials
		"sast":             "gitlab-sast",
		"secret_detection": "gitlab-secret-detection",
		"codequality":      "gitlab-codequality",
	}
	formats := map[string]bool{}
	for _, f := range report.Formats() {
		formats[f] = true
	}

	script := scriptText(t, job)
	for glType, format := range want {
		path, ok := reports[glType].(string)
		if !ok {
			t.Errorf("artifacts.reports.%s is missing", glType)
			continue
		}
		if !formats[format] {
			t.Errorf("the template relies on the %q format, which is not in the registry", format)
		}
		// The file GitLab is told to collect must be the one Draugr writes under that format.
		if filename := report.Filename(format); !strings.HasSuffix(path, filename) {
			t.Errorf("artifacts.reports.%s points at %q, but %q writes %q — GitLab would collect nothing",
				glType, path, format, filename)
		}
		if !strings.Contains(script, format) {
			t.Errorf("the template collects %s but never asks the scan to render %q", glType, format)
		}
	}
}

// The merge-base commit is fetched before it is used.
//
// GitLab clones 20 commits deep by default, so the commit a merge request diffs against is usually
// not in the checkout. Without the fetch, `git worktree add` fails on a real merge request and
// never on a small test repository — the shape of bug that reaches users because it passed here.
func TestTheGitLabTemplateFetchesTheMergeBase(t *testing.T) {
	doc := readGitLabTemplate(t)
	script := scriptText(t, doc["draugr"].(map[string]any))

	if !strings.Contains(script, "CI_MERGE_REQUEST_DIFF_BASE_SHA") {
		t.Error("the diff uses some other base; CI_MERGE_REQUEST_DIFF_BASE_SHA is the merge base")
	}
	fetch := strings.Index(script, "git fetch")
	worktree := strings.Index(script, "git worktree add")
	if fetch < 0 || worktree < 0 {
		t.Fatal("the merge-request path no longer fetches a base and adds a worktree")
	}
	if fetch > worktree {
		t.Error("the worktree is created before the commit it needs is fetched")
	}
}

// scriptText flattens a job's script into one searchable string.
func scriptText(t *testing.T, job map[string]any) string {
	t.Helper()
	var b strings.Builder
	for _, key := range []string{"before_script", "script", "after_script"} {
		lines, ok := job[key].([]any)
		if !ok {
			continue
		}
		for _, l := range lines {
			if s, ok := l.(string); ok {
				b.WriteString(s)
				b.WriteString("\n")
			}
		}
	}
	if b.Len() == 0 {
		t.Fatal("the draugr job runs nothing")
	}
	return b.String()
}
