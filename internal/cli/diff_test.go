package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/publish"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/skald"
)

// A minimal Draugr SARIF report with one result.
func sarifDoc(ruleID, level, uri, priority string) string {
	return `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Draugr","rules":[]}},"results":[
{"ruleId":"` + ruleID + `","level":"` + level + `","message":{"text":"` + ruleID + ` msg"},
"locations":[{"physicalLocation":{"artifactLocation":{"uri":"` + uri + `"}}}],
"properties":{"tool":"trivy","priority":"` + priority + `"}}]}]}`
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunDiffReportsDelta(t *testing.T) {
	base := writeFile(t, "base.sarif", sarifDoc("CVE-1", "warning", "img", "P3"))
	head := writeFile(t, "head.sarif", sarifDoc("CVE-2", "error", "img", "P1"))
	var out bytes.Buffer
	if err := runDiff(context.Background(), base, head, diffOptions{format: "console"}, &out); err != nil {
		t.Fatalf("runDiff: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "1 new") || !strings.Contains(s, "CVE-2") || !strings.Contains(s, "CVE-1") {
		t.Errorf("diff output missing expected content:\n%s", s)
	}
}

func TestRunDiffGateTrips(t *testing.T) {
	base := writeFile(t, "base.sarif", sarifDoc("CVE-1", "warning", "img", "P3"))
	head := writeFile(t, "head.sarif", sarifDoc("CVE-2", "error", "img", "P1"))
	var out bytes.Buffer
	err := runDiff(context.Background(), base, head, diffOptions{format: "console", failOnNewPriority: "P2"}, &out)
	if err == nil {
		t.Error("expected the differential gate to trip on a new P1")
	}
}

func TestRunDiffGatePasses(t *testing.T) {
	// Head only fixes a finding — no new ones, so no gate can trip.
	base := writeFile(t, "base.sarif", sarifDoc("CVE-1", "error", "img", "P1"))
	head := writeFile(t, "head.sarif", `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Draugr"}},"results":[]}]}`)
	var out bytes.Buffer
	if err := runDiff(context.Background(), base, head, diffOptions{failOnNew: "error", failOnNewPriority: "P1"}, &out); err != nil {
		t.Errorf("gate should pass when there are no new findings: %v", err)
	}
	if !strings.Contains(out.String(), "1 fixed") {
		t.Errorf("expected a fixed finding, got:\n%s", out.String())
	}
}

func TestRunDiffMissingFile(t *testing.T) {
	head := writeFile(t, "head.sarif", sarifDoc("CVE-2", "error", "img", "P1"))
	err := runDiff(context.Background(), filepath.Join(t.TempDir(), "nope.sarif"), head, diffOptions{}, &bytes.Buffer{})
	if err == nil {
		t.Error("expected an error for a missing base report")
	}
}

func TestRunDiffPublishNoopOutsideCI(t *testing.T) {
	// --publish outside a PR context no-ops (the publisher skips), so the command still succeeds.
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITHUB_REF", "")
	base := writeFile(t, "base.sarif", sarifDoc("CVE-1", "warning", "img", "P3"))
	head := writeFile(t, "head.sarif", sarifDoc("CVE-2", "error", "img", "P1"))
	if err := runDiff(context.Background(), base, head, diffOptions{format: "console", publish: true}, &bytes.Buffer{}); err != nil {
		t.Fatalf("--publish should no-op outside CI, got %v", err)
	}
}

func TestRunDiffBadFormat(t *testing.T) {
	base := writeFile(t, "base.sarif", sarifDoc("CVE-1", "warning", "img", "P3"))
	head := writeFile(t, "head.sarif", sarifDoc("CVE-2", "error", "img", "P1"))
	if err := runDiff(context.Background(), base, head, diffOptions{format: "bogus"}, &bytes.Buffer{}); err == nil {
		t.Error("expected an error for an unknown format")
	}
}

func TestDiffPublisherFollowsTheCIItIsRunningOn(t *testing.T) {
	// Every comment publisher no-ops when it cannot see its own CI system, so naming the wrong one
	// costs nothing visible: the run stays green and no comment appears. --publish either posts or
	// says why it did not, which means the choice has to follow the agent rather than a default.
	cases := []struct{ name, tfBuild, gitlabCI, want string }{
		{"azure", "True", "", "azure-pr-comment"},
		{"gitlab", "", "true", "gitlab-mr-comment"},
		{"github and anywhere else", "", "", "github-pr-comment"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TF_BUILD", tc.tfBuild)
			t.Setenv("GITLAB_CI", tc.gitlabCI)
			if got := diffPublisherKind(); got != tc.want {
				t.Errorf("diffPublisherKind() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDiffUsesItsOwnStickyComment(t *testing.T) {
	// A pipeline can reasonably run both: the Saga's PR-comment publisher for the state of the
	// branch, and `diff --publish` for what this pull request changed. They are two questions and
	// want two comments. Sharing the default marker made whichever ran second silently overwrite
	// the first, leaving no trace that the other had ever posted.
	if publish.DiffMarker == "" {
		t.Fatal("the diff publisher has no marker, so every run would post a new comment")
	}
	if publish.DiffMarker == publish.ReportMarker {
		t.Errorf("diff and report share the marker %q, so one overwrites the other",
			publish.DiffMarker)
	}
}

func TestDiffRejectsAGateLevelItCannotRank(t *testing.T) {
	// Before #559 the diff printed SARIF levels, so "error" was the obvious thing to type. It
	// prints severity bands now, which makes "high" the obvious thing — and an unrecognized level
	// ranks 0, so every new finding is at least that. The gate would quietly become "fail on
	// anything new" while looking like it had been narrowed.
	cmd := newRootCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"diff", "a.sarif", "b.sarif", "--fail-on-new", "high"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("--fail-on-new high was accepted, and silently means something else")
	}
	if !strings.Contains(err.Error(), "severity band") {
		t.Errorf("the error should explain the two ladders: %v", err)
	}
}

// scopedSARIF writes a SARIF report carrying the given scope, and returns its path.
func scopedSARIF(t *testing.T, name string, scope engine.Scope) string {
	t.Helper()
	rep := sarif.Report{Tool: "draugr", Results: []sarif.Result{
		{RuleID: "CVE-1", Level: sarif.LevelError, Message: "x"},
	}}
	if prov, ok := skald.ScopeProvenance(scope); ok {
		rep.Provenance = append(rep.Provenance, prov)
	}
	data, err := rep.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDiffRefusesReportsOfDifferentScope(t *testing.T) {
	// Every finding in the base and absent from the head is reported as fixed. That is correct
	// when both looked at the same things, and confidently wrong when one was scoped: the diff
	// announces the unscanned components' findings as resolved, and a gate on new findings
	// passes it.
	full := scopedSARIF(t, "base.sarif", engine.Scope{})
	scoped := scopedSARIF(t, "head.sarif", engine.Scope{Components: []string{"app"}})

	err := runDiff(t.Context(), full, scoped, diffOptions{format: "console"}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("comparing a scoped head against a full base must be refused")
	}
	for _, want := range []string{"do not describe the same scan", "components=app", "reported as fixed"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error should contain %q: %v", want, err)
		}
	}
}

func TestDiffComparesReportsOfTheSameScope(t *testing.T) {
	// Two scoped runs of the same scope are comparable — that is the iteration loop the flag
	// exists for, and refusing it would make the flag useless.
	sc := engine.Scope{Components: []string{"app"}, Controls: []string{"sca"}}
	base := scopedSARIF(t, "base.sarif", sc)
	head := scopedSARIF(t, "head.sarif", sc)
	if err := runDiff(t.Context(), base, head, diffOptions{format: "console"}, &bytes.Buffer{}); err != nil {
		t.Errorf("identical scopes are comparable: %v", err)
	}
}

func TestDiffComparesTwoUnscopedReports(t *testing.T) {
	// The ordinary case, which must not have changed.
	base := scopedSARIF(t, "base.sarif", engine.Scope{})
	head := scopedSARIF(t, "head.sarif", engine.Scope{})
	if err := runDiff(t.Context(), base, head, diffOptions{format: "console"}, &bytes.Buffer{}); err != nil {
		t.Errorf("two unscoped reports are comparable: %v", err)
	}
}
