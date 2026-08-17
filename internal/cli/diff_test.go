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

func TestDiffRejectsAThresholdItCannotRank(t *testing.T) {
	// An unrecognized threshold ranks 0, and every new finding is at least that — so accepting
	// one would quietly turn the gate into "fail on anything new" while reading like a
	// narrowing. It has to be refused rather than defaulted.
	cmd := newRootCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"diff", "a.sarif", "b.sarif", "--fail-on-new", "urgent"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("--fail-on-new urgent was accepted, and silently means something else")
	}
	if !strings.Contains(err.Error(), "critical") {
		t.Errorf("the error should name the bands: %v", err)
	}
}

// TestDiffTakesTheBandTheReportPrints: the diff lists findings by severity band, so the gate
// beside it takes the same word. Typing what you can see used to be the one thing that failed.
func TestDiffTakesTheBandTheReportPrints(t *testing.T) {
	cmd := newRootCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"diff", "a.sarif", "b.sarif", "--fail-on-new", "high"})
	err := cmd.Execute()
	// It gets past the flag and fails on the missing report, which is the next thing to go wrong.
	if err != nil && strings.Contains(err.Error(), "--fail-on-new") {
		t.Errorf("a severity band should be accepted: %v", err)
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

// A publisher that cannot deliver must not replace the verdict it was delivering.
//
// The gate is what the run is for. Returning the publish failure instead sends a reader to fix a
// credential while the P1 the change introduced goes unmentioned — and on a merge request that is
// the difference between "your CI is misconfigured" and "this should not merge". `scan` already
// reconciles the two this way.
func TestDiffPublishFailureDoesNotHideTheGate(t *testing.T) {
	// In GitLab CI with a merge request in context and no token, the publisher errors rather than
	// no-opping: --publish was asked for and cannot be honored.
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("TF_BUILD", "")
	t.Setenv("CI_PROJECT_ID", "1234")
	t.Setenv("CI_MERGE_REQUEST_IID", "7")
	t.Setenv("GITLAB_TOKEN", "")

	base := writeFile(t, "base.sarif", `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Draugr"}},"results":[]}]}`)
	head := writeFile(t, "head.sarif", sarifDoc("CVE-2", "error", "img", "P1"))

	err := runDiff(context.Background(), base, head,
		diffOptions{format: "console", publish: true, failOnNewPriority: "P1"}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("a new P1 with a broken publisher reported success")
	}
	if !strings.Contains(err.Error(), "differential gate") {
		t.Errorf("the verdict is the outcome and has to be in the error: %v", err)
	}
	if !strings.Contains(err.Error(), "publishing also failed") {
		t.Errorf("the delivery problem still has to be reported: %v", err)
	}
}

func TestDiffPublishFailureStillFailsAPassingGate(t *testing.T) {
	// Nothing new, so the gate passes — but --publish did nothing, and a flag that silently does
	// nothing is the thing this codebase refuses to ship.
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("TF_BUILD", "")
	t.Setenv("CI_PROJECT_ID", "1234")
	t.Setenv("CI_MERGE_REQUEST_IID", "7")
	t.Setenv("GITLAB_TOKEN", "")

	clean := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Draugr"}},"results":[]}]}`
	base := writeFile(t, "base.sarif", clean)
	head := writeFile(t, "head.sarif", clean)

	err := runDiff(context.Background(), base, head,
		diffOptions{format: "console", publish: true}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("--publish could not post and the run reported success")
	}
	if strings.Contains(err.Error(), "differential gate") {
		t.Errorf("no finding tripped the gate, so it should not be named: %v", err)
	}
	// A red check for a forge outage and a red check for a finding this change introduced look
	// identical in a checks list. The message is the only thing that separates them, so it says
	// the gate passed before it says what went wrong.
	if !strings.Contains(err.Error(), "the gate passed") {
		t.Errorf("the error has to say the gate passed, or it reads as a failing scan: %v", err)
	}
	if !strings.Contains(err.Error(), "publishing failed") {
		t.Errorf("the delivery problem is what went wrong and has to be named: %v", err)
	}
}
