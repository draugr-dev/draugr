package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// writeReport puts a SARIF report where explain will find it, and returns its directory.
func writeReport(t *testing.T, rules map[string]sarif.Rule, results []sarif.Result) string {
	t.Helper()
	data, err := sarif.Report{Tool: "Draugr", Rules: rules, Results: results}.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "results.sarif"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestExplainPrintsTheRemediationTheScannerPublished is the whole point.
//
// A finding's identifier and one truncated line is enough to rank it and not enough to decide
// anything. The remediation is already in the report — without somewhere to read it, the reader
// is sent to whatever a search engine offers, which for a benchmark is a registration form in
// front of a PDF.
func TestExplainPrintsTheRemediationTheScannerPublished(t *testing.T) {
	dir := writeReport(t,
		map[string]sarif.Rule{"kube-bench/cis/4.3.1": {
			Name:             "kube-bench/cis/4.3.1",
			ShortDescription: "Ensure that the kube-proxy metrics service is bound to localhost (Automated)",
			FullDescription:  "Modify or remove any values which bind the metrics service to a non-localhost address.\nThe default value is 127.0.0.1:10249.",
			HelpURI:          "https://www.cisecurity.org/benchmark/kubernetes",
		}},
		[]sarif.Result{{RuleID: "kube-bench/cis/4.3.1", Location: sarif.Location{URI: "kubernetes/prod"}}},
	)

	var out bytes.Buffer
	if err := runExplain(&out, "kube-bench/cis/4.3.1", filepath.Join(dir, "results.sarif")); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{
		"Ensure that the kube-proxy metrics service", // what the check is, in full
		"127.0.0.1:10249", // what to change
		"kubernetes/prod", // where it fired
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the explanation is missing %q:\n%s", want, got)
		}
	}
}

// TestExplainAcceptsTheIdAReaderRetypes: people retype the part that identifies the check, not
// the namespace in front of it.
func TestExplainAcceptsTheIdAReaderRetypes(t *testing.T) {
	// A rule only reaches the report when something reported it, so the fixture needs findings.
	dir := writeReport(t, map[string]sarif.Rule{
		"kube-bench/cis/4.3.1": {ShortDescription: "the one"},
		"kube-bench/cis/1.1.1": {ShortDescription: "another"},
	}, []sarif.Result{
		{RuleID: "kube-bench/cis/4.3.1", Location: sarif.Location{URI: "kubernetes/prod"}},
		{RuleID: "kube-bench/cis/1.1.1", Location: sarif.Location{URI: "kubernetes/prod"}},
	})

	var out bytes.Buffer
	if err := runExplain(&out, "4.3.1", filepath.Join(dir, "results.sarif")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "the one") {
		t.Errorf("a short id should find its rule:\n%s", out.String())
	}
}

// TestExplainRefusesAnAmbiguousId: picking one would explain a rule the reader did not ask about,
// and they would have no way to tell.
func TestExplainRefusesAnAmbiguousId(t *testing.T) {
	dir := writeReport(t, map[string]sarif.Rule{
		"kube-bench/cis/4.3.1":      {ShortDescription: "a"},
		"other-benchmark/cis/4.3.1": {ShortDescription: "b"},
	}, []sarif.Result{
		{RuleID: "kube-bench/cis/4.3.1", Location: sarif.Location{URI: "kubernetes/prod"}},
		{RuleID: "other-benchmark/cis/4.3.1", Location: sarif.Location{URI: "kubernetes/prod"}},
	})

	err := runExplain(&bytes.Buffer{}, "4.3.1", filepath.Join(dir, "results.sarif"))
	if err == nil {
		t.Fatal("an ambiguous id should not silently pick one")
	}
	for _, want := range []string{"kube-bench/cis/4.3.1", "other-benchmark/cis/4.3.1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error should list what it could have meant, got: %v", err)
		}
	}
}

// TestExplainSaysWhereItLooked: a reader who has not run a scan with -o needs to know that is
// what is missing, rather than being told a file does not exist.
func TestExplainSaysWhereItLooked(t *testing.T) {
	t.Chdir(t.TempDir())
	err := runExplain(&bytes.Buffer{}, "4.3.1", "")
	if err == nil {
		t.Fatal("no report should be an error")
	}
	if !strings.Contains(err.Error(), "-o") {
		t.Errorf("the error should say how to produce one, got: %v", err)
	}
}

// TestExplainNamesAnUnknownRuleRatherThanGuessing keeps a typo from reading as "nothing to say".
func TestExplainNamesAnUnknownRuleRatherThanGuessing(t *testing.T) {
	dir := writeReport(t, map[string]sarif.Rule{"a/b/c": {ShortDescription: "x"}},
		[]sarif.Result{{RuleID: "a/b/c", Location: sarif.Location{URI: "x"}}})
	err := runExplain(&bytes.Buffer{}, "nope", filepath.Join(dir, "results.sarif"))
	if err == nil || !strings.Contains(err.Error(), "nope") {
		t.Errorf("want an error naming the rule that was not found, got: %v", err)
	}
}
