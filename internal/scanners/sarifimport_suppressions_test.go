package scanners

import (
	"context"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// suppressedLog is a file from a tool that set two of its three findings aside: one by a comment in
// the code with no status and no reason, as Semgrep writes a nosemgrep, and one in its own settings,
// accepted with a reason. The third carries a suppression the team rejected.
func suppressedLog() string {
	return `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"bandit","rules":[{"id":"B105"},{"id":"B303"},{"id":"B608"}]}},
"results":[
{"ruleId":"B105","level":"error","message":{"text":"hardcoded password"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"app/config.py"}}}],
 "suppressions":[{"kind":"inSource"}]},
{"ruleId":"B303","level":"error","message":{"text":"weak hash"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"app/cache.py"}}}],
 "suppressions":[{"kind":"external","status":"accepted","justification":"cache keys, not passwords"}]},
{"ruleId":"B608","level":"error","message":{"text":"SQL built from strings"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"app/db.py"}}}],
 "suppressions":[{"kind":"external","status":"rejected","justification":"a query from user input"}]}
]}]}`
}

// resultsByRule indexes a report's results by rule.
func resultsByRule(rep sarif.Report) map[string]sarif.Result {
	out := map[string]sarif.Result{}
	for _, r := range rep.Results {
		out[r.RuleID] = r
	}
	return out
}

// Honored, the default, the tool's suppressions set aside the two findings whose suppression stands,
// each keeping how the tool recorded it, its reason or none, and the file it was read from. The one
// the team rejected counts, as it always did. In a component of two repositories, too: the
// suppression is the finding's own and does not depend on which repository it was placed in.
func TestAnImportHonorsTheToolsSuppressionsByDefault(t *testing.T) {
	path := writeFile(t, suppressedLog())
	ft := plugin.FileTarget{Path: path, Component: "app", Repositories: []plugin.RepositoryTarget{
		{URL: t.TempDir()}, {URL: t.TempDir()},
	}}
	rep, err := NewSARIFImport().Scan(context.Background(), ft, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := resultsByRule(rep)
	if s := got["B105"].Suppression; s == nil || s.Origin != sarif.OriginTool || s.Kind != "inSource" ||
		s.Justification != "" || s.Source != path {
		t.Errorf("B105 suppression = %+v, want the tool's, in the code, with no reason, from %s", s, path)
	}
	if s := got["B303"].Suppression; s == nil || s.Origin != sarif.OriginScanner ||
		s.Justification != "cache keys, not passwords" || s.Source != path {
		t.Errorf("B303 suppression = %+v, want the tool's settings with its reason, from %s", s, path)
	}
	if r := got["B608"]; r.Suppression != nil || !strings.Contains(r.Detail, "the file's suppression is rejected") {
		t.Errorf("B608 = %+v, want it counted with the rejected suppression in its detail", r)
	}
	if c := rep.Counts(); c.Error != 1 {
		t.Errorf("counted %+v, want the rejected one alone", c)
	}
}

// Counted, every finding counts and the gate judges all three. Each one the tool suppressed says so in
// its detail, which tool, where and why, so nothing the file recorded is lost.
func TestAnImportCountsTheToolsSuppressionsWhenAsked(t *testing.T) {
	ft := plugin.FileTarget{Path: writeFile(t, suppressedLog()), Component: "app", CountSuppressed: true,
		Repositories: []plugin.RepositoryTarget{{URL: t.TempDir()}, {URL: t.TempDir()}}}
	rep, err := NewSARIFImport().Scan(context.Background(), ft, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c := rep.Counts(); c.Error != 3 {
		t.Errorf("counted %+v, want all three", c)
	}
	got := resultsByRule(rep)
	for rule, want := range map[string]string{
		"B105": "bandit suppressed it in a comment in the code · no reason given · counted, as the import says suppressions: count",
		"B303": "bandit suppressed it in the tool's own settings · reason: cache keys, not passwords · counted, as the import says suppressions: count",
		"B608": "the file's suppression is rejected",
	} {
		r := got[rule]
		if r.Suppression != nil || !strings.HasSuffix(r.Detail, want) || strings.HasPrefix(r.Detail, " · ") {
			t.Errorf("%s: suppression %+v, detail %q, want it counted with %q", rule, r.Suppression, r.Detail, want)
		}
	}
}

// Whether the tool's suppressions are counted is part of what an import's result is cached on, so a
// descriptor that changes the setting reads the file again rather than reusing the other answer.
func TestCountingSuppressionsIsPartOfTheCacheKey(t *testing.T) {
	honor := plugin.FileTarget{Path: "a.sarif", Digest: "d"}
	count := honor
	count.CountSuppressed = true
	if honor.CacheDetail() == count.CacheDetail() {
		t.Errorf("both read %q", honor.CacheDetail())
	}
}

// A suppression a tool's own JSON already traced to a file, such as a .trivyignore line, keeps that
// file as its source when honored, since it says more than the import's file does.
func TestAnHonoredSuppressionKeepsTheFileTheToolNamed(t *testing.T) {
	results := []sarif.Result{
		{RuleID: "CVE-1", Suppression: &sarif.Suppression{Kind: "external", Origin: sarif.OriginScanner, Source: ".trivyignore"}},
		{RuleID: "CVE-2", Suppression: &sarif.Suppression{Kind: "external", Origin: sarif.OriginScanner}},
	}
	toolsSuppressions(results, plugin.FileTarget{Path: "trivy.json"})
	if got := results[0].Suppression.Source; got != ".trivyignore" {
		t.Errorf("CVE-1 source = %q, want the ignore file Trivy named", got)
	}
	if got := results[1].Suppression.Source; got != "trivy.json" {
		t.Errorf("CVE-2 source = %q, want the imported file", got)
	}
}

// A tool that names itself nowhere is still named in a counted finding's detail, as the tool.
func TestACountedSuppressionFromAnUnnamedTool(t *testing.T) {
	doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{}},"results":[{"ruleId":"R","message":{"text":"m"},
"suppressions":[{"kind":"inSource","justification":"  "}]}]}]}`
	rep, err := NewSARIFImport().Scan(context.Background(), plugin.FileTarget{Path: writeFile(t, doc), CountSuppressed: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if d := rep.Results[0].Detail; d != "the tool suppressed it in a comment in the code · no reason given · counted, as the import says suppressions: count" {
		t.Errorf("detail = %q", d)
	}
}
