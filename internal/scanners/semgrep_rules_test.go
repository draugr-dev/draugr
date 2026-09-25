package scanners

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

// semgrepLocalSARIF is Semgrep 1.169.0's output shape for a rule loaded from rules/a.yaml and one
// from rules/nested/b.yaml, with --config rules: the id, the rule's name and its short description
// all carry the directory.
const semgrepLocalSARIF = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Semgrep OSS","rules":[
 {"id":"rules.no-eval","name":"rules.no-eval","shortDescription":{"text":"Semgrep Finding: rules.no-eval"},"defaultConfiguration":{"level":"error"}},
 {"id":"rules.nested.no-eval","name":"rules.nested.no-eval","shortDescription":{"text":"Semgrep Finding: rules.nested.no-eval"},"defaultConfiguration":{"level":"warning"}}
]}},"results":[
 {"ruleId":"rules.no-eval","message":{"text":"m"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.js"},"region":{"startLine":1}}}]},
 {"ruleId":"rules.nested.no-eval","message":{"text":"m"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"b.js"},"region":{"startLine":2}}}]}
]}]}`

func semgrepRulesTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, f := range []string{"rules/a.yaml", "rules/nested/b.yaml", "root.yaml"} {
		path := filepath.Join(dir, f)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("rules: []\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// The prefixes are the ones Semgrep 1.169.0 was measured to produce for each form of --config.
func TestSemgrepRulePrefixes(t *testing.T) {
	dir := semgrepRulesTree(t)
	abs := filepath.Join(dir, "rules", "a.yaml")
	for config, want := range map[string]string{
		"rules/a.yaml":               "rules.",
		"./rules/a.yaml":             "rules.",
		"rules":                      "rules.",
		"root.yaml":                  "",
		"./root.yaml":                "",
		abs:                          dottedPrefix(filepath.Dir(abs)),
		"p/default":                  "",
		"https://example.com/r.yaml": "",
		"":                           "",
	} {
		got := semgrepRulePrefixes(dir, config)
		if want == "" {
			if len(got) != 0 {
				t.Errorf("%q: prefixes %v, want none", config, got)
			}
			continue
		}
		if len(got) == 0 || got[0] != want {
			t.Errorf("%q: prefixes %v, want %q first", config, got, want)
		}
	}
	// Through a symlink, the target's form is offered as well.
	link := filepath.Join(t.TempDir(), "rules-link")
	if err := os.Symlink(filepath.Join(dir, "rules"), link); err != nil {
		t.Fatal(err)
	}
	target, err := filepath.EvalSymlinks(filepath.Join(dir, "rules"))
	if err != nil {
		t.Fatal(err)
	}
	if got := semgrepRulePrefixes(dir, link); len(got) != 2 || got[1] != dottedPrefix(target) {
		t.Errorf("through a symlink: prefixes %v", got)
	}
	if got := dottedPrefix("../abs"); got != "abs." {
		t.Errorf("dottedPrefix(../abs) = %q; Semgrep leaves out ..", got)
	}
}

func TestParseSemgrepReportsDeclaredRuleIDs(t *testing.T) {
	dir := semgrepRulesTree(t)
	report, err := parseSemgrep([]byte(semgrepLocalSARIF), dir, plugin.Config{"config": "rules"})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, r := range report.Results {
		ids = append(ids, r.RuleID)
	}
	// The configured directory is gone; the subdirectory inside it stays, so the two rules that
	// declare one id remain two rules.
	if !slices.Equal(ids, []string{"no-eval", "nested.no-eval"}) {
		t.Errorf("result ids = %v", ids)
	}
	rule, ok := report.Rules["no-eval"]
	if !ok || rule.Name != "no-eval" || rule.ShortDescription != "Semgrep Finding: no-eval" {
		t.Errorf("rule metadata = %+v (found %v)", rule, ok)
	}
	if _, ok := report.Rules["rules.no-eval"]; ok {
		t.Error("the prefixed rule is still listed")
	}
	// The level still comes from the rule, which is resolved by id.
	if report.Results[0].Level != "error" || report.Results[1].Level != "warning" {
		t.Errorf("levels = %s, %s", report.Results[0].Level, report.Results[1].Level)
	}
}

func TestParseSemgrepLeavesRegistryIDsAlone(t *testing.T) {
	report, err := parseSemgrep([]byte(semgrepLocalSARIF), t.TempDir(), plugin.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Results[0].RuleID != "rules.no-eval" {
		t.Errorf("an id from the default pack was rewritten: %s", report.Results[0].RuleID)
	}
	if _, err := parseSemgrep([]byte("{"), t.TempDir(), plugin.Config{}); err == nil {
		t.Error("unreadable SARIF was accepted")
	}
}
