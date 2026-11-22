package engine

import (
	"fmt"
	"slices"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// kicsPrivileged is the KICS query that tests what Trivy's KSV-0017 tests.
const kicsPrivileged = "dd29336b-fe57-445b-a26e-e6aa867ae609"

// setting is one tool's finding of one rule in a manifest, from line start to end.
func setting(tool, rule, repo string, start, end int) sarif.Result {
	return sarif.Result{
		Tool: tool, RuleID: rule, Level: sarif.LevelError, Component: "platform", Repository: repo,
		Location: sarif.Location{URI: "k8s/web.yaml", StartLine: start, EndLine: end},
	}
}

// sameCheckRules gives KICS's privileged query the statement that it tests Trivy's check.
func sameCheckRules() map[string]sarif.Rule {
	return map[string]sarif.Rule{
		kicsPrivileged: {Taxa: []sarif.Taxon{sarif.SameCheckAs("Trivy", "KSV-0017", "Privileged")}},
	}
}

func iacControl(rules map[string]sarif.Rule, results ...sarif.Result) map[string]plugin.ControlResult {
	rep := sarif.Report{Tool: "iac", Results: results, Rules: rules}
	return map[string]plugin.ControlResult{"iac": {Control: "iac", Report: rep}}
}

func TestCorrelationCountsOneSettingTwoToolsFlagOnce(t *testing.T) {
	t.Parallel()
	ctrls := iacControl(sameCheckRules(),
		setting("Trivy", "KSV-0017", "api", 17, 22),
		setting("KICS", kicsPrivileged, "api", 22, 0),
	)
	if groups, _ := applyCorrelation(ctrls); groups != 1 {
		t.Fatalf("groups = %d, want 1", groups)
	}
	results := ctrls["iac"].Report.Results
	if n := ctrls["iac"].Report.Counts().Total(); n != 1 || len(results) != 2 {
		t.Fatalf("counted %d of %d, want 1 of both kept", n, len(results))
	}
	if !results[0].Correlated() || results[0].Correlation.CountedUnder != "KICS" {
		t.Errorf("Trivy's copy = %+v, want counted under KICS's, the tie going to the tool name", results[0].Correlation)
	}
	if also := results[1].Correlation.AlsoFoundBy; len(also) != 1 || also[0].RuleID != "KSV-0017" {
		t.Errorf("KICS's copy names %+v, want Trivy's KSV-0017", also)
	}
}

// sameCheckPairs runs sameCheckGroups and names each pair by its members' indexes.
func sameCheckPairs(rules map[string]sarif.Rule, results ...sarif.Result) string {
	return fmt.Sprint(sameCheckGroups(results, rules))
}

func TestSameCheckGroupsPairOnlyOneCopyOnOneResource(t *testing.T) {
	t.Parallel()
	rules := sameCheckRules()
	imported := setting("Trivy", "KSV-0017", "api", 17, 22)
	imported.Scanner = plugin.ImportScanner
	inModule := setting("Trivy", "KSV-0017", "api", 17, 22)
	inModule.Module = &sarif.Module{Source: "x"}
	otherComponent := setting("Trivy", "KSV-0017", "api", 17, 22)
	otherComponent.Component = "billing"

	for _, c := range []struct {
		name    string
		results []sarif.Result
		want    string
	}{
		{"two containers, each region holding one KICS line",
			[]sarif.Result{
				setting("Trivy", "KSV-0017", "api", 17, 22), setting("Trivy", "KSV-0017", "api", 23, 30),
				setting("KICS", kicsPrivileged, "api", 28, 0), setting("KICS", kicsPrivileged, "api", 21, 0),
			}, "[[0 3] [1 2]]"},
		{"a KICS line outside every region", []sarif.Result{
			setting("Trivy", "KSV-0017", "api", 17, 22), setting("KICS", kicsPrivileged, "api", 30, 0),
		}, "[]"},
		{"a region with no end is one line", []sarif.Result{
			setting("Trivy", "KSV-0017", "api", 10, 0), setting("KICS", kicsPrivileged, "api", 10, 0),
		}, "[[0 1]]"},
		{"a copy with no line covers nothing", []sarif.Result{
			setting("Trivy", "KSV-0017", "api", 0, 0), setting("KICS", kicsPrivileged, "api", 1, 0),
		}, "[]"},
		{"Trivy wrote the id another way", []sarif.Result{
			setting("Trivy", "KSV017", "api", 17, 22), setting("KICS", kicsPrivileged, "api", 18, 0),
		}, "[[0 1]]"},
		{"two KICS copies in one region pair with neither", []sarif.Result{
			setting("Trivy", "KSV-0017", "api", 17, 22),
			setting("KICS", kicsPrivileged, "api", 18, 0), setting("KICS", kicsPrivileged, "api", 20, 0),
		}, "[]"},
		{"overlapping regions leave the KICS copy unpaired", []sarif.Result{
			setting("Trivy", "KSV-0017", "api", 10, 22), setting("Trivy", "KSV-0017", "api", 17, 22),
			setting("KICS", kicsPrivileged, "api", 18, 0),
		}, "[]"},
		{"two repositories, each pair in its own", []sarif.Result{
			setting("Trivy", "KSV-0017", "api", 17, 22), setting("Trivy", "KSV-0017", "web", 17, 22),
			setting("KICS", kicsPrivileged, "web", 22, 0), setting("KICS", kicsPrivileged, "api", 22, 0),
		}, "[[0 3] [1 2]]"},
		{"another component", []sarif.Result{otherComponent, setting("KICS", kicsPrivileged, "api", 22, 0)}, "[]"},
		{"another rule", []sarif.Result{
			setting("Trivy", "KSV-0001", "api", 17, 22), setting("KICS", kicsPrivileged, "api", 22, 0),
		}, "[]"},
		{"an imported copy", []sarif.Result{imported, setting("KICS", kicsPrivileged, "api", 22, 0)}, "[]"},
		{"a copy inside a downloaded module", []sarif.Result{inModule, setting("KICS", kicsPrivileged, "api", 22, 0)}, "[]"},
		{"nothing states a pair", []sarif.Result{
			setting("Trivy", "KSV-0017", "api", 17, 22), setting("Trivy", "KSV-0017", "api", 17, 22),
		}, "[]"},
	} {
		if got := sameCheckPairs(rules, c.results...); got != c.want {
			t.Errorf("%s: pairs %s, want %s", c.name, got, c.want)
		}
	}

	// A benchmark check is checkGroups' to join, so a copy of one is left out here.
	rules["KSV-0017"] = cisRule("5.2.1", "cis-1.12")
	if got := sameCheckPairs(rules, setting("Trivy", "KSV-0017", "api", 17, 22),
		setting("KICS", kicsPrivileged, "api", 22, 0)); got != "[]" {
		t.Errorf("a benchmark check's copy: pairs %s, want none", got)
	}
}

func TestSameCheckGroupsIgnoreAStatementAboutTheToolsOwnRules(t *testing.T) {
	t.Parallel()
	rules := map[string]sarif.Rule{
		// KICS naming one of its own rules says nothing about another tool.
		kicsPrivileged: {Taxa: []sarif.Taxon{sarif.SameCheckAs("KICS", "other", "")}},
		// Both rules stating the pair is one pair, not two claims.
		"KSV-0017": {Taxa: []sarif.Taxon{sarif.SameCheckAs("KICS", kicsPrivileged, "")}},
	}
	got := sameCheckPairs(rules,
		setting("KICS", "other", "api", 22, 0), setting("KICS", kicsPrivileged, "api", 22, 0),
		setting("Trivy", "KSV-0017", "api", 17, 22))
	if got != "[]" {
		t.Errorf("pairs %s: Trivy's statement points KSV-0017's region at no KICS region", got)
	}
	rules[kicsPrivileged] = sameCheckRules()[kicsPrivileged]
	rules["KSV-0017"] = sarif.Rule{Taxa: []sarif.Taxon{sarif.SameCheckAs("KICS", kicsPrivileged, "")}}
	got = sameCheckPairs(rules,
		setting("Trivy", "KSV-0017", "api", 22, 22), setting("KICS", kicsPrivileged, "api", 22, 22))
	if got != "[[0 1]]" {
		t.Errorf("pairs %s, want the pair both sides state counted once", got)
	}
	if got := sameCheckGroups(nil, nil); got != nil {
		t.Errorf("no findings: %v", got)
	}
	if groups := flawGroups(sarif.Report{Results: []sarif.Result{
		setting("Trivy", "KSV-0017", "api", 17, 22), setting("KICS", kicsPrivileged, "api", 22, 0),
	}, Rules: sameCheckRules()}); len(groups) != 1 || !slices.Equal(groups[0], []int{0, 1}) {
		t.Error("flawGroups leaves out the pair sameCheckGroups makes")
	}
}

func TestSameCheckRuleID(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"KSV-0017":     "KSV17",
		"KSV017":       "KSV17",
		"AVD-KSV-0017": "KSV17",
		"ksv-0017":     "KSV17",
		"AWS-0107":     "AWS107",
		"DS-0000":      "DS0",
		"no-number":    "NONUMBER",
	} {
		if got := sameCheckRuleID(in); got != want {
			t.Errorf("sameCheckRuleID(%q) = %q, want %q", in, got, want)
		}
	}
}
