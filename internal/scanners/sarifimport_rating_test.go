package scanners

import (
	"context"
	"fmt"
	"maps"
	"os"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// rated is one row of a table test: what a rater made of a result, or nil where it rated nothing.
type rated struct {
	severity sarif.Severity
	detail   string
}

// checkRating compares a rating with the row a table test expects.
func checkRating(t *testing.T, name string, got *sarif.Rating, want *rated) {
	t.Helper()
	switch {
	case want == nil && got != nil:
		t.Errorf("%s: rated %+v, want no rating", name, got)
	case want != nil && got == nil:
		t.Errorf("%s: no rating, want %s %q", name, want.severity, want.detail)
	case want != nil && (got.Severity != want.severity || got.Detail != want.detail):
		t.Errorf("%s: rating %s %q, want %s %q", name, got.Severity, got.Detail, want.severity, want.detail)
	}
}

// Every row of gosec's table, as the tag is written on the rule. A rule with no rating tag rates
// nothing and keeps its level.
func TestGosecRatingTable(t *testing.T) {
	for _, c := range []struct {
		tags []any
		want *rated
	}{
		{[]any{"security", "HIGH"}, &rated{sarif.SeverityHigh, "severity tag high"}},
		{[]any{"security", "MEDIUM"}, &rated{sarif.SeverityMedium, "severity tag medium"}},
		{[]any{"security", "LOW"}, &rated{sarif.SeverityLow, "severity tag low"}},
		{[]any{"security"}, nil},
		{[]any{"security", "CRITICAL"}, nil},
	} {
		r := gosecRating(ratedResult{rule: map[string]any{"tags": c.tags}})
		checkRating(t, fmt.Sprint(c.tags), r, c.want)
	}
}

// Every row of CodeQL's table, from the rule's problem.severity.
func TestCodeQLRatingTable(t *testing.T) {
	for word, want := range map[string]*rated{
		"error":          {sarif.SeverityHigh, "problem.severity error"},
		"warning":        {sarif.SeverityMedium, "problem.severity warning"},
		"recommendation": {sarif.SeverityLow, "problem.severity recommendation"},
		"note":           nil,
	} {
		checkRating(t, word, codeqlRating(ratedResult{rule: map[string]any{"problem.severity": word}}), want)
	}
	checkRating(t, "no problem.severity", codeqlRating(ratedResult{rule: map[string]any{"precision": "high"}}), nil)
}

// dependency-check's rating is read from the first source it writes, CVSS v3 before v2 before its
// own word before the rule's summary, and a v2 score is banded as every score is.
func TestDependencyCheckRatingTable(t *testing.T) {
	for _, c := range []struct {
		name    string
		result  map[string]any
		rule    map[string]any
		summary string
		want    *rated
	}{
		{"v3 critical", map[string]any{"cvssv3_baseSeverity": "CRITICAL", "cvssv3_baseScore": 9.8}, nil, "",
			&rated{sarif.SeverityCritical, "cvssv3_baseSeverity critical"}},
		{"v3 high", map[string]any{"cvssv3_baseSeverity": "HIGH"}, nil, "", &rated{sarif.SeverityHigh, "cvssv3_baseSeverity high"}},
		{"v3 medium", map[string]any{"cvssv3_baseSeverity": "MEDIUM"}, nil, "", &rated{sarif.SeverityMedium, "cvssv3_baseSeverity medium"}},
		{"v3 low", map[string]any{"cvssv3_baseSeverity": "LOW"}, nil, "", &rated{sarif.SeverityLow, "cvssv3_baseSeverity low"}},
		{"v3 before v2", map[string]any{"cvssv3_baseSeverity": "MEDIUM", "cvssv2_score": 9.3}, nil, "",
			&rated{sarif.SeverityMedium, "cvssv3_baseSeverity medium"}},
		{"v2 score on the rule", nil, map[string]any{"cvssv2_score": 9.3, "cvssv2_severity": "HIGH"}, "",
			&rated{sarif.SeverityCritical, "cvssv2_score 9.3"}},
		{"v2 score high", nil, map[string]any{"cvssv2_score": 7.5, "cvssv2_severity": "HIGH"}, "",
			&rated{sarif.SeverityHigh, "cvssv2_score 7.5"}},
		{"v2 score as text", nil, map[string]any{"cvssv2_score": "4.3"}, "", &rated{sarif.SeverityMedium, "cvssv2_score 4.3"}},
		{"v2 word alone", nil, map[string]any{"cvssv2_severity": "LOW"}, "", &rated{sarif.SeverityLow, "cvssv2_severity low"}},
		{"unscored critical", map[string]any{"severity": "critical", "unscored": "true"}, nil, "",
			&rated{sarif.SeverityCritical, "severity critical"}},
		{"unscored moderate", map[string]any{"severity": "moderate"}, nil, "", &rated{sarif.SeverityMedium, "severity moderate"}},
		{"unscored info", map[string]any{"severity": "info"}, nil, "", &rated{sarif.SeverityLow, "severity info"}},
		{"unscored informational", map[string]any{"severity": "informational"}, nil, "", &rated{sarif.SeverityLow, "severity informational"}},
		{"summary", nil, nil, "critical severity - CVE-2021-44228 CWE-502 vulnerability in log4j-core",
			&rated{sarif.SeverityCritical, "critical severity"}},
		{"summary unknown", nil, nil, "unknown severity - CVE-2020-0001 vulnerability in x", nil},
		{"nothing", map[string]any{"source": "NVD"}, nil, "CVE-2020-0001", nil},
	} {
		r := dependencyCheckRating(ratedResult{result: c.result, rule: c.rule, summary: c.summary})
		checkRating(t, c.name, r, c.want)
	}
	r := dependencyCheckRating(ratedResult{rule: map[string]any{"cvssv2_score": 9.3, "cvssv2_severity": "HIGH"}})
	if want := map[string]string{"cvssv2_score": "9.3", "cvssv2_severity": "HIGH"}; !maps.Equal(r.Fields, want) {
		t.Errorf("fields = %v, want dependency-check's own", r.Fields)
	}
}

// Every rating Snyk writes at the head of a rule's summary.
func TestSnykRatingTable(t *testing.T) {
	for summary, want := range map[string]*rated{
		"Critical severity - Remote Code Execution vulnerability in log4j": {sarif.SeverityCritical, "Critical severity"},
		"High severity - Prototype Pollution vulnerability in lodash":      {sarif.SeverityHigh, "High severity"},
		"Medium severity - Regular Expression Denial of Service (ReDoS)":   {sarif.SeverityMedium, "Medium severity"},
		"Low severity - Denial of Service (DoS) vulnerability in bzip2":    {sarif.SeverityLow, "Low severity"},
		"Severe severity - not one of Snyk's four":                         nil,
		"": nil,
	} {
		checkRating(t, summary, snykRating(ratedResult{summary: summary}), want)
	}
}

// Fortify's four priorities, each quadrant of impact and likelihood, with the boundary itself counted
// high as Fortify counts it, and a result missing a value keeping its level.
func TestFortifyRatingTable(t *testing.T) {
	rule := func(impact, accuracy, probability any) map[string]any {
		return map[string]any{"Impact": impact, "Accuracy": accuracy, "Probability": probability}
	}
	for _, c := range []struct {
		name       string
		rule       map[string]any
		confidence any
		want       *rated
	}{
		{"critical", rule("3.0", "4.0", "4.0"), "5.0", &rated{sarif.SeverityCritical, "Impact 3.0 · likelihood 3.2"}},
		{"high", rule("3.0", "4.0", "1.0"), "5.0", &rated{sarif.SeverityHigh, "Impact 3.0 · likelihood 0.8"}},
		{"medium", rule("2.0", "5.0", "3.0"), "5.0", &rated{sarif.SeverityMedium, "Impact 2.0 · likelihood 3"}},
		{"low", rule("1.0", "5.0", "1.0"), "5.0", &rated{sarif.SeverityLow, "Impact 1.0 · likelihood 1"}},
		{"on both boundaries", rule("2.5", "5.0", "2.5"), "5.0", &rated{sarif.SeverityCritical, "Impact 2.5 · likelihood 2.5"}},
		{"just below both", rule("2.4", "5.0", "2.4"), "5.0", &rated{sarif.SeverityLow, "Impact 2.4 · likelihood 2.4"}},
		{"numbers", rule(3.0, 4.0, 4.0), 5.0, &rated{sarif.SeverityCritical, "Impact 3 · likelihood 3.2"}},
		{"no confidence", rule("3.0", "4.0", "4.0"), nil, nil},
		{"no impact", map[string]any{"Accuracy": "4.0", "Probability": "4.0"}, "5.0", nil},
		{"a word for a number", rule("high", "4.0", "4.0"), "5.0", nil},
	} {
		res := map[string]any{"InstanceSeverity": "3.0"}
		if c.confidence != nil {
			res["Confidence"] = c.confidence
		}
		checkRating(t, c.name, fortifyRating(ratedResult{result: res, rule: c.rule}), c.want)
	}
}

// The descriptor's mapping matches regardless of case and space, reads a number however it is
// written, takes the highest of a list, and rates nothing for a value it does not name.
func TestDescriptorRatingTable(t *testing.T) {
	m := saga.ImportSeverity{Property: "acme-severity", Values: map[string]string{
		"Blocker": "critical", "Major": "high", "Minor": "medium", "3": "low",
	}}
	rate := descriptorRater(m).rate
	for _, c := range []struct {
		name  string
		value any
		want  *rated
	}{
		{"exact", "Blocker", &rated{sarif.SeverityCritical, "acme-severity Blocker"}},
		{"another case", " major ", &rated{sarif.SeverityHigh, "acme-severity  major "}},
		{"a number", 3.0, &rated{sarif.SeverityLow, "acme-severity 3"}},
		{"a number as text", "3.0", &rated{sarif.SeverityLow, "acme-severity 3.0"}},
		{"the highest of a list", []any{"Minor", "Major", "unrelated"}, &rated{sarif.SeverityHigh, "acme-severity Major"}},
		{"a value it does not name", "Trivial", nil},
		{"no value", nil, nil},
	} {
		checkRating(t, c.name, rate(ratedResult{result: map[string]any{"acme-severity": c.value}}), c.want)
	}
	if r := rate(ratedResult{rule: map[string]any{"acme-severity": "Minor"}}); r == nil || r.Severity != sarif.SeverityMedium {
		t.Errorf("a value on the rule was not read: %+v", r)
	}
}

// imported is one result as the import reads it.
type imported struct {
	rule     string
	severity sarif.Severity
	detail   string
}

// importAll reads a file through the import and returns each result's rule, severity and rating
// detail, and the provenance's severity field.
func importAll(t *testing.T, ft plugin.FileTarget) ([]imported, string) {
	t.Helper()
	rep, err := NewSARIFImport().Scan(context.Background(), ft, nil)
	if err != nil {
		t.Fatal(err)
	}
	var got []imported
	for _, res := range rep.Results {
		i := imported{rule: res.RuleID, severity: res.Severity("")}
		if res.Rating != nil {
			i.detail = res.Rating.Detail
		}
		got = append(got, i)
	}
	return got, field(t, rep, "severity")
}

// Recorded with gosec 2.30.0, `gosec -fmt sarif -out gosec-ratings.sarif ./...`, in a container
// over a fixture with one HIGH, two MEDIUM and one LOW rule. gosec writes level error for HIGH and
// MEDIUM and warning for LOW, so its own rating moves the MEDIUM and LOW findings one band down from
// where the level put them, to where gosec rates them.
func TestSARIFImportRatesRecordedGosec(t *testing.T) {
	got, source := importAll(t, plugin.FileTarget{Path: "testdata/sarif-import/gosec-ratings.sarif"})
	want := []imported{
		{"G402", sarif.SeverityHigh, "severity tag high"},
		{"G401", sarif.SeverityMedium, "severity tag medium"},
		{"G501", sarif.SeverityMedium, "severity tag medium"},
		{"G104", sarif.SeverityLow, "severity tag low"},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("results:\n got %v\nwant %v", got, want)
	}
	if source != "gosec's severity tag" {
		t.Errorf("severity source = %q", source)
	}
}

// An imported gosec file rates each finding as Draugr's own gosec scanner rates the same file, so a
// MEDIUM rule is medium both ways, not high as its level error would say.
func TestSARIFImportRatesGosecAsTheGosecScannerDoes(t *testing.T) {
	for _, file := range []string{"testdata/sarif-import/gosec.sarif", "testdata/sarif-import/gosec-ratings.sarif"} {
		data, err := os.ReadFile(file) // #nosec G304 -- a fixture under testdata
		if err != nil {
			t.Fatal(err)
		}
		native, _, err := sarif.FromForeignSARIF(data, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := rateByGosecSeverity(&native, data); err != nil {
			t.Fatal(err)
		}
		got, _ := importAll(t, plugin.FileTarget{Path: file})
		for i, res := range native.Results {
			if got[i].severity != res.Severity("") {
				t.Errorf("%s %s: imported %s, the gosec scanner %s", file, res.RuleID, got[i].severity, res.Severity(""))
			}
		}
	}
	got, _ := importAll(t, plugin.FileTarget{Path: "testdata/sarif-import/gosec.sarif"})
	for _, g := range got {
		if g.severity != sarif.SeverityMedium {
			t.Errorf("%s: imported gosec MEDIUM rated %s, want medium", g.rule, g.severity)
		}
	}
}

// Recorded by OWASP dependency-check 6.1.2 and kept in DefectDojo's tests (see NOTICE). Version 6
// writes its properties on the result and no rules: CVSS v3's word for the advisories NVD scored,
// and its own word for the four RetireJS reported unscored. Every result is level error, which read
// alone ranked all thirteen high.
func TestSARIFImportRatesRecordedDependencyCheck(t *testing.T) {
	got, source := importAll(t, plugin.FileTarget{Path: "testdata/sarif-import/dependency-check-6.1.2.sarif"})
	if len(got) != 13 {
		t.Fatalf("results = %d, want 13", len(got))
	}
	counts := map[string]int{}
	for _, g := range got {
		counts[string(g.severity)+" "+g.detail]++
	}
	want := map[string]int{
		"low severity low":                  1,
		"medium severity medium":            3,
		"medium cvssv3_baseSeverity medium": 9,
	}
	if !maps.Equal(counts, want) {
		t.Errorf("ratings = %v, want %v", counts, want)
	}
	if source != "dependency-check's severity" {
		t.Errorf("severity source = %q", source)
	}
}

// ruleLog is a one-run log from tool, with rules and results written out, for the tools whose files
// cannot be recorded here or committed: written to the shape of files those tools wrote, which the
// test beside each names.
func ruleLog(tool, rules, results string) string {
	return `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"` + tool + `","rules":[` + rules + `]}},"results":[` +
		results + `]}]}`
}

// Written to the shape of CodeQL 2.27.3's SARIF: the rating on the rule, results with no level of
// their own. A security query's security-severity still decides; a quality query is rated from its
// problem.severity; a rule stating neither keeps the level.
func TestSARIFImportRatesCodeQL(t *testing.T) {
	doc := ruleLog("CodeQL",
		`{"id":"js/command-line-injection","defaultConfiguration":{"level":"error"},
		  "properties":{"problem.severity":"error","security-severity":"9.8","precision":"high"}},
		 {"id":"js/unused-local-variable","defaultConfiguration":{"level":"note"},
		  "properties":{"problem.severity":"recommendation","precision":"very-high"}},
		 {"id":"js/useless-assignment","defaultConfiguration":{"level":"warning"},"properties":{"precision":"high"}}`,
		`{"ruleId":"js/command-line-injection","message":{"text":"a"}},
		 {"ruleId":"js/unused-local-variable","message":{"text":"b"}},
		 {"ruleId":"js/useless-assignment","message":{"text":"c"}}`)
	got, source := importAll(t, plugin.FileTarget{Path: writeFile(t, doc)})
	want := []imported{
		{"js/command-line-injection", sarif.SeverityCritical, ""},
		{"js/unused-local-variable", sarif.SeverityLow, "problem.severity recommendation"},
		{"js/useless-assignment", sarif.SeverityMedium, ""},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("results:\n got %v\nwant %v", got, want)
	}
	if want := "security-severity for 1, problem.severity for 1, SARIF level for 1"; source != want {
		t.Errorf("severity source = %q, want %q", source, want)
	}
}

// Written to the shape of Fortify Static Code Analyzer's own SARIF, as in the sample the Fortify SSC
// SARIF parser ships: Impact, Accuracy and Probability on the rule as text, Confidence on the result.
// Levels note and warning, which read alone made the critical finding low.
func TestSARIFImportRatesFortify(t *testing.T) {
	doc := ruleLog("Micro Focus Fortify Static Code Analyzer",
		`{"id":"823FE039","properties":{"Accuracy":"4.0","Impact":"3.0","Probability":"4.0","Type":"Path Manipulation"}},
		 {"id":"F972FE42","defaultConfiguration":{"level":"note"},"properties":{"Accuracy":"5.0","Impact":"1.0","Probability":"1.0"}},
		 {"id":"F0B4AD7A"}`,
		`{"ruleId":"823FE039","level":"note","message":{"text":"a"},"properties":{"InstanceSeverity":"3.0","Confidence":"5.0"}},
		 {"ruleId":"F972FE42","message":{"text":"b"},"properties":{"InstanceSeverity":"2.0","Confidence":"5.0"}},
		 {"ruleId":"F0B4AD7A","message":{"text":"c"},"properties":{"Confidence":"5.0"}}`)
	got, source := importAll(t, plugin.FileTarget{Path: writeFile(t, doc)})
	want := []imported{
		{"823FE039", sarif.SeverityCritical, "Impact 3.0 · likelihood 3.2"},
		{"F972FE42", sarif.SeverityLow, "Impact 1.0 · likelihood 1"},
		{"F0B4AD7A", sarif.SeverityMedium, ""},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("results:\n got %v\nwant %v", got, want)
	}
	if want := "Fortify's impact and likelihood for 2, SARIF level for 1"; source != want {
		t.Errorf("severity source = %q, want %q", source, want)
	}
}

// Written to the shape of Snyk Open Source's SARIF (its CLI's open-source-sarif-output.ts): the
// score on the rule, the rating in the rule's summary. An advisory with no CVSS score writes
// "undefined" for it, and its summary rates it; one with a score keeps the score, whatever Snyk's
// own word.
func TestSARIFImportRatesSnyk(t *testing.T) {
	doc := ruleLog("Snyk Open Source",
		`{"id":"SNYK-JS-A","shortDescription":{"text":"Low severity - Denial of Service (DoS) vulnerability in a"},
		  "properties":{"cvssv3_baseScore":6.5,"security-severity":"6.5"}},
		 {"id":"snyk:lic:npm:b:AGPL-3.0","shortDescription":{"text":"Critical severity - AGPL-3.0 license vulnerability in b"},
		  "properties":{"security-severity":"undefined"}},
		 {"id":"SNYK-JS-C","shortDescription":{"text":"C in c"}}`,
		`{"ruleId":"SNYK-JS-A","level":"note","message":{"text":"a"}},
		 {"ruleId":"snyk:lic:npm:b:AGPL-3.0","level":"error","message":{"text":"b"}},
		 {"ruleId":"SNYK-JS-C","level":"warning","message":{"text":"c"}}`)
	got, source := importAll(t, plugin.FileTarget{Path: writeFile(t, doc)})
	want := []imported{
		{"SNYK-JS-A", sarif.SeverityMedium, ""},
		{"snyk:lic:npm:b:AGPL-3.0", sarif.SeverityCritical, "Critical severity"},
		{"SNYK-JS-C", sarif.SeverityMedium, ""},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("results:\n got %v\nwant %v", got, want)
	}
	if want := "security-severity for 1, Snyk's severity for 1, SARIF level for 1"; source != want {
		t.Errorf("severity source = %q, want %q", source, want)
	}
}

// Written to the shape of current dependency-check (templates/sarifReport.vsl): properties on the
// rule, a v2-only advisory scored by cvssv2_score and an unscored one rated only in its summary.
func TestSARIFImportRatesCurrentDependencyCheck(t *testing.T) {
	doc := ruleLog("dependency-check",
		`{"id":"CVE-2010-0001","shortDescription":{"text":"high severity - CVE-2010-0001 vulnerability in a"},
		  "properties":{"cvssv2_score":9.3,"cvssv2_severity":"HIGH","source":"NVD"}},
		 {"id":"GHSA-x","shortDescription":{"text":"critical severity - GHSA-x vulnerability in b"},"properties":{"source":"NPM"}}`,
		`{"ruleId":"CVE-2010-0001","level":"warning","message":{"text":"a"}},
		 {"ruleId":"GHSA-x","level":"warning","message":{"text":"b"}}`)
	got, _ := importAll(t, plugin.FileTarget{Path: writeFile(t, doc)})
	want := []imported{
		{"CVE-2010-0001", sarif.SeverityCritical, "cvssv2_score 9.3"},
		{"GHSA-x", sarif.SeverityCritical, "critical severity"},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("results:\n got %v\nwant %v", got, want)
	}
}

// A numeric security-severity still decides before any tool's table, and a tool whose file states no
// rating of its own keeps the level.
func TestSARIFImportScoreWinsAndNoRatingKeepsTheLevel(t *testing.T) {
	doc := ruleLog("gosec",
		`{"id":"G402","properties":{"tags":["security","HIGH"],"security-severity":"9.8"}},
		 {"id":"G104","properties":{"tags":["security"]}}`,
		`{"ruleId":"G402","level":"error","message":{"text":"a"}},
		 {"ruleId":"G104","level":"warning","message":{"text":"b"}}`)
	got, source := importAll(t, plugin.FileTarget{Path: writeFile(t, doc)})
	want := []imported{{"G402", sarif.SeverityCritical, ""}, {"G104", sarif.SeverityMedium, ""}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("results:\n got %v\nwant %v", got, want)
	}
	if want := "security-severity for 1, SARIF level for 1"; source != want {
		t.Errorf("severity source = %q, want %q", source, want)
	}
}

// A mapping the descriptor declares rates a tool Draugr has no table for. A value it does not name
// keeps the level, never anything lower, a score still decides, and the mapping replaces Draugr's
// own table for a tool it has one for.
func TestSARIFImportRatesByTheDescriptorsMapping(t *testing.T) {
	mapping := &saga.ImportSeverity{Property: "impact", Values: map[string]string{"Blocker": "critical", "Minor": "low"}}
	doc := ruleLog("acme-analyzer",
		`{"id":"A1","properties":{"impact":"Blocker"}},{"id":"A2"},{"id":"A3","properties":{"security-severity":"5.0"}}`,
		`{"ruleId":"A1","level":"warning","message":{"text":"a"}},
		 {"ruleId":"A2","level":"error","message":{"text":"b"},"properties":{"impact":"Unheard-of"}},
		 {"ruleId":"A3","level":"note","message":{"text":"c"},"properties":{"impact":"Blocker"}}`)
	got, source := importAll(t, plugin.FileTarget{Path: writeFile(t, doc), Severity: mapping})
	want := []imported{
		{"A1", sarif.SeverityCritical, "impact Blocker"},
		{"A2", sarif.SeverityHigh, ""},
		{"A3", sarif.SeverityMedium, ""},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("results:\n got %v\nwant %v", got, want)
	}
	if want := "security-severity for 1, impact, mapped by the descriptor for 1, SARIF level for 1"; source != want {
		t.Errorf("severity source = %q, want %q", source, want)
	}

	// Without the mapping the same file is read by level alone.
	got, _ = importAll(t, plugin.FileTarget{Path: writeFile(t, doc)})
	if got[0].severity != sarif.SeverityMedium {
		t.Errorf("an unknown tool was rated without a mapping: %v", got[0])
	}

	// The mapping is the team's word about its file, so it replaces gosec's table.
	gosecMapping := &saga.ImportSeverity{Property: "tags", Values: map[string]string{"MEDIUM": "critical"}}
	got, _ = importAll(t, plugin.FileTarget{Path: "testdata/sarif-import/gosec.sarif", Severity: gosecMapping})
	for _, g := range got {
		if g.severity != sarif.SeverityCritical || g.detail != "tags MEDIUM" {
			t.Errorf("%s: %s %q, want the descriptor's critical", g.rule, g.severity, g.detail)
		}
	}
}

// A mapping is part of what the scan read, so the same file read through another mapping is a
// different scan and is not answered from the cache.
func TestAFileTargetsCacheDetailHoldsItsMapping(t *testing.T) {
	plain := plugin.FileTarget{Path: "a.sarif", Digest: "abc"}
	one := plain
	one.Severity = &saga.ImportSeverity{Property: "impact", Values: map[string]string{"Major": "high", "Minor": "low"}}
	other := plain
	other.Severity = &saga.ImportSeverity{Property: "impact", Values: map[string]string{"Major": "critical", "Minor": "low"}}
	same := plain
	same.Severity = &saga.ImportSeverity{Property: "impact", Values: map[string]string{"Minor": "low", "Major": "high"}}
	if plain.CacheDetail() != "sha256=abc" {
		t.Errorf("a file with no mapping: %q", plain.CacheDetail())
	}
	if one.CacheDetail() == plain.CacheDetail() || one.CacheDetail() == other.CacheDetail() {
		t.Errorf("mappings share a cache entry: %q, %q", one.CacheDetail(), other.CacheDetail())
	}
	if one.CacheDetail() != same.CacheDetail() {
		t.Errorf("one mapping written in another order: %q, %q", one.CacheDetail(), same.CacheDetail())
	}
}

// A property bag that is not an object, and a value of a type no table reads, rate nothing and do
// not refuse the file.
func TestRateImportedReadsALooseBagAsNone(t *testing.T) {
	var b looseBag
	if err := b.UnmarshalJSON([]byte(`"a string"`)); err != nil || b != nil {
		t.Errorf("bag = %v, err %v", b, err)
	}
	if _, ok := ratingNumber(true); ok {
		t.Error("a boolean read as a number")
	}
	if texts := ratingTexts(map[string]any{"a": 1}); texts != nil {
		t.Errorf("an object read as %v", texts)
	}
}
