package scanners

import (
	"context"
	"fmt"
	"maps"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// Every combination of Bandit's two ratings, written out rather than computed, so the test states
// the table the doc states.
func TestBanditRatingTable(t *testing.T) {
	for _, c := range []struct {
		severity, confidence string
		want                 sarif.Severity
		detail               string
	}{
		{"HIGH", "HIGH", sarif.SeverityHigh, "issue_severity high"},
		{"HIGH", "MEDIUM", sarif.SeverityHigh, "issue_severity high"},
		{"HIGH", "LOW", sarif.SeverityMedium, "issue_severity high · issue_confidence low"},
		{"MEDIUM", "HIGH", sarif.SeverityMedium, "issue_severity medium"},
		{"MEDIUM", "MEDIUM", sarif.SeverityMedium, "issue_severity medium"},
		{"MEDIUM", "LOW", sarif.SeverityLow, "issue_severity medium · issue_confidence low"},
		{"LOW", "HIGH", sarif.SeverityLow, "issue_severity low"},
		{"LOW", "MEDIUM", sarif.SeverityLow, "issue_severity low"},
		{"LOW", "LOW", sarif.SeverityLow, "issue_severity low · issue_confidence low"},
		{"HIGH", "UNDEFINED", sarif.SeverityHigh, "issue_severity high"},
	} {
		r := banditRating(map[string]any{"issue_severity": c.severity, "issue_confidence": c.confidence})
		if r == nil || r.Severity != c.want || r.Detail != c.detail {
			t.Errorf("%s × %s: rating %+v, want %s %q", c.severity, c.confidence, r, c.want, c.detail)
			continue
		}
		want := map[string]string{"issue_severity": c.severity, "issue_confidence": c.confidence}
		if !maps.Equal(r.Fields, want) {
			t.Errorf("%s × %s: fields = %v, want Bandit's own", c.severity, c.confidence, r.Fields)
		}
	}
	for name, props := range map[string]map[string]any{
		"no properties":       nil,
		"undefined severity":  {"issue_severity": "UNDEFINED", "issue_confidence": "HIGH"},
		"confidence only":     {"issue_confidence": "LOW"},
		"a severity number":   {"issue_severity": 3},
		"another tool's word": {"issue_severity": "CRITICAL"},
	} {
		if r := banditRating(props); r != nil {
			t.Errorf("%s: rated %+v", name, r)
		}
	}
}

// bandit is one result as the import reads it: its rule and line, and what the rating made of it.
type bandit struct {
	rule     string
	line     int
	level    sarif.Level
	severity sarif.Severity
	detail   string
}

// importedBandit reads a recorded Bandit file through the import and returns each result's rule,
// line, level and rating.
func importedBandit(t *testing.T, file string) (sarif.Report, []bandit) {
	t.Helper()
	rep, err := NewSARIFImport().Scan(context.Background(), plugin.FileTarget{Path: file, Component: "app"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var got []bandit
	for _, res := range rep.Results {
		b := bandit{rule: res.RuleID, line: res.Location.StartLine, level: res.Level, severity: res.Severity("")}
		if res.Rating != nil {
			b.detail = res.Rating.Detail
		}
		got = append(got, b)
	}
	return rep, got
}

// Recorded with Bandit 1.9.4 over draugr-demo's app, `bandit -f sarif -o bandit-demo.sarif -r
// demo/app`: the file draugr-demo imports. Bandit writes the level from issue_severity, leaving it
// out for MEDIUM, and no result here is rated confidence LOW, so every severity is the one its
// level gave and every finding now says what Bandit rated it.
func TestSARIFImportRatesRecordedBanditDemo(t *testing.T) {
	rep, got := importedBandit(t, "testdata/sarif-import/bandit-demo.sarif")
	want := []bandit{
		{"B404", 6, "note", sarif.SeverityLow, "issue_severity low"},
		{"B605", 16, "error", sarif.SeverityHigh, "issue_severity high"},
		{"B602", 23, "error", sarif.SeverityHigh, "issue_severity high"},
		{"B307", 30, "warning", sarif.SeverityMedium, "issue_severity medium"},
		{"B201", 35, "error", sarif.SeverityHigh, "issue_severity high"},
		{"B104", 35, "warning", sarif.SeverityMedium, "issue_severity medium"},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("results:\n got %v\nwant %v", got, want)
	}
	if s := field(t, rep, "severity"); s != "issue_severity and issue_confidence" {
		t.Errorf("severity source = %q", s)
	}
}

// Recorded with Bandit 1.9.4 over files written to reach the combinations the demo does not, `bandit
// -f sarif -o bandit-corpus.sarif -r corpus corpus3`. A result rated confidence LOW is one band below
// its severity; none of Bandit's own plugins reached here rates HIGH with LOW confidence, which the
// table test covers.
func TestSARIFImportRatesRecordedBanditCorpus(t *testing.T) {
	_, got := importedBandit(t, "testdata/sarif-import/bandit-corpus.sarif")
	want := []bandit{
		{"B403", 2, "note", sarif.SeverityLow, "issue_severity low"},
		{"B404", 5, "note", sarif.SeverityLow, "issue_severity low"},
		{"B105", 12, "note", sarif.SeverityLow, "issue_severity low"},
		{"B608", 19, "warning", sarif.SeverityMedium, "issue_severity medium"},
		{"B301", 28, "warning", sarif.SeverityMedium, "issue_severity medium"},
		{"B506", 33, "warning", sarif.SeverityMedium, "issue_severity medium"},
		{"B324", 37, "error", sarif.SeverityHigh, "issue_severity high"},
		{"B311", 41, "note", sarif.SeverityLow, "issue_severity low"},
		{"B501", 45, "error", sarif.SeverityHigh, "issue_severity high"},
		{"B113", 45, "warning", sarif.SeverityLow, "issue_severity medium · issue_confidence low"},
		{"B108", 49, "warning", sarif.SeverityMedium, "issue_severity medium"},
		{"B607", 54, "note", sarif.SeverityLow, "issue_severity low"},
		{"B603", 54, "note", sarif.SeverityLow, "issue_severity low"},
		{"B110", 55, "note", sarif.SeverityLow, "issue_severity low"},
		{"B202", 13, "note", sarif.SeverityLow, "issue_severity low · issue_confidence low"},
		{"B701", 14, "error", sarif.SeverityHigh, "issue_severity high"},
		{"B604", 22, "warning", sarif.SeverityLow, "issue_severity medium · issue_confidence low"},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("results:\n got %v\nwant %v", got, want)
	}
}

// The table is for Bandit's words, so another tool's properties of the same name rate nothing, and
// a Bandit result scored by whoever wrote the file keeps its score.
func TestSARIFImportRatesOnlyBanditsUnscoredResults(t *testing.T) {
	rated := `{"ruleId":"EX2","level":"error","message":{"text":"rated"},` +
		`"properties":{"issue_severity":"LOW","issue_confidence":"LOW"}}`
	scored := `{"ruleId":"EX2","level":"error","message":{"text":"scored"},` +
		`"properties":{"security-severity":"9.8","issue_severity":"LOW","issue_confidence":"LOW"}}`
	other := exampleLog(rated, "")
	rep, err := NewSARIFImport().Scan(context.Background(), plugin.FileTarget{Path: writeFile(t, other)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Results[0].Rating != nil || rep.Results[0].Severity("") != sarif.SeverityHigh {
		t.Errorf("another tool's result rated %+v", rep.Results[0].Rating)
	}

	both := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Bandit","version":"1.9.4"}},"results":[` +
		rated + "," + scored + "," + leveledResult + `]}]}`
	rep, err = NewSARIFImport().Scan(context.Background(), plugin.FileTarget{Path: writeFile(t, both)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r := rep.Results[0].Rating; r == nil || rep.Results[0].Severity("") != sarif.SeverityLow {
		t.Errorf("Bandit's result: rating %+v, severity %s", r, rep.Results[0].Severity(""))
	}
	if rep.Results[1].Rating != nil || rep.Results[1].Severity("") != sarif.SeverityCritical {
		t.Errorf("a scored result was rated %+v", rep.Results[1].Rating)
	}
	if rep.Results[2].Rating != nil {
		t.Errorf("a result with no rating was rated %+v", rep.Results[2].Rating)
	}
	want := "security-severity for 1, issue_severity and issue_confidence for 1, SARIF level for 1"
	if got := field(t, rep, "severity"); got != want {
		t.Errorf("severity source = %q, want %q", got, want)
	}
}

// A file whose runs hold fewer results than the parse read is rated as far as it goes. Only a file
// read twice could disagree with itself, so this guards the indexing rather than any file.
func TestRateBanditStopsAtTheReportsResults(t *testing.T) {
	rep := sarif.Report{Results: []sarif.Result{{RuleID: "B1"}}}
	doc := `{"runs":[{"tool":{"driver":{"name":"Bandit"}},"results":[
		{"properties":{"issue_severity":"HIGH"}},{"properties":{"issue_severity":"HIGH"}}]}]}`
	if err := rateBandit(&rep, []byte(doc)); err != nil {
		t.Fatal(err)
	}
	if rep.Results[0].Rating == nil {
		t.Error("the first result was not rated")
	}
	if err := rateBandit(&rep, []byte("{")); err == nil {
		t.Error("an unreadable file was accepted")
	}
}
