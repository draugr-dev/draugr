package scanners

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// noSemgrepResults is Semgrep's JSON report for a run that found nothing, in the shape it writes.
const noSemgrepResults = `{"version":"1.182.1","results":[],"errors":[],"paths":{"scanned":[]}}`

// semgrepReportsOf is the document withSemgrepJSON hands parseSemgrep for a run that printed
// sarifDoc and wrote jsonDoc.
func semgrepReportsOf(t *testing.T, sarifDoc, jsonDoc []byte) []byte {
	t.Helper()
	out, err := json.Marshal(semgrepReports{SARIF: sarifDoc, JSON: jsonDoc})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// recordedSemgrep reads a recorded Semgrep run from testdata/semgrep: what it printed with --sarif
// and what it wrote to --json-output.
func recordedSemgrep(t *testing.T, name string) []byte {
	t.Helper()
	sarifDoc, err := os.ReadFile(filepath.Join("testdata", "semgrep", name+".sarif")) // #nosec G304 -- a fixture this test names
	if err != nil {
		t.Fatal(err)
	}
	jsonDoc, err := os.ReadFile(filepath.Join("testdata", "semgrep", name+".json")) // #nosec G304 -- a fixture this test names
	if err != nil {
		t.Fatal(err)
	}
	return semgrepReportsOf(t, sarifDoc, jsonDoc)
}

// fakeSemgrep stands in for the semgrep binary behind withSemgrepJSON: it prints sarifDoc, writes
// jsonDoc to the path --json-output names, and hands every argv to seen.
func fakeSemgrep(sarifDoc, jsonDoc string, seen func(argv []string)) func(context.Context, string, []string) ([]byte, error) {
	return withSemgrepJSON(func(_ context.Context, _ string, argv []string) ([]byte, error) {
		if seen != nil {
			seen(argv)
		}
		if i := slices.Index(argv, "--json-output"); i >= 0 && i+1 < len(argv) {
			if err := os.WriteFile(argv[i+1], []byte(jsonDoc), 0o600); err != nil {
				return nil, err
			}
		}
		return []byte(sarifDoc), nil
	})
}

// Every cell of the documented table, and each rule for lowering a cell, written out rather than
// computed, so the test states the table the doc states.
func TestSemgrepRatingTable(t *testing.T) {
	meta := func(impact, likelihood, confidence string, subcategory any) map[string]any {
		m := map[string]any{"impact": impact, "likelihood": likelihood, "confidence": confidence}
		if subcategory != nil {
			m["subcategory"] = subcategory
		}
		return m
	}
	vuln := []any{"vuln"}
	for _, c := range []struct {
		name   string
		meta   map[string]any
		want   sarif.Severity
		detail string
	}{
		{"high high", meta("HIGH", "HIGH", "MEDIUM", vuln), sarif.SeverityCritical, "impact high · likelihood high"},
		{"high medium", meta("HIGH", "MEDIUM", "MEDIUM", vuln), sarif.SeverityHigh, "impact high · likelihood medium"},
		{"high low", meta("HIGH", "LOW", "MEDIUM", vuln), sarif.SeverityMedium, "impact high · likelihood low"},
		{"medium high", meta("MEDIUM", "HIGH", "MEDIUM", vuln), sarif.SeverityHigh, "impact medium · likelihood high"},
		{"medium medium", meta("MEDIUM", "MEDIUM", "MEDIUM", vuln), sarif.SeverityMedium, "impact medium · likelihood medium"},
		{"medium low", meta("MEDIUM", "LOW", "MEDIUM", vuln), sarif.SeverityLow, "impact medium · likelihood low"},
		{"low high", meta("LOW", "HIGH", "MEDIUM", vuln), sarif.SeverityMedium, "impact low · likelihood high"},
		{"low medium", meta("LOW", "MEDIUM", "MEDIUM", vuln), sarif.SeverityLow, "impact low · likelihood medium"},
		{"low low", meta("LOW", "LOW", "MEDIUM", vuln), sarif.SeverityLow, "impact low · likelihood low"},

		{"high confidence changes nothing", meta("HIGH", "HIGH", "HIGH", vuln), sarif.SeverityCritical, "impact high · likelihood high"},
		{"low confidence lowers one band", meta("HIGH", "HIGH", "LOW", vuln), sarif.SeverityHigh,
			"impact high · likelihood high · confidence low"},
		{"audit lowers one band", meta("HIGH", "HIGH", "MEDIUM", []any{"audit"}), sarif.SeverityHigh,
			"impact high · likelihood high · subcategory audit"},
		{"both lower once", meta("HIGH", "HIGH", "LOW", []any{"audit"}), sarif.SeverityHigh,
			"impact high · likelihood high · confidence low · subcategory audit"},
		{"a secure default is not lowered", meta("HIGH", "HIGH", "MEDIUM", []any{"secure default"}), sarif.SeverityCritical,
			"impact high · likelihood high"},
		{"low is the floor", meta("LOW", "LOW", "LOW", []any{"audit"}), sarif.SeverityLow,
			"impact low · likelihood low · confidence low · subcategory audit"},
		{"a bare-string subcategory", meta("HIGH", "MEDIUM", "MEDIUM", "audit"), sarif.SeverityMedium,
			"impact high · likelihood medium · subcategory audit"},
		{"audit among others", meta("HIGH", "MEDIUM", "MEDIUM", []any{"vuln", "Audit"}), sarif.SeverityMedium,
			"impact high · likelihood medium · subcategory audit"},
		{"words in any case", meta("high", " Medium ", "low", vuln), sarif.SeverityMedium,
			"impact high · likelihood medium · confidence low"},
		{"no confidence", map[string]any{"impact": "MEDIUM", "likelihood": "HIGH"}, sarif.SeverityHigh,
			"impact medium · likelihood high"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := semgrepRating(c.meta)
			if r == nil {
				t.Fatal("no rating")
			}
			if r.Severity != c.want || r.Detail != c.detail {
				t.Errorf("rating = %s %q, want %s %q", r.Severity, r.Detail, c.want, c.detail)
			}
		})
	}
}

// A rule that does not state both ratings in Semgrep's words has no rating, and keeps its level.
func TestSemgrepRatingNeedsImpactAndLikelihood(t *testing.T) {
	for name, meta := range map[string]map[string]any{
		"no metadata":        nil,
		"no likelihood":      {"impact": "HIGH", "confidence": "LOW"},
		"no impact":          {"likelihood": "HIGH"},
		"a word Semgrep has": {"impact": "CRITICAL", "likelihood": "HIGH"},
		"a number":           {"impact": 5, "likelihood": "HIGH"},
		"a list":             {"impact": []any{"HIGH"}, "likelihood": "HIGH"},
	} {
		if r := semgrepRating(meta); r != nil {
			t.Errorf("%s: rated %+v", name, r)
		}
	}
}

// The machine formats keep what Semgrep said: every rating field under its own name, with its own
// value, a list as the list's entries.
func TestSemgrepRatingKeepsSemgrepsWords(t *testing.T) {
	r := semgrepRating(map[string]any{
		"impact": "HIGH", "likelihood": "MEDIUM", "confidence": "MEDIUM",
		"subcategory": []any{"vuln", "audit"}, "cwe": []any{"CWE-78"},
	})
	want := map[string]string{"impact": "HIGH", "likelihood": "MEDIUM", "confidence": "MEDIUM", "subcategory": "vuln, audit"}
	if r == nil || !maps.Equal(r.Fields, want) {
		t.Errorf("fields = %+v, want %v", r, want)
	}
}

// Recorded with Semgrep 1.182.1 and p/default over draugr-demo and a few files written to reach
// the cells the demo does not: `semgrep scan --sarif --json-output <file> --quiet --no-error
// --metrics=off --config p/default demo corpus corpus5`. Kept are every result under demo/app and
// the first result of each further impact, likelihood, confidence and subcategory, each object as
// Semgrep wrote it, with the SARIF rules no kept result names left out.
func TestParseSemgrepRatesRecordedRegistryOutput(t *testing.T) {
	report, err := parseSemgrep(recordedSemgrep(t, "registry"), t.TempDir(), plugin.Config{})
	if err != nil {
		t.Fatal(err)
	}
	type want struct {
		level    sarif.Level
		severity sarif.Severity
		detail   string
	}
	wants := map[string]want{
		// impact × likelihood, as the table has them.
		"python.lang.security.dangerous-system-call.dangerous-system-call": {"error", sarif.SeverityCritical,
			"impact high · likelihood high"},
		"python.lang.security.dangerous-subprocess-use.dangerous-subprocess-use": {"error", sarif.SeverityHigh,
			"impact high · likelihood medium"},
		"python.django.security.injection.code.user-eval.user-eval": {"warning", sarif.SeverityHigh,
			"impact high · likelihood medium"},
		"yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag": {"warning",
			sarif.SeverityHigh, "impact high · likelihood medium"},
		"python.flask.security.injection.subprocess-injection.subprocess-injection": {"error", sarif.SeverityHigh,
			"impact medium · likelihood high"},
		"python.flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host": {"warning", sarif.SeverityHigh,
			"impact medium · likelihood high"},
		"python.flask.security.audit.debug-enabled.debug-enabled": {"warning", sarif.SeverityHigh,
			"impact medium · likelihood high"},
		"javascript.express.security.injection.raw-html-format.raw-html-format": {"warning", sarif.SeverityHigh,
			"impact medium · likelihood high"},
		"python.flask.security.injection.user-eval.eval-injection": {"error", sarif.SeverityMedium,
			"impact medium · likelihood medium"},
		// A secure default keeps its cell.
		"python.lang.security.audit.subprocess-shell-true.subprocess-shell-true": {"error", sarif.SeverityMedium,
			"impact low · likelihood high"},
		// Lowered one band: by audit, by confidence LOW, and by both at once.
		"python.flask.security.injection.os-system-injection.os-system-injection": {"error", sarif.SeverityMedium,
			"impact high · likelihood medium · subcategory audit"},
		"javascript.lang.security.audit.dangerous-spawn-shell.dangerous-spawn-shell": {"error", sarif.SeverityMedium,
			"impact medium · likelihood high · confidence low"},
		"python.lang.security.audit.eval-detected.eval-detected": {"warning", sarif.SeverityLow,
			"impact high · likelihood low · confidence low · subcategory audit"},
		// Already at the bottom of the table, where lowering has nowhere to go.
		"dockerfile.security.missing-user.missing-user": {"error", sarif.SeverityLow,
			"impact medium · likelihood low · subcategory audit"},
		"generic.secrets.security.detected-private-key.detected-private-key": {"error", sarif.SeverityLow,
			"impact medium · likelihood low · confidence low · subcategory audit"},
		"python.django.security.injection.tainted-sql-string.tainted-sql-string": {"error", sarif.SeverityLow,
			"impact low · likelihood medium · confidence low · subcategory audit"},
		"python.requests.security.disabled-cert-validation.disabled-cert-validation": {"error", sarif.SeverityLow,
			"impact low · likelihood low · confidence low · subcategory audit"},
	}
	if len(report.Results) != len(wants) {
		t.Fatalf("results = %d, want %d", len(report.Results), len(wants))
	}
	for _, res := range report.Results {
		w, ok := wants[res.RuleID]
		if !ok {
			t.Errorf("unexpected rule %s", res.RuleID)
			continue
		}
		if res.Rating == nil {
			t.Errorf("%s: not rated", res.RuleID)
			continue
		}
		// The level is Semgrep's, unchanged; the severity is the table's.
		if res.Level != w.level || res.Severity("") != w.severity || res.Rating.Detail != w.detail {
			t.Errorf("%s: level %s, severity %s, %q\nwant level %s, severity %s, %q",
				res.RuleID, res.Level, res.Severity(""), res.Rating.Detail, w.level, w.severity, w.detail)
		}
	}
	// What Semgrep wrote, under its own names.
	for _, res := range report.Results {
		if res.RuleID == "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true" {
			want := map[string]string{"impact": "LOW", "likelihood": "HIGH", "confidence": "MEDIUM", "subcategory": "secure default"}
			if !maps.Equal(res.Rating.Fields, want) {
				t.Errorf("fields = %v, want %v", res.Rating.Fields, want)
			}
		}
	}
}

// Recorded with Semgrep 1.182.1 over a file holding the same call twice, the second under a
// nosemgrep comment, with p/default and a local rule that states no ratings: `--config p/default
// --config rules/local.yaml corpus4`. The SARIF keeps the suppressed result and the JSON leaves it
// out; the local rule's metadata is empty.
func TestParseSemgrepRatesBySuppressedTwinAndLeavesUnratedRules(t *testing.T) {
	report, err := parseSemgrep(recordedSemgrep(t, "mixed"), t.TempDir(), plugin.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Results) != 4 {
		t.Fatalf("results = %d, want the four Semgrep printed", len(report.Results))
	}
	for _, res := range report.Results {
		suppressed := res.Suppression != nil
		switch res.RuleID {
		case "python.lang.security.dangerous-system-call.dangerous-system-call":
			if res.Rating == nil || res.Severity("") != sarif.SeverityCritical {
				t.Errorf("line %d (suppressed %v): rating %+v, want its rule's", res.Location.StartLine, suppressed, res.Rating)
			}
		case "rules.no-os-popen":
			if res.Rating != nil || res.Severity("") != sarif.SeverityHigh {
				t.Errorf("line %d: rating %+v, severity %s; a rule stating no ratings keeps its level",
					res.Location.StartLine, res.Rating, res.Severity(""))
			}
		default:
			t.Errorf("unexpected rule %s", res.RuleID)
		}
	}
}

// A rule from disk is rated under the id Semgrep reported, and then reported under the id its file
// declares, with the rating on it.
func TestParseSemgrepRatesBeforeShorteningIDs(t *testing.T) {
	dir := semgrepRulesTree(t)
	t.Chdir(dir)
	prefix := dottedPrefix(filepath.Join(dir, "rules"))
	out := strings.ReplaceAll(semgrepLocalSARIF, "rules.", prefix)
	doc := `{"results":[{"check_id":"` + prefix + `no-eval","extra":{"metadata":{"impact":"HIGH","likelihood":"HIGH"}}}]}`
	report, err := parseSemgrep(semgrepReportsOf(t, []byte(out), []byte(doc)), t.TempDir(), plugin.Config{"config": "rules"})
	if err != nil {
		t.Fatal(err)
	}
	if got := report.Results[0]; got.RuleID != "no-eval" || got.Rating == nil || got.Severity("") != sarif.SeverityCritical {
		t.Errorf("result = %s rated %+v", got.RuleID, got.Rating)
	}
	if report.Results[1].Rating != nil {
		t.Errorf("%s was rated from another rule's metadata", report.Results[1].RuleID)
	}
}

// A result's rating is its own: rating one finding does not reach another of the same rule. The
// JSON repeats a rule's metadata on each of its results, and the rule is read once.
func TestRateSemgrepGivesEachResultItsOwnRating(t *testing.T) {
	report := sarif.Report{Results: []sarif.Result{{RuleID: "r", Level: "error"}, {RuleID: "r", Level: "error"}}}
	doc := `{"results":[
		{"check_id":"r","extra":{"metadata":{"impact":"LOW","likelihood":"LOW"}}},
		{"check_id":"r","extra":{"metadata":{"impact":"LOW","likelihood":"LOW"}}}]}`
	if err := rateSemgrep(&report, []byte(doc)); err != nil {
		t.Fatal(err)
	}
	report.Results[0].Rating.Detail = "changed"
	if report.Results[1].Rating.Detail != "impact low · likelihood low" {
		t.Errorf("second rating = %q", report.Results[1].Rating.Detail)
	}
}

// A rule whose metadata is not an object costs that rule its rating and nothing else, and a result
// that already carries a score keeps it.
func TestRateSemgrepKeepsWhatItCannotRate(t *testing.T) {
	report := sarif.Report{Results: []sarif.Result{
		{RuleID: "odd", Level: "error"},
		{RuleID: "scored", Level: "error", Score: 9.8, HasScore: true},
	}}
	doc := `{"results":[
		{"check_id":"odd","extra":{"metadata":["not","an","object"]}},
		{"check_id":"scored","extra":{"metadata":{"impact":"LOW","likelihood":"LOW"}}}]}`
	if err := rateSemgrep(&report, []byte(doc)); err != nil {
		t.Fatal(err)
	}
	for _, res := range report.Results {
		if res.Rating != nil {
			t.Errorf("%s rated %+v", res.RuleID, res.Rating)
		}
	}
	if got := report.Results[1].Severity(""); got != sarif.SeverityCritical {
		t.Errorf("scored severity = %s, want the score's", got)
	}
}

// Reports that cannot be read stop the scan, as unreadable SARIF does.
func TestParseSemgrepRefusesUnreadableReports(t *testing.T) {
	for _, c := range []struct {
		name string
		out  []byte
		want string
	}{
		{"not the reports document", []byte("{"), "read Semgrep's reports"},
		{"SARIF that is not JSON", semgrepReportsOf(t, []byte("Usage: semgrep"), []byte(noSemgrepResults)), "not a SARIF log"},
		{"JSON that is not JSON", semgrepReportsOf(t, []byte(semgrepLocalSARIF), []byte("{")), "JSON report Semgrep writes"},
	} {
		if _, err := parseSemgrep(c.out, t.TempDir(), plugin.Config{}); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
		}
	}
	_, err := parseSemgrep(semgrepReportsOf(t, nil, []byte(noSemgrepResults)), t.TempDir(), plugin.Config{})
	if !errors.Is(err, sarif.ErrNotSARIF) {
		t.Errorf("empty stdout: err = %v, want ErrNotSARIF", err)
	}
}

// One run writes both reports: the SARIF on stdout, the JSON to a file made for it and removed
// after.
func TestWithSemgrepJSONReturnsBothReports(t *testing.T) {
	var path string
	run := fakeSemgrep(semgrepLocalSARIF, noSemgrepResults, func(argv []string) {
		path = argv[slices.Index(argv, "--json-output")+1]
	})
	out, err := run(context.Background(), t.TempDir(), semgrepArgs("/work/repo", nil))
	if err != nil {
		t.Fatal(err)
	}
	var got semgrepReports
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if string(got.SARIF) != semgrepLocalSARIF || string(got.JSON) != noSemgrepResults {
		t.Errorf("reports = %s / %s", got.SARIF, got.JSON)
	}
	if path == "" || path == semgrepJSONPath {
		t.Errorf("--json-output %q, want a real file", path)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("%s is still there: %v", path, err)
	}
}

// A run that fails, or that wrote no JSON, is an error rather than findings ranked by level alone.
func TestWithSemgrepJSONRefusesARunWithoutItsJSON(t *testing.T) {
	failed := withSemgrepJSON(func(context.Context, string, []string) ([]byte, error) {
		return nil, errors.New("exit status 2")
	})
	if _, err := failed(context.Background(), t.TempDir(), semgrepArgs("/work/repo", nil)); err == nil || err.Error() != "exit status 2" {
		t.Errorf("failed run: err = %v", err)
	}
	silent := fakeSemgrep(semgrepLocalSARIF, "  \n", nil)
	if _, err := silent(context.Background(), t.TempDir(), semgrepArgs("/work/repo", nil)); err == nil ||
		!strings.Contains(err.Error(), "wrote no JSON report") {
		t.Errorf("empty JSON: err = %v", err)
	}
	removed := withSemgrepJSON(func(_ context.Context, _ string, argv []string) ([]byte, error) {
		return []byte(semgrepLocalSARIF), os.Remove(argv[slices.Index(argv, "--json-output")+1])
	})
	if _, err := removed(context.Background(), t.TempDir(), semgrepArgs("/work/repo", nil)); err == nil {
		t.Error("a run whose JSON report is missing was accepted")
	}
	if _, err := fakeSemgrep(semgrepLocalSARIF, noSemgrepResults, nil)(context.Background(), t.TempDir(),
		[]string{"semgrep", "scan", "--sarif", "/work/repo"}); err == nil {
		t.Error("a command with no slot for the JSON report ran")
	}
}
