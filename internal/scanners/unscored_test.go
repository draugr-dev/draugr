package scanners

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// unscoredRow is what these tests read of a finding: its band, the rating's label, and whether the
// message carries the label.
type unscoredRow struct {
	severity sarif.Severity
	label    string
	labeled  bool
}

func unscoredRowOf(r sarif.Result) unscoredRow {
	row := unscoredRow{severity: r.Severity(""), labeled: strings.Contains(r.Message, notScoredYet)}
	if r.Rating != nil {
		row.label = r.Rating.Detail
	}
	return row
}

// Trivy's UNKNOWN with no CVSS score is an advisory its databases have not rated, and ranks high,
// labeled not scored yet in its rating and its message; its LOW beside it stays low, and an UNKNOWN
// that carries a CVSS score is ranked by the score.
func TestTrivysUnknownIsNotScoredYetAndRanksHigh(t *testing.T) {
	doc, err := decodeTrivyVulns([]byte(`{"SchemaVersion": 2, "Results": [{"Target": "go.mod", "Class": "lang-pkgs", "Type": "gomod",
	  "Vulnerabilities": [
	    {"VulnerabilityID": "CVE-2026-0001", "PkgName": "golang.org/x/sys", "InstalledVersion": "v0.1.0", "FixedVersion": "v0.2.0",
	     "Severity": "UNKNOWN", "Title": "golang.org/x/sys: a flaw nobody has scored"},
	    {"VulnerabilityID": "CVE-2026-0002", "PkgName": "golang.org/x/sys", "InstalledVersion": "v0.1.0",
	     "Severity": "LOW", "Title": "a low flaw"},
	    {"VulnerabilityID": "CVE-2026-0003", "PkgName": "golang.org/x/sys", "InstalledVersion": "v0.1.0",
	     "Severity": "UNKNOWN", "CVSS": {"nvd": {"V3Score": 5.3}}, "Title": "scored by NVD"}
	  ]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]unscoredRow{}
	var unknown sarif.Result
	for _, r := range trivyVulnReport(doc, "", plugin.Config{}).Results {
		got[r.RuleID] = unscoredRowOf(r)
		if r.RuleID == "CVE-2026-0001" {
			unknown = r
		}
	}
	want := map[string]unscoredRow{
		"CVE-2026-0001": {sarif.SeverityHigh, notScoredYet, true},
		"CVE-2026-0002": {sarif.SeverityLow, "", false},
		"CVE-2026-0003": {sarif.SeverityMedium, "", false},
	}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("%s: %+v, want %+v", id, got[id], w)
		}
	}
	if unknown.Message != "golang.org/x/sys v0.1.0 → v0.2.0: a flaw nobody has scored (not scored yet)" {
		t.Errorf("message = %q, want the label at the end", unknown.Message)
	}
	if unknown.Level != sarif.LevelError || unknown.Rating.Fields["severity"] != "UNKNOWN" {
		t.Errorf("level %s, rating %+v", unknown.Level, unknown.Rating)
	}
}

// Grype's SARIF writes Unknown as a score of 0.0, the same as Negligible. Read with its JSON, an
// Unknown with no CVSS score is not scored yet and ranks high, labeled; Negligible and Low, which are
// Grype's ratings, stay low; and an Unknown a related CVE's record scores is ranked by that score.
func TestGrypesUnknownIsNotScoredYetAndRanksHigh(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "sarif-import", "grype-dir-lodash.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	severities := map[string]string{"GHSA-35jh-r3h4-6jhm": "Unknown", "GHSA-29mw-wpgm-hmr9": "Negligible", "GHSA-r5fr-rjxr-66jc": "Low"}
	for _, m := range doc["matches"].([]any) {
		match := m.(map[string]any)
		v := match["vulnerability"].(map[string]any)
		if v["id"] == "GHSA-xxjr-mmjv-4gpg" {
			// Unknown to Grype's own record, and scored by the related CVE's: the score decides.
			v["severity"], v["cvss"] = "Unknown", []any{}
		}
		if s, ok := severities[v["id"].(string)]; ok {
			v["severity"], v["cvss"] = s, []any{}
			// The related CVE's record carries a score too, which Grype's SARIF reads.
			related, _ := match["relatedVulnerabilities"].([]any)
			for _, rel := range related {
				rel.(map[string]any)["cvss"] = []any{}
			}
		}
	}
	edited, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := NewSARIFImport().Scan(context.Background(),
		plugin.FileTarget{Path: writeFile(t, string(edited)), Format: saga.ImportFormatGrypeJSON}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]unscoredRow{
		"GHSA-35jh-r3h4-6jhm": {sarif.SeverityHigh, notScoredYet, true},
		"GHSA-29mw-wpgm-hmr9": {sarif.SeverityLow, "", false},
		"GHSA-r5fr-rjxr-66jc": {sarif.SeverityLow, "", false},
		"GHSA-xxjr-mmjv-4gpg": {sarif.SeverityHigh, "", false}, // the related CVE's highest score, 8.2
	}
	seen := 0
	for _, r := range rep.Results {
		id, _, _ := strings.Cut(r.RuleID, "-lodash")
		w, ok := want[id]
		if !ok {
			t.Errorf("unexpected finding %s", r.RuleID)
			continue
		}
		seen++
		if got := unscoredRowOf(r); got.severity != w.severity || got.labeled != w.labeled ||
			(w.label != "" && got.label != w.label) {
			t.Errorf("%s: %+v, want %+v (message %q)", r.RuleID, got, w, r.Message)
		}
		if w.labeled && (!strings.HasPrefix(r.Message, "A vulnerability in npm package: lodash") || !strings.HasSuffix(r.Message, "(not scored yet)")) {
			t.Errorf("%s: message %q", r.RuleID, r.Message)
		}
	}
	if seen != len(want) {
		t.Errorf("read %d of the %d findings", seen, len(want))
	}
}

// A Grype message of another shape keeps its words.
func TestAGrypeMessageOfAnotherShapeKeepsItsWords(t *testing.T) {
	if got := withoutGrypeSeverity("something else"); got != "something else" {
		t.Errorf("another shape: %q", got)
	}
}
