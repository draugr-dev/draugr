package scanners

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// veracodeFixture is a file of testdata/sarif-import holding Veracode's own output (see its NOTICE).
func veracodeFixture(name string) string { return filepath.Join("testdata", "sarif-import", name) }

// importVeracode reads file as format into the component of repos.
func importVeracode(t *testing.T, file, format string, repos ...plugin.RepositoryTarget) sarif.Report {
	t.Helper()
	rep, err := NewSARIFImport().Scan(context.Background(),
		plugin.FileTarget{Path: file, Format: format, Repositories: repos}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// A Pipeline Scan file and the SARIF Veracode's own converter wrote of it are the same flaws: each at
// the same file and line, under the same CWE, with the same flaw hash, so an alert keeps its identity
// whichever route the upload took.
func TestAVeracodePipelineFileReadsAsVeracodesOwnSARIFDoes(t *testing.T) {
	key := func(uri string, line int, cwe string, fp map[string]string) string {
		return fmt.Sprintf("%s:%d %s %s/%s/%s", uri, line, cwe, fp["flawHash"], fp["flawHashCount"], fp["flawHashOrdinal"])
	}
	var fromJSON, fromSARIF []string
	for _, r := range importVeracode(t, veracodeFixture("veracode-pipeline-js.json"), saga.ImportFormatVeracodePipelineJSON).Results {
		if len(r.CWE) != 1 || r.CWE[0] != r.RuleID || !strings.HasPrefix(r.RuleID, "CWE-") {
			t.Errorf("%s at %s: CWE = %v", r.RuleID, r.Location.URI, r.CWE)
		}
		fromJSON = append(fromJSON, key(r.Location.URI, r.Location.StartLine, r.RuleID, r.PartialFingerprints))
	}
	for _, r := range importVeracode(t, veracodeFixture("veracode-pipeline-js.sarif"), saga.ImportFormatSARIF).Results {
		fromSARIF = append(fromSARIF, key(r.Location.URI, r.Location.StartLine, "CWE-"+r.RuleID, r.PartialFingerprints))
	}
	slices.Sort(fromJSON)
	slices.Sort(fromSARIF)
	if len(fromJSON) != 13 || !slices.Equal(fromJSON, fromSARIF) {
		t.Errorf("the JSON reads\n%s\nand Veracode's SARIF\n%s", strings.Join(fromJSON, "\n"), strings.Join(fromSARIF, "\n"))
	}
}

// Each flaw is rated by Veracode's severity, as Veracode's converter bands it, with the rating naming
// Veracode's own word for it; its message is the flaw's type and the call, and its detail Veracode's
// explanation without markup. A Java class's bare file name is placed at the one file in the checkout
// whose path ends with it.
func TestAVeracodePipelineFlawIsRatedPlacedAndExplained(t *testing.T) {
	dir := checkoutWith(t, map[string]string{"src/main/java/SQLvulnerability.java": "class SQLvulnerability {}\n"})
	rep := importVeracode(t, veracodeFixture("veracode-pipeline-java.json"), saga.ImportFormatVeracodePipelineJSON,
		plugin.RepositoryTarget{URL: dir})
	type row struct {
		rule, at string
		sev      sarif.Severity
		rated    string
	}
	var got []row
	for _, r := range rep.Results {
		got = append(got, row{r.RuleID, fmt.Sprintf("%s:%d", r.Location.URI, r.Location.StartLine), r.Rating.Severity, r.Rating.Detail})
		if strings.ContainsAny(r.Detail, "<>") || r.Detail == "" || strings.Contains(r.Detail, "References:") {
			t.Errorf("%s: detail %q", r.RuleID, r.Detail)
		}
	}
	want := []row{
		{"CWE-89", "src/main/java/SQLvulnerability.java:21", sarif.SeverityHigh, "Veracode High"},
		{"CWE-259", "src/main/java/SQLvulnerability.java:16", sarif.SeverityMedium, "Veracode Medium"},
		{"CWE-117", "src/main/java/SQLvulnerability.java:23", sarif.SeverityMedium, "Veracode Medium"},
		{"CWE-404", "src/main/java/SQLvulnerability.java:19", sarif.SeverityLow, "Veracode Informational"},
		{"CWE-404", "src/main/java/SQLvulnerability.java:21", sarif.SeverityLow, "Veracode Informational"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("findings =\n%+v\nwant\n%+v", got, want)
	}
	if m := rep.Results[0].Message; m != "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') "+
		"at java.sql.Statement.executeQuery" {
		t.Errorf("message = %q", m)
	}
	for _, sev := range []int{1, 2, 5} {
		if s := veracodeSeverities[sev]; sev == 5 && s.band != sarif.SeverityCritical || sev < 5 && s.band != sarif.SeverityLow {
			t.Errorf("severity %d (%s) reads as %s", sev, s.name, s.band)
		}
	}
}

// A name no file of the checkout ends with, or that two files end with, is kept as Pipeline Scan
// wrote it, as is every name where the component has no local checkout.
func TestAVeracodePipelineFileNameIsPlacedOnlyWhereItIsOneFile(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"no such file":   {"README.md": "x\n"},
		"two such files": {"a/SQLvulnerability.java": "class A {}\n", "b/SQLvulnerability.java": "class B {}\n"},
	} {
		rep := importVeracode(t, veracodeFixture("veracode-pipeline-java.json"), saga.ImportFormatVeracodePipelineJSON,
			plugin.RepositoryTarget{URL: checkoutWith(t, files)})
		if uri := rep.Results[0].Location.URI; uri != "SQLvulnerability.java" {
			t.Errorf("%s: placed at %s", name, uri)
		}
	}
	rep := importVeracode(t, veracodeFixture("veracode-pipeline-js.json"), saga.ImportFormatVeracodePipelineJSON,
		plugin.RepositoryTarget{URL: "https://github.com/acme/web"})
	if uri := rep.Results[0].Location.URI; uri != "lib/optimizer/Optimizer.js" {
		t.Errorf("with no checkout: placed at %s", uri)
	}
	if place := veracodePlacer(checkoutWith(t, map[string]string{"x.js": ""})); place("/abs/x.js") != "/abs/x.js" {
		t.Error("an absolute path was moved")
	}
}

// A file that is not Pipeline Scan's, a scan that did not succeed, and a flaw Pipeline Scan would not
// write are refused, rather than read as a scan that found less.
func TestAVeracodePipelineFileThatIsNotOneIsRefused(t *testing.T) {
	for name, c := range map[string]struct{ body, want string }{
		"not JSON":               {`nope`, "not Veracode Pipeline Scan JSON"},
		"Trivy's report":         {`{"SchemaVersion":2,"Results":[]}`, "not Veracode Pipeline Scan JSON"},
		"no findings, no status": {`{"findings":[]}`, "not Veracode Pipeline Scan JSON"},
		"a failed scan": {`{"scan_status":"FAILURE","message":"Scan failed.","findings":[]}`,
			"scan status FAILURE: Scan failed. Draugr reads a scan that succeeded"},
		"a failed scan with no message": {`{"scan_status":"FAILURE","findings":[]}`,
			"scan status FAILURE. Draugr reads a scan that succeeded"},
		"a flaw with no CWE": {`{"scan_status":"SUCCESS","findings":[{"severity":3,"files":{"source_file":{"file":"a.js","line":1}}}]}`,
			"a flaw names no CWE, severity or file"},
		"a severity Veracode has not": {`{"scan_status":"SUCCESS","findings":[{"severity":9,"cwe_id":"79","files":{"source_file":{"file":"a.js","line":1}}}]}`,
			"severity 9; Veracode rates a flaw 0 to 5"},
	} {
		_, err := NewSARIFImport().Scan(context.Background(),
			plugin.FileTarget{Path: writeFile(t, c.body), Format: saga.ImportFormatVeracodePipelineJSON}, nil)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
	rep := importVeracode(t, writeFile(t, `{"scan_status":"SUCCESS","findings":[]}`), saga.ImportFormatVeracodePipelineJSON)
	if len(rep.Results) != 0 {
		t.Errorf("a clean scan read %d findings", len(rep.Results))
	}
	if got := veracodeFingerprints(map[string]json.RawMessage{"cause_hash": []byte(`"x"`)}); got != nil {
		t.Errorf("fingerprints with no flaw hash = %v", got)
	}
}
