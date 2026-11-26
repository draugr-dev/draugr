package scanners

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// importGitLabSAST reads file, a GitLab SAST report, as an import would.
func importGitLabSAST(t *testing.T, file string) sarif.Report {
	t.Helper()
	return importVeracode(t, file, saga.ImportFormatGitLabSAST)
}

// One Semgrep run wrote its own JSON and the GitLab report of the same findings (semgrep scan
// --json-output and --gitlab-sast-output, over the demo): the report reads as the same findings, each
// at the file and line Semgrep's JSON gives, under the rule that found it.
func TestAGitLabSASTReportFromSemgrepReadsAsSemgrepsOwnJSONDoes(t *testing.T) {
	var fromReport, fromJSON []string
	for _, r := range importGitLabSAST(t, veracodeFixture("gitlab-sast-semgrep-cli.json")).Results {
		if r.Tool != "Semgrep" {
			t.Errorf("%s: tool %q", r.RuleID, r.Tool)
		}
		fromReport = append(fromReport, fmt.Sprintf("%s:%d %s", r.Location.URI, r.Location.StartLine, r.RuleID))
	}
	data, err := os.ReadFile(veracodeFixture("gitlab-sast-semgrep-cli.native.json"))
	if err != nil {
		t.Fatal(err)
	}
	var native struct {
		Results []struct {
			CheckID string `json:"check_id"`
			Path    string `json:"path"`
			Start   struct {
				Line int `json:"line"`
			} `json:"start"`
		} `json:"results"`
	}
	if err := json.Unmarshal(data, &native); err != nil {
		t.Fatal(err)
	}
	for _, r := range native.Results {
		fromJSON = append(fromJSON, fmt.Sprintf("%s:%d %s", r.Path, r.Start.Line, r.CheckID))
	}
	slices.Sort(fromReport)
	slices.Sort(fromJSON)
	if len(fromReport) != 24 || !slices.Equal(fromReport, fromJSON) {
		t.Errorf("the report reads\n%s\nand Semgrep's JSON\n%s", strings.Join(fromReport, "\n"), strings.Join(fromJSON, "\n"))
	}
}

// GitLab's own analyzers' reports read each vulnerability under its primary identifier, with the CWE
// its identifiers name, rated by GitLab's severity, under the scanner the vulnerability names.
func TestAGitLabSASTVulnerabilityCarriesItsRuleCWEAndSeverity(t *testing.T) {
	type row struct {
		rule, at, cwe string
		sev           sarif.Severity
		rated, tool   string
	}
	rows := func(rep sarif.Report) []row {
		var out []row
		for _, r := range rep.Results {
			out = append(out, row{r.RuleID, fmt.Sprintf("%s:%d", r.Location.URI, r.Location.StartLine),
				strings.Join(r.CWE, ","), r.Rating.Severity, r.Rating.Detail, r.Tool})
		}
		return out
	}
	app := "src/main/java/com/gitlab/security_products/tests/App.java"
	spotbugs := rows(importGitLabSAST(t, veracodeFixture("gitlab-sast-spotbugs.json")))
	want := []row{
		{"PREDICTABLE_RANDOM", app + ":47", "CWE-330", sarif.SeverityMedium, "GitLab Medium", "Find Security Bugs"},
		{"CIPHER_INTEGRITY", app + ":29", "CWE-353", sarif.SeverityMedium, "GitLab Medium", "Find Security Bugs"},
		{"PREDICTABLE_RANDOM", app + ":41", "CWE-330", sarif.SeverityMedium, "GitLab Medium", "Find Security Bugs"},
		{"ECB_MODE", app + ":29", "CWE-327", sarif.SeverityMedium, "GitLab Medium", "Find Security Bugs"},
	}
	if !slices.Equal(spotbugs, want) {
		t.Errorf("SpotBugs' report reads\n%+v\nwant\n%+v", spotbugs, want)
	}

	rep := importGitLabSAST(t, veracodeFixture("gitlab-sast-semgrep-analyzer.json"))
	semgrep := rows(rep)
	if len(semgrep) != 16 {
		t.Fatalf("GitLab's Semgrep analyzer's report read %d findings, want 16", len(semgrep))
	}
	if first := (row{"bandit.B506", "app/app.py:329", "CWE-502", sarif.SeverityHigh, "GitLab High", "Semgrep"}); semgrep[0] != first {
		t.Errorf("first finding = %+v, want %+v", semgrep[0], first)
	}
	if low := semgrep[4]; low.rule != "bandit.B311" || low.sev != sarif.SeverityLow {
		t.Errorf("fifth finding = %+v, want bandit.B311 rated low", low)
	}
	r := rep.Results[0]
	if r.Message != "Deserialization of untrusted data" || !strings.Contains(r.Detail, "safe_load") || r.Level != sarif.LevelError {
		t.Errorf("message %q, level %s, detail %.60q", r.Message, r.Level, r.Detail)
	}
	if rule := rep.Rules["bandit.B506"]; rule.HelpURI != "https://semgrep.dev/r/gitlab.bandit.B506" ||
		rule.ShortDescription != "Deserialization of untrusted data" {
		t.Errorf("rule = %+v", rule)
	}
}

// Info is low, as the mildest rating a tool gives. Unknown, and a vulnerability that states no
// severity, rank high and say they were not rated, since no rating is no evidence the flaw is mild.
// A vulnerability with no name reads its message, and with neither its primary identifier's name.
func TestAGitLabSASTSeverityThatSaysNothingRanksHigh(t *testing.T) {
	vuln := func(severity, name string, line int) string {
		return fmt.Sprintf(`{"id":"1","name":%q,"severity":%q,"location":{"file":"a.go","start_line":%d,"end_line":%d},`+
			`"identifiers":[{"type":"gosec_rule","name":"G101 hard-coded credential","value":"G101"},`+
			`{"type":"cwe","name":"CWE-798","value":"CWE-798"},{"type":"cwe","name":"CWE-798","value":"798"},{"type":"cwe","name":"x","value":"x"}]}`,
			name, severity, line, line+2)
	}
	body := `{"version":"15.2.5","scan":{"type":"sast","status":"success","scanner":{"name":"gosec"}},"vulnerabilities":[` +
		vuln("Info", "Credential", 3) + "," + vuln("Unknown", "", 13) + "," + vuln("", "", 23) + `]}`
	rep := importGitLabSAST(t, writeFile(t, body))
	for i, want := range []struct {
		sev            sarif.Severity
		rated, message string
	}{
		{sarif.SeverityLow, "GitLab Info", "Credential"},
		{sarif.SeverityHigh, "GitLab Unknown, not rated, so ranked high", "G101 hard-coded credential"},
		{sarif.SeverityHigh, "GitLab Unknown, not rated, so ranked high", "G101 hard-coded credential"},
	} {
		r := rep.Results[i]
		if r.Rating.Severity != want.sev || r.Rating.Detail != want.rated || r.Message != want.message {
			t.Errorf("finding %d: %s, %q, %q; want %s, %q, %q", i, r.Rating.Severity, r.Rating.Detail, r.Message,
				want.sev, want.rated, want.message)
		}
		if !slices.Equal(r.CWE, []string{"CWE-798"}) || r.Location.EndLine != r.Location.StartLine+2 || r.Tool != "gosec" {
			t.Errorf("finding %d: CWE %v, end line %d, tool %q", i, r.CWE, r.Location.EndLine, r.Tool)
		}
	}
}

// A file that is not a GitLab SAST report, one of another schema version or scan type, a scan that
// failed, and a vulnerability the format would not hold are refused, rather than read as a scan that
// found less.
func TestAGitLabSASTFileThatIsNotOneIsRefused(t *testing.T) {
	scan := `"scan":{"type":"sast","status":"success"}`
	for name, c := range map[string]struct{ body, want string }{
		"not JSON":                   {`nope`, "not a GitLab SAST report"},
		"Trivy's report":             {`{"SchemaVersion":2,"Results":[]}`, "not a GitLab SAST report"},
		"no scan":                    {`{"version":"15.2.5","vulnerabilities":[]}`, "not a GitLab SAST report"},
		"no vulnerabilities":         {`{"version":"15.2.5",` + scan + `}`, "not a GitLab SAST report"},
		"vulnerabilities not a list": {`{"version":"15.2.5",` + scan + `,"vulnerabilities":{}}`, "not a GitLab SAST report"},
		"schema 14":                  {`{"version":"14.1.2",` + scan + `,"vulnerabilities":[]}`, `schema version "14.1.2". Draugr reads GitLab's SAST schema version 15.x`},
		"dependency scanning": {`{"version":"15.2.5","scan":{"type":"dependency_scanning","status":"success"},"vulnerabilities":[]}`,
			`a "dependency_scanning" scan, and format gitlab-sast reads a SAST scan`},
		"a failed scan": {`{"version":"15.2.5","scan":{"type":"sast","status":"failure"},"vulnerabilities":[]}`,
			`scan status "failure". Draugr reads a scan that succeeded`},
		"no identifier": {`{"version":"15.2.5",` + scan + `,"vulnerabilities":[{"id":"1","identifiers":[],"location":{"file":"a.go"}}]}`,
			"a vulnerability names no file, identifier or package"},
		"no file": {`{"version":"15.2.5",` + scan + `,"vulnerabilities":[{"id":"1","identifiers":[{"type":"x","name":"x","value":"x"}],"location":{}}]}`,
			"a vulnerability names no file, identifier or package"},
		"a severity GitLab has not": {`{"version":"15.2.5",` + scan + `,"vulnerabilities":[{"id":"1","severity":"Severe",` +
			`"identifiers":[{"type":"x","name":"x","value":"x"}],"location":{"file":"a.go"}}]}`, `severity "Severe"; GitLab's format rates`},
	} {
		_, err := NewSARIFImport().Scan(context.Background(),
			plugin.FileTarget{Path: writeFile(t, c.body), Format: saga.ImportFormatGitLabSAST}, nil)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
	rep := importGitLabSAST(t, writeFile(t, `{"version":"15.0.4",`+scan+`,"vulnerabilities":[]}`))
	if len(rep.Results) != 0 {
		t.Errorf("a clean scan read %d findings", len(rep.Results))
	}
}

// Gemnasium's report of the demo reads as Draugr's own dependency scanners report: each finding is a
// package at its installed version in its lockfile, under its CVE with its GHSA id as an alias, with
// the fixed version its solution names. A Go module keeps go.mod's "v" in its version and package
// URL, and its fix is written without one, as Trivy and govulncheck write them.
func TestAGitLabDependencyScanningReportReadsAsANativeSCAFinding(t *testing.T) {
	rep := importVeracode(t, veracodeFixture("gitlab-dependency-scanning-gemnasium.json"),
		saga.ImportFormatGitLabDependencyScanning)
	if len(rep.Results) != 16 {
		t.Fatalf("read %d findings, want 16", len(rep.Results))
	}
	type row struct {
		rule, at, pkg, version, fixed, purl, ecosystem, aliases string
		sev                                                     sarif.Severity
	}
	byRule := map[string]row{}
	for _, r := range rep.Results {
		if r.Tool != "Gemnasium" || r.Package == nil {
			t.Fatalf("%s: tool %q, package %v", r.RuleID, r.Tool, r.Package)
		}
		p := r.Package
		byRule[r.RuleID+" "+r.Location.URI] = row{r.RuleID, r.Location.URI, p.Name, p.Version, p.FixedVersion, p.PURL, p.Ecosystem,
			strings.Join(r.Aliases, ","), r.Rating.Severity}
	}
	for _, want := range []row{
		{"CVE-2020-14040", "checkout/go.mod", "golang.org/x/text", "v0.3.0", "0.3.3", "pkg:golang/golang.org/x/text@v0.3.0", "gomod", "", sarif.SeverityHigh},
		{"CVE-2022-32149", "checkout/go.mod", "golang.org/x/text", "v0.3.0", "0.3.8", "pkg:golang/golang.org/x/text@v0.3.0", "gomod", "GHSA-69ch-w2m2-3vjp", sarif.SeverityHigh},
		{"CVE-2021-23337", "worker/package-lock.json", "lodash", "4.17.20", "4.17.21", "pkg:npm/lodash@4.17.20", "npm", "GHSA-35jh-r3h4-6jhm", sarif.SeverityHigh},
		{"CVE-2019-11358", "web/package-lock.json", "jquery", "1.8.3", "3.4.0", "pkg:npm/jquery@1.8.3", "npm", "GHSA-6c3j-c64m-qhgq", sarif.SeverityMedium},
	} {
		if got := byRule[want.rule+" "+want.at]; got != want {
			t.Errorf("%s =\n%+v\nwant\n%+v", want.rule, got, want)
		}
	}
	var unrated []sarif.Result
	for _, r := range rep.Results {
		if r.Rating.Detail == sarif.NotScoredYet {
			unrated = append(unrated, r)
		}
	}
	// Three advisories carry only Gemnasium's own id and the severity Unknown: each ranks high, labeled
	// not scored yet, under that id, with the fix the retire.js wording names.
	if len(unrated) != 3 {
		t.Fatalf("%d findings not scored, want 3", len(unrated))
	}
	if r := unrated[0]; r.RuleID != "04a14325-f5d9-4711-aee7-cf19ed54b0d2" || r.Rating.Severity != sarif.SeverityHigh ||
		r.Package.FixedVersion != "1.9.0" || !strings.HasSuffix(r.Message, sarif.MessageNotScoredYet) {
		t.Errorf("unrated finding = %s %s fixed %q, message %q", r.RuleID, r.Rating.Severity, r.Package.FixedVersion, r.Message)
	}
	if m := byRule["CVE-2021-23337 worker/package-lock.json"]; rep.Rules[m.rule].HelpURI != "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23337" {
		t.Errorf("rule = %+v", rep.Rules[m.rule])
	}
}

// A solution in a form the import does not read leaves no fixed version, and stays in the detail
// beside "no fix available"; a manifest the import has no ecosystem for leaves the package URL out;
// an npm scope's @ is escaped in the package URL.
func TestAGitLabDependencyFixAndPackageURLAreReadOnlyWhereCertain(t *testing.T) {
	vuln := func(file, name, solution string) string {
		return fmt.Sprintf(`{"id":"1","name":"Prototype pollution","severity":"High","solution":%q,`+
			`"location":{"file":%q,"dependency":{"package":{"name":%q},"version":"1.0.0"}},`+
			`"identifiers":[{"type":"gemnasium","name":"g","value":"g-1"},{"type":"cve","name":"CVE-2020-1","value":"CVE-2020-1"}]}`,
			solution, file, name)
	}
	body := `{"version":"15.2.2","scan":{"type":"dependency_scanning","status":"success","scanner":{"name":"Gemnasium"}},"vulnerabilities":[` +
		vuln("a/package-lock.json", "@acme/x", "Upgrade to version 1.0.1 or above.") + "," +
		vuln("b/pom.xml", "org.acme/x", "Upgrade to the latest version.") + "]}"
	rep := importVeracode(t, writeFile(t, body), saga.ImportFormatGitLabDependencyScanning)
	if p := rep.Results[0].Package; p.PURL != "pkg:npm/%40acme/x@1.0.0" || p.FixedVersion != "1.0.1" {
		t.Errorf("npm package = %+v", p)
	}
	r := rep.Results[1]
	if r.Package.PURL != "" || r.Package.Ecosystem != "" || r.Package.FixedVersion != "" ||
		!strings.Contains(r.Message, "no fix available") || !strings.HasSuffix(r.Detail, "Solution: Upgrade to the latest version.") {
		t.Errorf("maven package = %+v, message %q, detail %q", r.Package, r.Message, r.Detail)
	}
	for name, c := range map[string]struct{ body, want string }{
		"a SAST report": {`{"version":"15.2.2","scan":{"type":"sast","status":"success"},"vulnerabilities":[]}`,
			`a "sast" scan, and format gitlab-dependency-scanning reads a dependency scanning scan`},
		"no package": {`{"version":"15.2.2","scan":{"type":"dependency_scanning","status":"success"},"vulnerabilities":[` +
			`{"id":"1","identifiers":[{"type":"cve","name":"c","value":"CVE-1"}],"location":{"file":"go.mod"}}]}`,
			"a vulnerability names no file, identifier or package"},
		"not one": {`{}`, "not a GitLab dependency scanning report"},
	} {
		_, err := NewSARIFImport().Scan(context.Background(),
			plugin.FileTarget{Path: writeFile(t, c.body), Format: saga.ImportFormatGitLabDependencyScanning}, nil)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
}
