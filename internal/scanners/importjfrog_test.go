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

// importJFrog reads body, a simple-json file, as an import into sca would.
func importJFrog(t *testing.T, body string) sarif.Report {
	t.Helper()
	return importJFrogInto(t, writeFile(t, body), "sca")
}

// importJFrogInto reads the simple-json file at path as an import into control would.
func importJFrogInto(t *testing.T, path, control string) sarif.Report {
	t.Helper()
	rep, err := NewSARIFImport().Scan(context.Background(),
		plugin.FileTarget{Path: path, Format: saga.ImportFormatJFrogSimpleJSON, Control: control}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// jfrogFile is a simple-json file whose dependency scan succeeded, holding vulns and violations.
func jfrogFile(vulns, violations string) string {
	return `{"vulnerabilities":[` + vulns + `],"securityViolations":[` + violations + `],"sast":null,` +
		`"errors":null,"scansStatus":{"scaScanStatusCode":0}}`
}

// jfrogVuln is one vulnerability row of type, name and version, in a manifest, with severity, CVE
// and fixedVersions.
func jfrogVuln(typ, name, version, file, severity, cve, fixed string) string {
	cves := "null"
	if cve != "" {
		cves = fmt.Sprintf(`[{"id":%q}]`, cve)
	}
	return fmt.Sprintf(`{"severity":%q,"impactedPackageName":%q,"impactedPackageVersion":%q,"impactedPackageType":%q,`+
		`"components":[{"name":%q,"version":%q,"location":{"file":%q}}],"summary":"Prototype pollution",`+
		`"fixedVersions":%s,"cves":%s,"issueId":"XRAY-1"}`, severity, name, version, typ, name, version, file, fixed, cves)
}

// JFrog's own test of jf audit writes the same scan as simple-json and as SARIF. The simple-json
// reads as the SARIF's Xray run does, each CVE in its package at its installed and fixed version in
// the manifest, with the package and versions as fields rather than folded into the rule id. A
// vulnerability listed on several targets, and a violation of one listed too, is one finding.
func TestJFrogSimpleJSONReadsAsJFrogsOwnSARIFDoes(t *testing.T) {
	rep := importJFrogInto(t, veracodeFixture("jfrog-audit-simple-json.json"), "sca")
	var fromJSON []string
	for _, r := range rep.Results {
		if r.Tool != jfrogTool || r.Package == nil || r.Package.Ecosystem != "npm" ||
			r.Package.PURL != "pkg:npm/"+r.Package.Name+"@"+r.Package.Version {
			t.Errorf("%s: tool %q, package %+v", r.RuleID, r.Tool, r.Package)
		}
		fromJSON = append(fromJSON, fmt.Sprintf("%s_%s_%s %s %q", r.RuleID, r.Package.Name, r.Package.Version,
			r.Location.URI, r.Package.FixedVersion))
	}
	data, err := os.ReadFile(veracodeFixture("jfrog-audit-sarif.json"))
	if err != nil {
		t.Fatal(err)
	}
	var log struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Name string `json:"name"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID     string `json:"ruleId"`
				Properties struct {
					FixedVersion string `json:"fixedVersion"`
				} `json:"properties"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatal(err)
	}
	var fromSARIF []string
	for _, run := range log.Runs {
		if run.Tool.Driver.Name != "JFrog Xray Scanner" {
			continue
		}
		for _, r := range run.Results {
			fixed, _ := jfrogFixedVersion([]string{r.Properties.FixedVersion})
			fromSARIF = append(fromSARIF, fmt.Sprintf("%s %s %q", r.RuleID,
				r.Locations[0].PhysicalLocation.ArtifactLocation.URI, fixed))
		}
	}
	slices.Sort(fromJSON)
	slices.Sort(fromSARIF)
	if len(fromJSON) != 5 || !slices.Equal(fromJSON, fromSARIF) {
		t.Errorf("simple-json reads\n%s\nand JFrog's SARIF\n%s", strings.Join(fromJSON, "\n"), strings.Join(fromSARIF, "\n"))
	}

	// A transitive package says which direct dependency brings it in, and every finding what JFrog's
	// contextual analysis said, which ranks nothing.
	for _, r := range rep.Results {
		if r.Package.Name == "async" && (r.Aliases[0] != "XRAY-609848" ||
			r.Detail != "Brought in by jake 10.8.7. JFrog's contextual analysis: Applicable.") {
			t.Errorf("async: aliases %v, detail %q", r.Aliases, r.Detail)
		}
	}
}

// Xray's severity is the rating, Information low as the mildest. Unknown, and a vulnerability that
// states none, rank high and say they were not scored yet, since no rating is no evidence the flaw is
// mild.
func TestJFrogSeverityIsXraysAndUnknownRanksHigh(t *testing.T) {
	rows := []string{
		jfrogVuln("npm", "a", "1.0.0", "package.json", "Critical", "CVE-2020-1", "null"),
		jfrogVuln("npm", "b", "1.0.0", "package.json", "Information", "CVE-2020-2", "null"),
		jfrogVuln("npm", "c", "1.0.0", "package.json", "Unknown", "CVE-2020-3", "null"),
		jfrogVuln("npm", "d", "1.0.0", "package.json", "", "CVE-2020-4", "null"),
	}
	rep := importJFrog(t, jfrogFile(strings.Join(rows, ","), ""))
	want := []sarif.Severity{sarif.SeverityCritical, sarif.SeverityLow, sarif.SeverityHigh, sarif.SeverityHigh}
	for i, r := range rep.Results {
		if r.Rating == nil || r.Rating.Severity != want[i] {
			t.Errorf("%s: rating %+v, want %s", r.RuleID, r.Rating, want[i])
		}
		if notScored := strings.HasSuffix(r.Message, sarif.MessageNotScoredYet); notScored != (i >= 2) {
			t.Errorf("%s: message %q", r.RuleID, r.Message)
		}
	}
}

// A fix Xray writes as one version is read, several are joined as Trivy joins them, and one in
// another form stays in the detail beside "no fix available". A Go module keeps its "v" in its version
// and package URL, and a package type with no package URL this writes, such as Maven's, leaves it out.
// A vulnerability with no CVE is named by Xray's own id. One brought in through two manifests is a
// finding in each.
func TestJFrogFixPackageURLAndIDAreReadWhereCertain(t *testing.T) {
	twoFiles := `{"severity":"High","impactedPackageName":"x","impactedPackageVersion":"1.0.0","impactedPackageType":"npm",` +
		`"components":[{"name":"p","version":"1","location":{"file":"a/package.json"}},` +
		`{"name":"q","version":"2","location":{"file":"b/package.json"}}],"cves":[{"id":"CVE-2020-9"}],"issueId":"XRAY-9"}`
	rows := []string{
		jfrogVuln("npm", "multi", "1.0.0", "package.json", "High", "CVE-2020-1", `["[1.0.1]","[2.0.1]"]`),
		jfrogVuln("Maven", "org.acme:x", "1.0.0", "pom.xml", "High", "CVE-2020-2", `["(,1.2.0)"]`),
		jfrogVuln("Go", "golang.org/x/net", "v0.1.0", "go.mod", "High", "", `["[v0.7.0]"]`),
		twoFiles,
	}
	rep := importJFrog(t, jfrogFile(strings.Join(rows, ","), ""))
	if len(rep.Results) != 5 {
		t.Fatalf("%d findings", len(rep.Results))
	}
	if p := rep.Results[0].Package; p.FixedVersion != "1.0.1, 2.0.1" {
		t.Errorf("multi = %+v", p)
	}
	r := rep.Results[1]
	if r.Package.PURL != "" || r.Package.FixedVersion != "" || r.Package.Ecosystem != "Maven" ||
		!strings.Contains(r.Message, "no fix available") || r.Detail != "Xray lists the fixed versions as (,1.2.0)." {
		t.Errorf("maven = %+v, message %q, detail %q", r.Package, r.Message, r.Detail)
	}
	r = rep.Results[2]
	if r.RuleID != "XRAY-1" || r.Package.PURL != "pkg:golang/golang.org/x/net@v0.1.0" || r.Package.FixedVersion != "0.7.0" {
		t.Errorf("go = %s %+v", r.RuleID, r.Package)
	}
	if a, b := rep.Results[3], rep.Results[4]; a.Location.URI != "a/package.json" || b.Location.URI != "b/package.json" ||
		a.RuleID != "CVE-2020-9" || a.Detail != "Brought in by p 1, q 2." {
		t.Errorf("two manifests = %+v / %+v", a.Location, b.Location)
	}
}

// A file whose findings are only the violations a watch raised is read from them, rather than as a
// clean scan.
func TestJFrogViolationsAloneAreRead(t *testing.T) {
	rep := importJFrog(t, jfrogFile("", jfrogVuln("npm", "a", "1.0.0", "package.json", "High", "CVE-2020-1", "null")))
	if len(rep.Results) != 1 || rep.Results[0].RuleID != "CVE-2020-1" {
		t.Errorf("results = %+v", rep.Results)
	}
}

// A file that is not simple-json, one whose dependency scan did not run, failed or left a target
// unscanned, and a vulnerability the format would not hold are refused, rather than read as a scan
// that found less.
func TestAJFrogFileThatIsNotAFinishedScanIsRefused(t *testing.T) {
	noFile := `{"severity":"High","impactedPackageName":"x","impactedPackageVersion":"1","components":[{"name":"x","version":"1"}],` +
		`"cves":[{"id":"CVE-1"}]}`
	for name, c := range map[string]struct{ body, want string }{
		"SARIF":       {`{"version":"2.1.0","runs":[]}`, "not JFrog simple-json"},
		"not JSON":    {`[`, "not JFrog simple-json"},
		"wrong shape": {`{"vulnerabilities":{},"scansStatus":{}}`, "not JFrog simple-json"},
		"bad rows":    {`{"vulnerabilities":[1],"scansStatus":{"scaScanStatusCode":0}}`, "not JFrog simple-json"},
		"no SCA":      {`{"vulnerabilities":null,"scansStatus":{"sastScanStatusCode":0}}`, "no dependency scan"},
		"SCA failed":  {`{"vulnerabilities":null,"scansStatus":{"scaScanStatusCode":1}}`, "the dependency scan did not succeed (status 1)"},
		"an error": {`{"vulnerabilities":null,"scansStatus":{"scaScanStatusCode":0},` +
			`"errors":[{"filePath":"svc","errorMessage":" npm install failed "}]}`, "the scan of svc failed (npm install failed)"},
		"an error of no file": {`{"vulnerabilities":null,"scansStatus":{"scaScanStatusCode":0},` +
			`"errors":[{"errorMessage":"timeout"}]}`, "the scan failed (timeout), so findings may be missing"},
		"no manifest": {jfrogFile(noFile, ""), "a vulnerability names no package, advisory id or manifest"},
		"no id":       {jfrogFile(`{"impactedPackageName":"x","components":[{"name":"x","location":{"file":"f"}}]}`, ""), "names no package, advisory id"},
		"bad severity": {jfrogFile(jfrogVuln("npm", "a", "1", "package.json", "Severe", "CVE-1", "null"), ""),
			`severity "Severe"; Xray rates`},
	} {
		_, err := NewSARIFImport().Scan(context.Background(),
			plugin.FileTarget{Path: writeFile(t, c.body), Format: saga.ImportFormatJFrogSimpleJSON, Control: "sca"}, nil)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
}

// JFrog's own test of jf audit writes its secrets, IaC and SAST findings beside the dependency scan,
// and each import reads its own control's: a finding at its file and line under JFrog's rule, rated by
// the severity JFrog states, with the CWE a SAST rule names. A finding a watch also raised as a
// violation is one finding, and the dependency vulnerabilities stay in sca.
func TestJFrogCodeFindingsAreReadIntoTheirOwnControls(t *testing.T) {
	file := veracodeFixture("jfrog-audit-simple-json.json")
	type row struct {
		tool, rule, at, severity string
		cwe                      []string
	}
	read := func(control string) []row {
		var out []row
		for _, r := range importJFrogInto(t, file, control).Results {
			if r.Package != nil {
				t.Errorf("%s: %s carries a package; a code finding names none", control, r.RuleID)
			}
			out = append(out, row{r.Tool, r.RuleID, fmt.Sprintf("%s:%d", r.Location.URI, r.Location.StartLine),
				string(r.Rating.Severity), r.CWE})
		}
		return out
	}

	// The file's SAST findings are in sastViolations only, each CWE listed as a bare number.
	want := []row{
		{"JFrog SAST", "js-template-injection", "server.js:26", "high", []string{"CWE-73"}},
		{"JFrog SAST", "js-insecure-random", "public/js/bootstrap.bundle.js:136", "low", []string{"CWE-338"}},
	}
	if got := read("sast"); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("sast = %+v, want %+v", got, want)
	}
	// Two secrets, and the violations raised for each; the violation states High where the finding
	// states Medium, and the first listed is kept.
	secrets := read("secrets")
	if len(secrets) != 2 {
		t.Fatalf("secrets = %+v, want the two secrets once each", secrets)
	}
	for _, r := range secrets {
		if r.tool != "JFrog Secrets" || r.rule != "REQ.SECRET.KEYS" || r.severity != "medium" {
			t.Errorf("secret = %+v", r)
		}
	}
	if got := read("iac"); len(got) != 1 || got[0].tool != "JFrog IaC" || got[0].rule != "aws_cloudfront_tls_only" ||
		got[0].at != "req_sw_terraform_aws_cloudfront_tls_only.tf:2" || got[0].severity != "high" {
		t.Errorf("iac = %+v", got)
	}
	// A secret's token validation is kept in the detail and changes no rating: one JFrog judged not a
	// token still ranks as the other does, since that judgment is no evidence the value is harmless.
	details := map[string]string{ // #nosec G101 -- the detail text the import writes, not a credential
		"fake-creds.txt": "JFrog's token validation: Active (active token).",
		"dir/server.js":  "JFrog's token validation: Not a token.",
	}
	for _, r := range importJFrogInto(t, file, "secrets").Results {
		if r.Detail != details[r.Location.URI] || r.Location.EndLine != 0 {
			t.Errorf("%s at %s:%d: detail %q, end %d", r.RuleID, r.Location.URI, r.Location.StartLine, r.Detail,
				r.Location.EndLine)
		}
	}
	for _, r := range importJFrogInto(t, file, "iac").Results {
		if r.Location.EndLine != 21 {
			t.Errorf("iac: end line %d, want the 21 the file states", r.Location.EndLine)
		}
	}
}

// A code finding is rated by the severity JFrog states, Information low as the mildest. Unknown, and
// a finding that states none, rank high and say why, since an unrated rule is no evidence the flaw is
// mild. A severity JFrog does not use, a finding with no rule or file, a control the file does not
// hold and a code scan that did not run are refused.
func TestJFrogCodeSeverityAndRefusals(t *testing.T) {
	codeFile := func(status, rows string) string {
		return `{"vulnerabilities":null,"sast":[` + rows + `],"scansStatus":{` + status + `}}`
	}
	sastRow := func(severity string) string {
		return fmt.Sprintf(`{"severity":%q,"ruleId":"r","cwe":["CWE-79","79","x"],"file":"a\\b.js","startLine":3,`+
			`"finding":" XSS "}`, severity)
	}
	ok := `"sastScanStatusCode":0`
	for severity, want := range map[string]string{"Critical": "critical", "Information": "low", "Unknown": "high", "": "high"} {
		rep := importJFrogInto(t, writeFile(t, codeFile(ok, sastRow(severity))), "sast")
		r := rep.Results[0]
		if string(r.Rating.Severity) != want || r.Location.URI != "a/b.js" || r.Message != "XSS" ||
			!slices.Equal(r.CWE, []string{"CWE-79"}) {
			t.Errorf("%q: rating %s, at %s, message %q, cwe %v", severity, r.Rating.Severity, r.Location.URI,
				r.Message, r.CWE)
		}
		if want == "high" && severity != "Critical" && !strings.Contains(r.Rating.Detail, "not rated, so ranked high") {
			t.Errorf("%q: label %q should say it was not rated", severity, r.Rating.Detail)
		}
	}

	for name, c := range map[string]struct{ body, control, want string }{
		"bad severity": {codeFile(ok, sastRow("Severe")), "sast", `severity "Severe"; JFrog rates`},
		"no rule":      {codeFile(ok, `{"severity":"High","file":"a.js"}`), "sast", "names no rule or file"},
		"no file":      {codeFile(ok, `{"severity":"High","ruleId":"r"}`), "sast", "names no rule or file"},
		"no SAST":      {codeFile(`"scaScanStatusCode":0`, ""), "sast", "no SAST scan"},
		"no secrets":   {codeFile(ok, ""), "secrets", "no secrets scan: the file records none. Run jf audit without selecting scanners, or with --secrets"},
		"IaC failed":   {codeFile(`"iacScanStatusCode":2`, ""), "iac", "the IaC scan did not succeed (status 2)"},
		"no control":   {codeFile(ok, ""), "", `the import names control ""; import this file into sca, sast, secrets or iac`},
		"images":       {codeFile(ok, ""), "images", "into sca, sast, secrets or iac"},
	} {
		_, err := NewSARIFImport().Scan(context.Background(), plugin.FileTarget{Path: writeFile(t, c.body),
			Format: saga.ImportFormatJFrogSimpleJSON, Control: c.control}, nil)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
}
