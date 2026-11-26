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

// importJFrog reads body, a simple-json file, as an import would.
func importJFrog(t *testing.T, body string) sarif.Report {
	t.Helper()
	return importVeracode(t, writeFile(t, body), saga.ImportFormatJFrogSimpleJSON)
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
	rep := importVeracode(t, veracodeFixture("jfrog-audit-simple-json.json"), saga.ImportFormatJFrogSimpleJSON)
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
			plugin.FileTarget{Path: writeFile(t, c.body), Format: saga.ImportFormatJFrogSimpleJSON}, nil)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
}
