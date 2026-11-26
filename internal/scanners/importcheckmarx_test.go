package scanners

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// importCheckmarx reads file into control as an import would, suppressions counted where count says.
func importCheckmarx(t *testing.T, file, control string, count bool) sarif.Report {
	t.Helper()
	rep, err := NewSARIFImport().Scan(context.Background(), plugin.FileTarget{Path: file,
		Format: saga.ImportFormatCheckmarxOneJSON, Control: control, CountSuppressed: count}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// checkmarxFile is a results file holding results, counted as written.
func checkmarxFile(results ...string) string {
	return fmt.Sprintf(`{"results":[%s],"totalCount":%d,"scanID":"s"}`, strings.Join(results, ","), len(results))
}

// checkmarxSASTResult is an SQL injection result in src/A.java, at a line of its own for each
// severity and state, in state, with severity and comment.
func checkmarxSASTResult(state, severity, comment string) string {
	line := len(state)*10 + len(severity)
	return fmt.Sprintf(`{"type":"sast","id":"1","state":%q,"severity":%q,"description":"d",`+
		`"data":{"queryName":"SQL_Injection","nodes":[{"line":%d,"fileName":"/src/A.java"}]},`+
		`"comments":{"comments":%q},"vulnerabilityDetails":{"cweId":89}}`, state, severity, line, comment)
}

// Checkmarx's own results file holds two SAST results, one KICS result and one SCA result. Each
// control reads its own: SAST at the file and line the data enters, under the query and its CWE;
// KICS under KICS's query id, as Draugr's own KICS names it; SCA as the package at its installed and
// recommended version in its manifest, under the CVE. None is read into another control.
func TestEachControlReadsItsOwnResultsFromCheckmarxsFile(t *testing.T) {
	file := veracodeFixture("checkmarx-one-results.json")
	row := func(r sarif.Result) string {
		return fmt.Sprintf("%s %s:%d %s %s %s", r.RuleID, r.Location.URI, r.Location.StartLine,
			strings.Join(r.CWE, ","), r.Rating.Severity, r.Rating.Detail)
	}
	for control, want := range map[string][]string{
		"sast": {
			"Client_DOM_Stored_XSS challenge8-js.testdata:7 CWE-79 high Checkmarx HIGH",
			"Client_DOM_Stored_XSS GoatUtils-js.testdata:56 CWE-79 high Checkmarx HIGH",
		},
		"iac": {"fd54f200-402c-4333-a5a4-36ef6709af2f Dockerfile_desktop:1  high Checkmarx HIGH"},
		"sca": {"CVE-2013-7285 pom.xml:0 CWE-78 high Checkmarx HIGH"},
	} {
		rep := importCheckmarx(t, file, control, false)
		var got []string
		for _, r := range rep.Results {
			if r.Tool != checkmarxTool || r.Suppression != nil {
				t.Errorf("%s %s: tool %q, suppression %+v", control, r.RuleID, r.Tool, r.Suppression)
			}
			got = append(got, row(r))
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s:\n got %q\nwant %q", control, got, want)
		}
	}

	sast := importCheckmarx(t, file, "sast", false).Results[0]
	if sast.Message != "Client DOM Stored XSS" || strings.Contains(sast.Detail, "\n") ||
		!strings.HasSuffix(sast.Detail, "The data flows to challenge8-js.testdata:18.") {
		t.Errorf("SAST message %q, detail %q", sast.Message, sast.Detail)
	}
	iac := importCheckmarx(t, file, "iac", false).Results[0]
	if iac.Message != "Missing User Instruction" || iac.Detail != "The 'Dockerfile' does not contain any 'USER' "+
		"instruction. The 'Dockerfile' should contain the 'USER' instruction." {
		t.Errorf("KICS message %q, detail %q", iac.Message, iac.Detail)
	}
	sca := importCheckmarx(t, file, "sca", false).Results[0]
	pkg := sca.Package
	if pkg == nil || pkg.Name != "com.thoughtworks.xstream:xstream" || pkg.Version != "1.4.5" || pkg.FixedVersion != "1.4.20" ||
		pkg.Ecosystem != "maven" || pkg.PURL != "pkg:maven/com.thoughtworks.xstream/xstream@1.4.5" {
		t.Fatalf("SCA package %+v", pkg)
	}
	// The file's cveName, CWE-78, is no advisory id, so the finding carries no alias.
	if len(sca.Aliases) != 0 || sca.Message != "com.thoughtworks.xstream:xstream 1.4.5 → 1.4.20" ||
		!strings.HasPrefix(sca.Detail, "Xstream API versions up to 1.4.6") {
		t.Errorf("SCA aliases %v, message %q, detail %q", sca.Aliases, sca.Message, sca.Detail)
	}
}

// A result a person triaged Not Exploitable or Ignored in Checkmarx One is one the tool suppressed:
// set aside where the import honors suppressions, naming Checkmarx One, the state and the comment,
// and counted with that in its detail where it counts them. Proposed Not Exploitable awaits review,
// and counts either way.
func TestACheckmarxResultTriagedNotExploitableIsTheToolsSuppression(t *testing.T) {
	file := writeFile(t, checkmarxFile(
		checkmarxSASTResult("NOT_EXPLOITABLE", "HIGH", "input is a constant"),
		checkmarxSASTResult("IGNORED", "MEDIUM", ""),
		checkmarxSASTResult("PROPOSED_NOT_EXPLOITABLE", "LOW", "maybe"),
		checkmarxSASTResult("TO_VERIFY", "INFO", "")))

	honored := importCheckmarx(t, file, "sast", false).Results
	var reasons []string
	for _, r := range honored {
		if r.Suppression == nil {
			reasons = append(reasons, "counts")
			continue
		}
		s := r.Suppression
		if s.Service != "" || s.Origin != sarif.OriginScanner || s.Source != file {
			t.Errorf("suppression %+v", s)
		}
		reasons = append(reasons, s.Justification)
	}
	want := []string{"triaged NOT EXPLOITABLE (input is a constant)", "triaged IGNORED", "counts", "counts"}
	if !slices.Equal(reasons, want) {
		t.Errorf("honored: %q, want %q", reasons, want)
	}
	if honored[3].Rating.Severity != sarif.SeverityLow || honored[3].Rating.Detail != "Checkmarx INFO" {
		t.Errorf("INFO rated %+v", honored[3].Rating)
	}

	counted := importCheckmarx(t, file, "sast", true).Results
	if counted[0].Suppression != nil || !strings.Contains(counted[0].Detail, "reason: triaged NOT EXPLOITABLE "+
		"(input is a constant) · counted, as the import says suppressions: count") {
		t.Errorf("counted: suppression %+v, detail %q", counted[0].Suppression, counted[0].Detail)
	}
}

// A result that states no severity ranks high and says so: an SCA one as an advisory not scored yet,
// a query as a rule nobody rated. A CRITICAL one is critical.
func TestACheckmarxResultWithNoSeverityRanksHigh(t *testing.T) {
	sca := `{"type":"sca","id":"Cx35-4f6c","severity":"","data":{"packageIdentifier":"Npm-@scope/left-pad-1.0.0",` +
		`"recommendedVersion":null,"scaPackageData":{"locations":["/web/package.json"],"isDirectDependency":false,` +
		`"dependencyPaths":[[{"id":"Npm-app-2.0.0","name":"app","version":"2.0.0"},` +
		`{"id":"Npm-@scope/left-pad-1.0.0","name":"@scope/left-pad","version":"1.0.0"}]]}},` +
		`"vulnerabilityDetails":{"cweId":"NVD-CWE-Other","cveName":"GHSA-2222-3333-4444"}}`
	file := writeFile(t, checkmarxFile(sca, checkmarxSASTResult("TO_VERIFY", "", ""),
		`{"type":"kics","severity":"CRITICAL","data":{"queryId":"q-1","filename":"main.tf","line":3,"value":"open"}}`))

	got := importCheckmarx(t, file, "sca", false).Results[0]
	pkg := got.Package
	if got.RuleID != "Cx35-4f6c" || !slices.Equal(got.Aliases, []string{"GHSA-2222-3333-4444"}) || len(got.CWE) != 0 ||
		got.Location.URI != "web/package.json" || pkg.Name != "@scope/left-pad" || pkg.Version != "1.0.0" ||
		pkg.FixedVersion != "" || pkg.PURL != "pkg:npm/%40scope/left-pad@1.0.0" {
		t.Errorf("SCA %s at %s, aliases %v, CWE %v, package %+v", got.RuleID, got.Location.URI, got.Aliases, got.CWE, pkg)
	}
	if got.Rating.Severity != sarif.SeverityHigh || got.Rating.Detail != notScoredYet ||
		!strings.HasSuffix(got.Detail, "Brought in by app 2.0.0.") {
		t.Errorf("SCA rating %+v, detail %q", got.Rating, got.Detail)
	}
	if r := importCheckmarx(t, file, "sast", false).Results[0].Rating; r.Severity != sarif.SeverityHigh ||
		!strings.Contains(r.Detail, "not rated, so ranked high") {
		t.Errorf("SAST rating %+v", r)
	}
	if r := importCheckmarx(t, file, "iac", false).Results[0]; r.Rating.Severity != sarif.SeverityCritical ||
		r.RuleID != "q-1" || r.Message != "q-1" || r.Detail != "open" {
		t.Errorf("KICS %s %q %q rated %+v", r.RuleID, r.Message, r.Detail, r.Rating)
	}
}

// The package is read from the dependency path that names it, which states its name and version
// apart. Where no path names it, the identifier is split at its last hyphen, the name is its whole
// remainder where there is none, and a PHP or Ruby package takes the ecosystem Draugr's scanners name.
func TestCheckmarxPackageIdentifiers(t *testing.T) {
	for _, c := range []struct{ id, eco, name, version string }{
		{"Php-guzzlehttp/guzzle-6.3.0", "composer", "guzzlehttp/guzzle", "6.3.0"},
		{"Ruby-rack-2.0.1", "gem", "rack", "2.0.1"},
		{"Go-golang.org/x/net", "go", "golang.org/x/net", ""},
	} {
		eco, name, version := checkmarxPackage(c.id, nil)
		if eco != c.eco || name != c.name || version != c.version {
			t.Errorf("%s: %q %q %q", c.id, eco, name, version)
		}
	}
}

// A file that is not Checkmarx One's JSON, lists fewer results than it counts, or holds a result the
// CLI never writes, is refused with what is wrong, and so is an import into a control the file holds
// nothing for.
func TestACheckmarxFileThatIsNotWhatTheCLIWroteIsRefused(t *testing.T) {
	sca := func(data string) string {
		return `{"type":"sca","id":"CVE-2020-1","severity":"HIGH","data":` + data + `}`
	}
	for name, c := range map[string]struct{ body, control, want string }{
		"SARIF":       {`{"version":"2.1.0","runs":[]}`, "sast", "not Checkmarx One JSON"},
		"not JSON":    {`[`, "sast", "not Checkmarx One JSON"},
		"wrong shape": {`{"results":{},"totalCount":0,"scanID":"s"}`, "sast", "not Checkmarx One JSON"},
		"bad rows":    {`{"results":[1],"totalCount":1,"scanID":"s"}`, "sast", "not Checkmarx One JSON"},
		"cut short": {`{"results":[],"totalCount":75,"scanID":"s"}`, "sast",
			"the file lists 0 results and counts 75, so results are missing"},
		"secrets": {checkmarxFile(), "secrets", `the import names control "secrets"; import this file into sast, sca or iac`},
		"SAST with no file": {checkmarxFile(`{"type":"sast","severity":"HIGH","data":{"queryName":"q","nodes":[{"line":1}]}}`),
			"sast", "a SAST result names no query or file; every result"},
		"KICS with no query": {checkmarxFile(`{"type":"kics","severity":"HIGH","data":{"filename":"/x.tf"}}`),
			"iac", "a KICS result names no query or file"},
		"SCA with no package": {checkmarxFile(sca(`{"packageName":"tar"}`)), "sca",
			"an SCA result (id CVE-2020-1) names no vulnerability, package or manifest"},
		"SCA with no manifest": {checkmarxFile(sca(`{"packageIdentifier":"Npm-a-1","scaPackageData":{"locations":[" "]}}`)),
			"sca", "an SCA result (id CVE-2020-1) names no manifest"},
		"bad severity": {checkmarxFile(checkmarxSASTResult("TO_VERIFY", "SEVERE", "")), "sast",
			`severity "SEVERE"; Checkmarx One rates`},
		"bad SCA severity": {checkmarxFile(`{"type":"sca","id":"CVE-2020-1","severity":"SEVERE","data":` +
			`{"packageIdentifier":"Npm-a-1","scaPackageData":{"locations":["package.json"]}}}`), "sca", `severity "SEVERE"`},
		"bad KICS severity": {checkmarxFile(`{"type":"kics","severity":"SEVERE","data":{"queryId":"q","filename":"x.tf"}}`),
			"iac", `severity "SEVERE"`},
	} {
		_, err := NewSARIFImport().Scan(context.Background(), plugin.FileTarget{Path: writeFile(t, c.body),
			Format: saga.ImportFormatCheckmarxOneJSON, Control: c.control}, nil)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
}

// One file imported into two controls is two reads, cached apart; a format read whole keeps the key
// it had.
func TestACheckmarxFileIsCachedPerControl(t *testing.T) {
	sast := plugin.FileTarget{Path: "cx.json", Digest: "d", Format: saga.ImportFormatCheckmarxOneJSON, Control: "sast"}
	sca := sast
	sca.Control = "sca"
	if sast.CacheDetail() == sca.CacheDetail() || !strings.Contains(sca.CacheDetail(), " control=sca") {
		t.Errorf("sast %q, sca %q", sast.CacheDetail(), sca.CacheDetail())
	}
	trivy := plugin.FileTarget{Path: "t.json", Digest: "d", Format: saga.ImportFormatTrivyJSON, Control: "sca"}
	if strings.Contains(trivy.CacheDetail(), "control=") {
		t.Errorf("trivy-json keyed on its control: %q", trivy.CacheDetail())
	}
	got, err := DescribeFile([]byte(checkmarxFile(checkmarxSASTResult("TO_VERIFY", "HIGH", ""))), sast)
	if err != nil || got != "Checkmarx One JSON, 1 finding" {
		t.Errorf("describe: %q, %v", got, err)
	}
}
