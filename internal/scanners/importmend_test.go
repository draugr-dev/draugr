package scanners

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// mendFinding is the finding of rule in package name among results, failing the test where there is
// not exactly one.
func mendFinding(t *testing.T, results []sarif.Result, rule, name string) sarif.Result {
	t.Helper()
	var found []sarif.Result
	for _, r := range results {
		if r.RuleID == rule && r.Package != nil && r.Package.Name == name {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%s in %s: %d findings", rule, name, len(found))
	}
	return found[0]
}

const (
	mendDatabind = "com.fasterxml.jackson.core:jackson-databind"
	mendStruts   = "org.apache.struts:struts2-core"
	mendSpring   = "org.springframework:spring-core"
	mendPOM      = "/java/work/mend-poc-webgoat/pom.xml"
)

// A real file mend dep wrote of a Maven project reads as Draugr's dependency scanners read one: each
// vulnerability of a library at its installed version, in the manifest, under its CVE, with the
// package named group:artifact and its Maven package URL, as Trivy names a package in a pom.xml, so
// the two scanners' copies of a flaw correlate. Mend lists a library wherever the dependency tree
// holds it, and each vulnerability of it is one finding.
func TestMendDependencyJSONReadsAsDraugrsDependencyScannersDo(t *testing.T) {
	rep := importVeracode(t, veracodeFixture("mend-dep.json"), saga.ImportFormatMendJSON)
	// The file lists 138 vulnerabilities, 121 of them once each per library and manifest.
	if len(rep.Results) != 121 {
		t.Fatalf("%d findings, want 121", len(rep.Results))
	}
	perPackage := map[string]int{}
	for _, r := range rep.Results {
		p := r.Package
		if r.Tool != mendTool || p == nil || p.Ecosystem != "maven" || r.Location.URI != mendPOM ||
			p.PURL != "pkg:maven/"+strings.Replace(p.Name, ":", "/", 1)+"@"+p.Version || r.Rating == nil {
			t.Errorf("%s: tool %q, at %q, package %+v", r.RuleID, r.Tool, r.Location.URI, p)
			continue
		}
		perPackage[p.Name]++
	}
	want := map[string]int{mendDatabind: 64, "com.fasterxml.jackson.core:jackson-core": 1,
		"commons-collections:commons-collections": 5, "org.apache.commons:commons-email": 2, mendStruts: 28,
		"commons-fileupload:commons-fileupload": 4, "commons-io:commons-io": 2, "ognl:ognl": 1,
		"org.apache.struts.xwork:xwork-core": 9, mendSpring: 5}
	if fmt.Sprint(perPackage) != fmt.Sprint(want) {
		t.Errorf("findings per package = %v, want %v", perPackage, want)
	}

	r := mendFinding(t, rep.Results, "CVE-2018-19362", mendDatabind)
	if r.Package.Version != "2.9.5" || r.Package.FixedVersion != "2.9.8" || r.Rating.Severity != sarif.SeverityCritical ||
		r.Level != sarif.LevelError || r.Message != mendDatabind+" 2.9.5 → 2.9.8" || r.Detail != "" {
		t.Errorf("CVE-2018-19362 = %+v, message %q, detail %q", r.Package, r.Message, r.Detail)
	}
	if rule := rep.Rules["CVE-2018-19362"]; rule.Name != "CVE-2018-19362" {
		t.Errorf("rule = %+v", rule)
	}
}

// Mend writes a fix in its researchers' words. A version is read where the fix names it for this
// package, in each form the real file holds, and only above the version installed, since a fix of an
// older release line is no upgrade; several are joined as Trivy joins them. Where the fix also names
// another package, names this one in a form not read, or names no version above the installed one,
// Mend's whole text stays in the detail.
func TestMendFixIsReadWhereItNamesThisPackage(t *testing.T) {
	rep := importVeracode(t, veracodeFixture("mend-dep.json"), saga.ImportFormatMendJSON)
	for _, c := range []struct {
		rule, name, fixed, mends string
	}{
		// A version alone, and older release lines left out.
		{"CVE-2018-12023", mendDatabind, "2.9.6", ""},
		// group:artifact:version, continued by versions alone.
		{"CVE-2020-25649", mendDatabind, "2.9.10.7, 2.10.5.1, 2.11.0.rc1", ""},
		// group:artifact-version and artifact-version.
		{"CVE-2021-20190", mendDatabind, "2.9.10.7", ""},
		{"CVE-2020-10673", mendDatabind, "2.9.10.4", ""},
		// Every version named is an older release line.
		{"CVE-2020-10969", mendDatabind, "", "Upgrade to version com.fasterxml.jackson.core:jackson-databind:2.8.11.6;" +
			"com.fasterxml.jackson.core:jackson-databind:2.7.9.7"},
		// group:artifact - version, beside another package.
		{"CVE-2018-11776", mendStruts, "2.3.35, 2.5.17", "Upgrade to version org.apache.struts:struts2-core - 2.3.35,2.5.17;" +
			"org.apache.struts:struts2-rest-plugin - 2.3.34,2.5.17"},
		// The version installed is no fix.
		{"CVE-2015-5169", mendStruts, "", "Upgrade to version 2.3.20"},
		// A coordinate written with no colon before its version is not read.
		{"CVE-2015-6420", "commons-collections:commons-collections", "", "Upgrade to version " +
			"commons-collections:commons-collections3.2.2,org.apache.commons:commons-collections4:4.1"},
		// Fixed only by upgrading another package.
		{"CVE-2017-9787", "org.apache.struts.xwork:xwork-core", "", "Upgrade to version " +
			"org.apache.struts:struts2-core:2.3.33,org.apache.struts:struts2-core:2.5.12"},
		// A fix in spring-security-web, and spring-core's own versions after it.
		{"CVE-2018-1199", mendSpring, "4.3.14.RELEASE, 5.0.3.RELEASE", "Upgrade to version " +
			"org.springframework.security:spring-security-web:4.1.5.RELEASE,4.2.4.RELEASE,5.0.1.RELEASE;" +
			"org.springframework.security:spring-security-config:4.1.5.RELEASE,4.2.4.RELEASE,5.0.1.RELEASE;" +
			"org.springframework:spring-core:4.3.14.RELEASE,5.0.3.RELEASE"},
		// Whitespace inside the text is read as one space.
		{"CVE-2016-4465", mendStruts, "2.3.29", "Upgrade to version org.apache.struts:struts2-core:2.3.29, " +
			"org.apache.struts.xwork:xwork-core:2.3.29"},
	} {
		r := mendFinding(t, rep.Results, c.rule, c.name)
		if r.Package.FixedVersion != c.fixed {
			t.Errorf("%s in %s: fixed %q, want %q", c.rule, c.name, r.Package.FixedVersion, c.fixed)
		}
		if c.fixed == "" && !strings.Contains(r.Message, "no fix available") {
			t.Errorf("%s in %s: message %q", c.rule, c.name, r.Message)
		}
		if has := strings.Contains(r.Detail, "Mend's fix: "+c.mends+"."); has != (c.mends != "") ||
			(c.mends == "" && strings.Contains(r.Detail, "Mend's fix")) {
			t.Errorf("%s in %s: detail %q", c.rule, c.name, r.Detail)
		}
	}
}

// A library the tree lists under a direct dependency names that direct dependency, the one in the
// manifest to change, however deep it sits; one listed both directly and under another says both.
// Mend's own WS- id names a vulnerability with no CVE.
func TestMendTransitiveLibraryNamesTheDirectDependency(t *testing.T) {
	rep := importVeracode(t, veracodeFixture("mend-dep.json"), saga.ImportFormatMendJSON)
	for _, c := range []struct{ rule, name, via string }{
		{"WS-2022-0468", "com.fasterxml.jackson.core:jackson-core", "Brought in by " + mendDatabind + " 2.9.5."},
		// Two levels down, under commons-fileupload and xwork-core.
		{"CVE-2021-29425", "commons-io:commons-io", "Brought in by " + mendStruts + " 2.3.20."},
		{"CVE-2022-22970", mendSpring, "Declared directly and brought in by " + mendStruts + " 2.3.20."},
	} {
		if r := mendFinding(t, rep.Results, c.rule, c.name); !strings.HasSuffix(r.Detail, c.via) {
			t.Errorf("%s in %s: detail %q, want it to end %q", c.rule, c.name, r.Detail, c.via)
		}
	}
	if r := mendFinding(t, rep.Results, "CVE-2016-3093", mendStruts); strings.Contains(r.Detail, "Brought in") {
		t.Errorf("a direct dependency: detail %q", r.Detail)
	}
}

// mendFile is a hand-written file mend dep could write, of one library in manifest with vulns.
func mendFile(name, manifest, vulns string) string {
	return fmt.Sprintf(`[{"name":%q,"dependencyFile":%q,"vulnerabilities":[%s]}]`, name, manifest, vulns)
}

// mendVuln is a hand-written vulnerability of id rated severity, fixed as fix says.
func mendVuln(id, severity, fix string) string {
	return fmt.Sprintf(`{"name":%q,"severity":%q,"topFix":{"fixResolution":%q}}`, id, severity, fix)
}

// Shapes the real file lacks, each hand-written: LOW is low; a library whose name does not split
// keeps its file name, says it states no version, and counts every version its fix names, having none
// to compare them with; a fix that names no group leaves the package without one and with no package
// URL; a version after a part of the fix not read has no known package, so it is not read either; a
// vulnerability with no fix has no fix text; and a manifest inside the component's checkout is placed
// in it.
func TestMendShapesTheRealFileLacks(t *testing.T) {
	repo := t.TempDir()
	manifest := filepath.Join(repo, "svc", "pom.xml")
	unread := "Upgrade to version see - advisory, a:b:latest, 2.0"
	body := `[{"name":"tools.jar","dependencyFile":` + fmt.Sprintf("%q", manifest) + `,"vulnerabilities":[` +
		mendVuln("CVE-2024-1", "LOW", "Upgrade to version 0.9, 1.0") + `]},` +
		`{"name":"lib-1.0.jar","dependencyFile":"pom.xml","vulnerabilities":[` +
		mendVuln("CVE-2024-2", "MEDIUM", "Upgrade to version v1.1") + `,` + mendVuln("CVE-2024-3", "MEDIUM", unread) + `,` +
		`{"name":"CVE-2024-4","severity":"HIGH","description":"A flaw.","url":"https://example.test/4"}]}]`
	rep := importVeracode(t, writeFile(t, body), saga.ImportFormatMendJSON,
		plugin.RepositoryTarget{URL: repo})
	if len(rep.Results) != 4 {
		t.Fatalf("%d findings", len(rep.Results))
	}
	r := rep.Results[0]
	if r.Location.URI != "svc/pom.xml" || r.Package.Name != "tools.jar" || r.Package.Version != "" ||
		r.Package.PURL != "" || r.Rating.Severity != sarif.SeverityLow || r.Level != sarif.LevelNote ||
		r.Package.FixedVersion != "0.9, 1.0" ||
		r.Detail != "Mend names the library by its file, tools.jar, which states no version." {
		t.Errorf("tools.jar = %+v at %q, detail %q", r.Package, r.Location.URI, r.Detail)
	}
	r = rep.Results[1]
	if r.Package.Name != "lib" || r.Package.Version != "1.0" || r.Package.Ecosystem != "maven" ||
		r.Package.PURL != "" || r.Package.FixedVersion != "1.1" || r.Detail != "" || r.Level != sarif.LevelWarning {
		t.Errorf("lib = %+v, detail %q", r.Package, r.Detail)
	}
	if r = rep.Results[2]; r.Package.FixedVersion != "" || r.Detail != "Mend's fix: "+unread+"." {
		t.Errorf("unread = %+v, detail %q", r.Package, r.Detail)
	}
	r = rep.Results[3]
	if r.Package.FixedVersion != "" || r.Detail != "A flaw." || rep.Rules["CVE-2024-4"].HelpURI != "https://example.test/4" {
		t.Errorf("no fix = %+v, detail %q, rule %+v", r.Package, r.Detail, rep.Rules["CVE-2024-4"])
	}
}

// A file that is not the list mend dep writes, or whose library or vulnerability lacks what places
// and names it, or rates one outside Mend's severities, is refused with an error naming what, rather
// than read as a scan that found less.
func TestAMendFileOfTheWrongShapeIsRefused(t *testing.T) {
	for name, c := range map[string]struct{ body, want string }{
		"an object": {`{"libraries":[]}`, "not Mend's dependency JSON"},
		"null":      {`null`, "not Mend's dependency JSON"},
		"not JSON":  {`[`, "not Mend's dependency JSON"},
		"bad rows":  {`[1]`, "not Mend's dependency JSON"},
		"no name":   {`[{"dependencyFile":"pom.xml"}]`, "a library has no name"},
		"no file":   {`[{"name":"a-1.0.jar"}]`, "library a-1.0.jar has no dependencyFile"},
		"no file below": {`[{"name":"a-1.0.jar","dependencyFile":"pom.xml","children":[{"name":"b-1.0.jar"}]}]`,
			"library b-1.0.jar has no dependencyFile"},
		"no id": {mendFile("a-1.0.jar", "pom.xml", `{"severity":"HIGH"}`), "a vulnerability of a-1.0.jar has no name"},
		"bad severity": {mendFile("a-1.0.jar", "pom.xml", mendVuln("CVE-1", "SEVERE", "")),
			`severity "SEVERE" of CVE-1 in a-1.0.jar; Mend rates a vulnerability CRITICAL, HIGH, MEDIUM or LOW`},
	} {
		_, err := NewSARIFImport().Scan(context.Background(),
			plugin.FileTarget{Path: writeFile(t, c.body), Format: saga.ImportFormatMendJSON}, nil)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
	// An empty list is a scan that found no library.
	if rep := importVeracode(t, writeFile(t, `[]`), saga.ImportFormatMendJSON); len(rep.Results) != 0 {
		t.Errorf("empty list: %d findings", len(rep.Results))
	}
}
