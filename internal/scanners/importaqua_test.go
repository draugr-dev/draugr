package scanners

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// importAqua reads file as aqua-json into images, in the component of repos.
func importAqua(t *testing.T, file string, repos ...plugin.RepositoryTarget) sarif.Report {
	t.Helper()
	rep, err := NewSARIFImport().Scan(context.Background(), plugin.FileTarget{Path: file,
		Format: saga.ImportFormatAquaJSON, Control: "images", Repositories: repos}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// aquaFindingOf is the finding of rule in the package named name among results, failing the test
// where there is not exactly one.
func aquaFindingOf(t *testing.T, results []sarif.Result, rule, name string) sarif.Result {
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

// Aqua's own file, from its Harbor adapter, reads as Draugr's image scan reads one: each
// vulnerability under its CVE, at the image, with the package and installed version, rated by its
// CVSS score. Its packages carry no format, so they are not known to be the operating system's: no
// ecosystem, no operating system, and where Aqua found the package in the detail.
func TestAquaFileReadsAsDraugrsImageScanDoes(t *testing.T) {
	rep := importAqua(t, veracodeFixture("aqua-photon.json"))
	if len(rep.Results) != 3 {
		t.Fatalf("%d findings, want 3", len(rep.Results))
	}
	const image = "library/photon@sha256:ba6a5e0592483f28827545ce100f711aa602adf100e5884840c56c5b9b059acc"
	r := aquaFindingOf(t, rep.Results, "CVE-2019-9169", "glibc")
	if r.Tool != aquaTool || r.Location.URI != image || r.Image != image || r.OperatingSystem != "" || !r.HasScore ||
		r.Score != 9.8 || r.Severity("") != sarif.SeverityCritical || r.Level != sarif.LevelError {
		t.Errorf("finding = %+v", r)
	}
	if p := r.Package; p.Version != "2.28" || p.FixedVersion != "" || p.Ecosystem != "" || p.PURL != "" {
		t.Errorf("package = %+v", p)
	}
	if !strings.HasPrefix(r.Detail, "In the GNU C Library (aka glibc or libc6) through 2.29") ||
		!strings.HasSuffix(r.Detail, " Found at /usr/bin/gencat.") || strings.Contains(r.Detail, "Aqua's fix") {
		t.Errorf("detail = %q", r.Detail)
	}
	if r.Message != "glibc 2.28, no fix available" {
		t.Errorf("message = %q", r.Message)
	}
	if rule := rep.Rules["CVE-2019-9169"]; rule.HelpURI != "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2019-9169" {
		t.Errorf("rule = %+v", rule)
	}
	if r := aquaFindingOf(t, rep.Results, "CVE-2017-5932", "bash"); r.Severity("") != sarif.SeverityHigh || r.Score != 7.8 {
		t.Errorf("bash = %+v", r)
	}
	if got := provenanceField(rep, "severity"); got != "CVSS score" {
		t.Errorf("severity source = %q", got)
	}
}

// A package whose format is an operating system's package database is the distribution's: in its
// ecosystem, with the image's operating system, its fix read as the version Aqua names. A library Aqua
// identifies by its path alone is named by the path. A fix written as versions on its first line is
// read as those versions, every one kept where nothing orders them, and anything written after it, or
// a fix in the vendor's words alone, stays in the detail.
func TestAquaOperatingSystemPackagesAreTheDistros(t *testing.T) {
	rep := importAqua(t, veracodeFixture("aqua-many-vulns.json"))
	if len(rep.Results) != 24 {
		t.Fatalf("%d findings, want 24", len(rep.Results))
	}
	for _, r := range rep.Results {
		if r.Location.URI != "your_image:latest" || r.Image != "your_image:latest" {
			t.Errorf("%s: at %q, image %q", r.RuleID, r.Location.URI, r.Image)
		}
	}
	const jar = "/usr/share/myapp/myapp.war:WEB-INF/lib/spring-web-2.5.6.SEC03.jar"
	for _, c := range []struct {
		rule, name, version, ecosystem, os, fixed, fix string
	}{
		{"CVE-2019-14697", "musl", "1.1.20-r4", "alpine", "alpine 3.9.4", "1.1.20-r5", ""},
		{"CVE-2019-15133", "giflib", "5.1.4-r2", "alpine", "alpine 3.9.4", "", ""},
		{"CVE-2013-2099", "/usr/lib/python2.7/ssl.py", "", "", "", "3.3.2-r1, 3.2.5-r1, 2.6.8, 2.7.3-r1", ""},
		{"CVE-2014-0054", jar, "", "", "", "3.2.8, 4.0.2", "Aqua's fix: 3.2.8,4.0.2 3.2.8,4.0.2."},
		{"CVE-2013-7315", jar, "", "", "", "3.2.4, 4.0.0.M3", "Aqua's fix: 3.2.4, 4.0.0.M3 Users of affected versions"},
		{"CVE-2011-2730", jar, "", "", "", "", "Aqua's fix: The vendor has issued a fix (2.0)."},
	} {
		r := aquaFindingOf(t, rep.Results, c.rule, c.name)
		if r.Package.Version != c.version || r.Package.Ecosystem != c.ecosystem || r.OperatingSystem != c.os ||
			r.Package.FixedVersion != c.fixed {
			t.Errorf("%s = %+v, os %q", c.rule, r.Package, r.OperatingSystem)
		}
		if has := strings.Contains(r.Detail, c.fix); !has || (c.fix == "" && strings.Contains(r.Detail, "Aqua's fix")) {
			t.Errorf("%s: detail %q", c.rule, r.Detail)
		}
		if strings.Contains(r.Detail, "Found at") {
			t.Errorf("%s: detail repeats the path it is named by: %q", c.rule, r.Detail)
		}
	}
	// WS-2009-0001 has no score, so it keeps Aqua's severity.
	if r := aquaFindingOf(t, rep.Results, "WS-2009-0001", "/usr/share/myapp/myapp.war:WEB-INF/lib/commons-codec-1.9.jar"); r.HasScore || r.Severity("") != sarif.SeverityLow {
		t.Errorf("WS-2009-0001 = %+v", r)
	}
	if got := provenanceField(rep, "severity"); got != "CVSS score for 23, Aqua's severity for 1" {
		t.Errorf("severity source = %q", got)
	}
}

// Aqua's severity and its score can disagree, since Aqua takes the distribution's word: apt's flaw is
// critical to Aqua at a score of 3.7, and tar's negligible at 10. A finding keeps whichever is more
// severe, so neither lower reading ranks it lower. A Java package Aqua names by its path keeps no
// ecosystem.
func TestAquaRatesByTheMoreSevereOfScoreAndSeverity(t *testing.T) {
	rep := importAqua(t, veracodeFixture("aqua-debian-severity.json"))
	if len(rep.Results) != 13 {
		t.Fatalf("%d findings, want 13", len(rep.Results))
	}
	for _, c := range []struct {
		rule, name string
		severity   sarif.Severity
		scored     bool
	}{
		{"CVE-2011-3374", "apt", sarif.SeverityCritical, false},
		{"CVE-2005-2541", "tar", sarif.SeverityCritical, true},
		{"CVE-2018-6829", "libgcrypt20", sarif.SeverityHigh, true},
		{"CVE-2020-8908", "/BOOT-INF/lib/guava-20.0.jar", sarif.SeverityLow, true},
	} {
		r := aquaFindingOf(t, rep.Results, c.rule, c.name)
		if r.Severity("") != c.severity || r.HasScore != c.scored {
			t.Errorf("%s = %s, scored %v", c.rule, r.Severity(""), r.HasScore)
		}
	}
	r := aquaFindingOf(t, rep.Results, "CVE-2011-3374", "apt")
	if r.Package.Ecosystem != "debian" || r.OperatingSystem != "debian 10" || r.Rating.Detail != "Aqua critical" {
		t.Errorf("apt = %+v, os %q, rating %+v", r.Package, r.OperatingSystem, r.Rating)
	}
	r = aquaFindingOf(t, rep.Results, "CVE-2018-10237", "/BOOT-INF/lib/guava-20.0.jar")
	if r.Package.Version != "20.0.0" || r.Package.FixedVersion != "24.1.1-android" || r.Package.Ecosystem != "" ||
		r.OperatingSystem != "" {
		t.Errorf("guava = %+v, os %q", r.Package, r.OperatingSystem)
	}
	if got := provenanceField(rep, "severity"); got != "CVSS score for 12, Aqua's severity for 1" {
		t.Errorf("severity source = %q", got)
	}
}

// aquaFileOf is a hand-written file of the image named image, of os, with resources.
func aquaFileOf(image, os, resources string) string {
	return fmt.Sprintf(`{"image":%q,"os":%q,"version":"12","resources":[%s]}`, image, os, resources)
}

// aquaResourceOf is a hand-written resource with its vulnerabilities.
func aquaResourceOf(resource string, vulns ...string) string {
	return fmt.Sprintf(`{"resource":%s,"vulnerabilities":[%s]}`, resource, strings.Join(vulns, ","))
}

// aquaVulnOf is a hand-written vulnerability id rated severity and score, with fix.
func aquaVulnOf(id, severity, score, fix string) string {
	return fmt.Sprintf(`{"name":%q,"aqua_severity":%q,"aqua_score":%s,"fix_version":%q}`, id, severity, score, fix)
}

// Shapes the real files lack, each hand-written: an operating-system package's fixes are ordered by
// its distribution, and an npm package's by npm, so an older release line is left out, and a fix
// naming only older ones stays in the detail; an rpm package of a distribution Draugr does not know
// takes its format's ecosystem; the source package a binary package was built from is in the detail;
// a score may be a string or absent; a vendor URL stands in for the NVD's; and the same
// vulnerability of a package listed twice is one finding, rated by the worse copy.
func TestAquaShapesTheRealFilesLack(t *testing.T) {
	resources := strings.Join([]string{
		aquaResourceOf(`{"format":"deb","name":"libssl3","version":"3.0.1-1","src_name":"openssl","src_version":"3.0.1-1"}`,
			aquaVulnOf("CVE-2024-1", "high", `"7.5"`, "3.0.0-9, 3.0.2-1, 3.1.0-1"),
			aquaVulnOf("CVE-2024-2", "medium", "null", "3.0.0-9")),
		aquaResourceOf(`{"format":"npm","name":"ws","version":"7.5.9","path":"/app/node_modules/ws"}`,
			aquaVulnOf("CVE-2024-37890", "high", "7.5", "5.2.4, 6.2.3, 7.5.10, 8.17.1")),
		aquaResourceOf(`{"format":"rpm","name":"zlib","version":"1.2.13"}`,
			`{"name":"CVE-2024-5","aqua_severity":"low","aqua_score":2.0,"vendor_url":"https://vendor.test/CVE-2024-5"}`,
			aquaVulnOf("CVE-2024-5", "high", "8.0", "")),
	}, ",")
	rep := importAqua(t, writeFile(t, aquaFileOf("ghcr.io/acme/web:1.0", "debian", resources)))
	if len(rep.Results) != 4 {
		t.Fatalf("%d findings, want 4", len(rep.Results))
	}
	for _, c := range []struct {
		rule, name, ecosystem, fixed, fix, detail string
		severity                                  sarif.Severity
		scored, os                                bool
	}{
		{"CVE-2024-1", "libssl3", "debian", "3.0.2-1, 3.1.0-1", "", "Built from openssl 3.0.1-1.", sarif.SeverityHigh, true, true},
		{"CVE-2024-2", "libssl3", "debian", "", "3.0.0-9", "Built from openssl 3.0.1-1.", sarif.SeverityMedium, false, true},
		{"CVE-2024-37890", "ws", "npm", "7.5.10, 8.17.1", "", "Found at /app/node_modules/ws.", sarif.SeverityHigh, true, false},
		{"CVE-2024-5", "zlib", "debian", "", "", "", sarif.SeverityHigh, true, true},
	} {
		r := aquaFindingOf(t, rep.Results, c.rule, c.name)
		if r.Package.Ecosystem != c.ecosystem || r.Package.FixedVersion != c.fixed || r.Severity("") != c.severity ||
			r.HasScore != c.scored || (r.OperatingSystem == "debian 12") != c.os {
			t.Errorf("%s = %+v, severity %s, scored %v, os %q", c.rule, r.Package, r.Severity(""), r.HasScore,
				r.OperatingSystem)
		}
		if has := strings.Contains(r.Detail, "Aqua's fix: "+c.fix+"."); has != (c.fix != "") ||
			(c.fix == "" && strings.Contains(r.Detail, "Aqua's fix")) || !strings.Contains(r.Detail, c.detail) {
			t.Errorf("%s: detail %q", c.rule, r.Detail)
		}
	}
	if rule := rep.Rules["CVE-2024-5"]; rule.HelpURI != "https://vendor.test/CVE-2024-5" {
		t.Errorf("rule = %+v", rule)
	}

	// An rpm package of a distribution Draugr does not know belongs to rpm's ecosystem.
	rep = importAqua(t, writeFile(t, aquaFileOf("web", "photon", aquaResourceOf(`{"format":"rpm","name":"zlib","version":"1.2.13"}`,
		aquaVulnOf("CVE-1", "low", "2", "1.2.12, 1.2.14")))))
	if r := aquaFindingOf(t, rep.Results, "CVE-1", "zlib"); r.Package.Ecosystem != "rpm" ||
		r.Package.FixedVersion != "1.2.14" || r.OperatingSystem != "photon 12" {
		t.Errorf("zlib on photon = %+v, os %q", r.Package, r.OperatingSystem)
	}
}

// An image finding's location is the image, which names nothing in a checkout, so it is placed in no
// repository: a component's paths: leave it in, and it is not reported as naming a file the checkout
// lacks.
func TestAquaFindingsAreNotPlacedInACheckout(t *testing.T) {
	rep := importAqua(t, veracodeFixture("aqua-photon.json"),
		plugin.RepositoryTarget{URL: t.TempDir(), Paths: []string{"services/api"}})
	if len(rep.Results) != 3 {
		t.Fatalf("findings = %+v", rep.Results)
	}
	for _, r := range rep.Results {
		if r.ImportedRepository != "" {
			t.Errorf("%s placed in %q", r.RuleID, r.ImportedRepository)
		}
	}
	if len(rep.Inputs) != 0 {
		t.Errorf("inputs = %+v", rep.Inputs)
	}
}

// A file that is not the JSON Aqua's scanner writes, or whose image, resource or vulnerability lacks
// what places and names it, or that rates one outside Aqua's severities or scores one with something
// other than a number, is refused with an error naming what, rather than read as a scan that found
// less.
func TestAnAquaFileOfTheWrongShapeIsRefused(t *testing.T) {
	zlib := `{"format":"apk","name":"zlib","version":"1.0"}`
	for name, c := range map[string]struct{ body, want string }{
		"a list":       {`[]`, "not Aqua's scanner JSON"},
		"no resources": {`{"image":"web"}`, "not Aqua's scanner JSON"},
		"not JSON":     {`{`, "not Aqua's scanner JSON"},
		"bad rows":     {`{"image":"web","resources":[1]}`, "not Aqua's scanner JSON"},
		"no image":     {`{"resources":[]}`, "the file has no image, pull_name or digest, naming the image it scanned"},
		"no package": {aquaFileOf("web", "alpine", aquaResourceOf(`{"format":"apk"}`, aquaVulnOf("CVE-1", "high", "7.5", ""))),
			"a resource in web has no name or path"},
		"no id": {aquaFileOf("web", "alpine", aquaResourceOf(zlib, `{"aqua_severity":"high"}`)),
			"a vulnerability of zlib in web has no name, its CVE or advisory id"},
		"bad severity": {aquaFileOf("web", "alpine", aquaResourceOf(zlib, aquaVulnOf("CVE-1", "severe", "7.5", ""))),
			`aqua_severity "severe" of CVE-1 in zlib; Aqua rates a vulnerability critical, high, medium, low or negligible`},
		"no severity": {aquaFileOf("web", "alpine", aquaResourceOf(zlib, `{"name":"CVE-1"}`)),
			`aqua_severity "" of CVE-1 in zlib`},
		"bad score": {aquaFileOf("web", "alpine", aquaResourceOf(zlib, aquaVulnOf("CVE-1", "high", `"high"`, ""))),
			`aqua_score "high" of CVE-1 in zlib; Aqua writes a number from 0 to 10. Import the file scannercli wrote`},
	} {
		_, err := NewSARIFImport().Scan(context.Background(),
			plugin.FileTarget{Path: writeFile(t, c.body), Format: saga.ImportFormatAquaJSON}, nil)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
	// A resource with no vulnerabilities, a file of none, and one with only a summary, are scans that
	// found none.
	for _, body := range []string{
		aquaFileOf("web", "alpine", aquaResourceOf(`{"format":"apk"}`)),
		aquaFileOf("web", "alpine", ""),
		`{"image":"web","vulnerability_summary":{"total":0}}`,
	} {
		if rep := importAqua(t, writeFile(t, body)); len(rep.Results) != 0 {
			t.Errorf("%s: %d findings", body, len(rep.Results))
		}
	}
}
