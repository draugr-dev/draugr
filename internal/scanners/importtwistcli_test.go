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

// twistcliFinding is the finding of rule among results, failing the test where there is not exactly
// one.
func twistcliFinding(t *testing.T, results []sarif.Result, rule string) sarif.Result {
	t.Helper()
	var found []sarif.Result
	for _, r := range results {
		if r.RuleID == rule {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%s: %d findings", rule, len(found))
	}
	return found[0]
}

// importTwistcli reads file as twistcli-json into images, in the component of repos.
func importTwistcli(t *testing.T, file string, repos ...plugin.RepositoryTarget) sarif.Report {
	t.Helper()
	rep, err := NewSARIFImport().Scan(context.Background(), plugin.FileTarget{Path: file,
		Format: saga.ImportFormatTwistcliJSON, Control: "images", Repositories: repos}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// A real twistcli file of an image with an application's package reads as Draugr's image scan reads
// one: the vulnerability under its CVE, at the image, with the package, installed version and every
// version the status names as fixed, rated by its CVSS score. The package's path in the image is in
// the detail, and since twistcli names no ecosystem for it, every fixed version is kept.
func TestTwistcliFileReadsAsDraugrsImageScanDoes(t *testing.T) {
	rep := importTwistcli(t, veracodeFixture("twistcli-packagename.json"))
	if len(rep.Results) != 1 {
		t.Fatalf("%d findings, want 1", len(rep.Results))
	}
	r := rep.Results[0]
	if r.Tool != twistcliTool || r.RuleID != "CVE-2025-48913" || r.Location.URI != "some-docker-image" ||
		r.Image != "some-docker-image" || r.OperatingSystem != "" || !r.HasScore || r.Score != 9.8 ||
		r.Severity("") != sarif.SeverityCritical || r.Level != sarif.LevelError {
		t.Errorf("finding = %+v", r)
	}
	p := r.Package
	if p.Name != "org.apache.cxf_cxf-core" || p.Version != "3.5.11" || p.FixedVersion != "4.1.3, 4.0.9, 3.6.8" ||
		p.Ecosystem != "" || p.PURL != "" {
		t.Errorf("package = %+v", p)
	}
	if !strings.HasPrefix(r.Detail, "If untrusted users are allowed to configure JMS") ||
		!strings.HasSuffix(r.Detail, " Found at /opt/vendor/component-kit/libs/cxf-core-3.5.11.jar.") ||
		strings.Contains(r.Detail, "twistcli's status") {
		t.Errorf("detail = %q", r.Detail)
	}
	if r.Message != "org.apache.cxf_cxf-core 3.5.11 → 4.1.3, 4.0.9, 3.6.8" {
		t.Errorf("message = %q", r.Message)
	}
	if rule := rep.Rules["CVE-2025-48913"]; rule.HelpURI != "https://nvd.nist.gov/vuln/detail/CVE-2025-48913" {
		t.Errorf("rule = %+v", rule)
	}
	if got := provenanceField(rep, "severity"); got != "CVSS score" {
		t.Errorf("severity source = %q", got)
	}
}

// A package twistcli names with the binaries built from it is the operating system's: named by its
// source package, in the distro's ecosystem, with the image's operating system and the binaries in the
// detail. One it gives no path and no type for, such as pycrypto, is named as written with no
// ecosystem, since twistcli lists language packages that way too. A file that names no image
// reference is located at the image's ID. A score less severe than twistcli's severity is not taken,
// and one more severe is.
func TestTwistcliOperatingSystemPackagesAreTheDistros(t *testing.T) {
	rep := importTwistcli(t, veracodeFixture("twistcli-many-vulns.json"))
	if len(rep.Results) != 5 {
		t.Fatalf("%d findings, want 5", len(rep.Results))
	}
	const id = "sha256:f4c0503d26c8da0a04e6190c9d4f2a30f38958852b9fb80bcd2b819a7571e7f7"
	for _, r := range rep.Results {
		if r.Location.URI != id || r.Image != id || r.Package.FixedVersion != "" ||
			!strings.Contains(r.Message, "no fix available") || strings.Contains(r.Detail, "twistcli's status") {
			t.Errorf("%s: at %q, image %q, package %+v, message %q, detail %q", r.RuleID, r.Location.URI, r.Image,
				r.Package, r.Message, r.Detail)
		}
	}
	for _, c := range []struct {
		rule, name, version, ecosystem, os, binaries string
		severity                                     sarif.Severity
		scored                                       bool
	}{
		{"CVE-2018-6485", "glibc", "2.24-11+deb9u4", "debian", "Debian GNU/Linux 9 (stretch)",
			"libc6, multiarch-support, libc-bin", sarif.SeverityCritical, true},
		// Low to twistcli, high by its score of 7.5.
		{"CVE-2018-9234", "gnupg2", "2.1.18-8~deb9u4", "debian", "Debian GNU/Linux 9 (stretch)", "gpgv",
			sarif.SeverityHigh, true},
		{"CVE-2019-6465", "bind9", "1:9.10.3.dfsg.P4-12.3+deb9u4", "debian", "Debian GNU/Linux 9 (stretch)",
			"libisccfg140, dnsutils, libisccc140, libbind9-140, liblwres141, libdns162, libisc160, bind9-host",
			sarif.SeverityLow, false},
		{"CVE-2013-7459", "pycrypto", "2.6.1", "", "", "", sarif.SeverityCritical, true},
	} {
		r := twistcliFinding(t, rep.Results, c.rule)
		if r.Package.Name != c.name || r.Package.Version != c.version || r.Package.Ecosystem != c.ecosystem ||
			r.OperatingSystem != c.os || r.Severity("") != c.severity || r.HasScore != c.scored {
			t.Errorf("%s = %+v, os %q, severity %s, scored %v", c.rule, r.Package, r.OperatingSystem,
				r.Severity(""), r.HasScore)
		}
		if has := strings.Contains(r.Detail, "Installed as "+c.binaries+"."); has != (c.binaries != "") {
			t.Errorf("%s: detail %q", c.rule, r.Detail)
		}
	}
	if got := provenanceField(rep, "severity"); got != "CVSS score for 4, twistcli's severity for 1" {
		t.Errorf("severity source = %q", got)
	}
}

// A file with no CVSS score is rated by twistcli's severity; a status of open is no fix, and a fixed
// version of a package whose ecosystem twistcli does not state is kept as written.
func TestTwistcliWithoutAScoreIsRatedBySeverity(t *testing.T) {
	rep := importTwistcli(t, veracodeFixture("twistcli-no-cvss.json"))
	if len(rep.Results) != 2 {
		t.Fatalf("%d findings, want 2", len(rep.Results))
	}
	r := twistcliFinding(t, rep.Results, "CVE-2025-6297")
	if r.Package.Name != "dpkg" || r.Package.FixedVersion != "" || r.HasScore || r.Severity("") != sarif.SeverityLow ||
		r.Level != sarif.LevelNote || r.Detail != "" || r.Image != "somename:v8.11" {
		t.Errorf("dpkg = %+v, detail %q", r, r.Detail)
	}
	r = twistcliFinding(t, rep.Results, "CVE-2025-1390")
	if r.Package.Name != "libcap2" || r.Package.Version != "1:2.66-4" || r.Package.FixedVersion != "1:2.66-4+deb12u1" ||
		strings.Contains(r.Detail, "twistcli's status") {
		t.Errorf("libcap2 = %+v, detail %q", r.Package, r.Detail)
	}
	if got := provenanceField(rep, "severity"); got != "twistcli's severity" {
		t.Errorf("severity source = %q", got)
	}
}

// provenanceField is the value of the import's provenance field key.
func provenanceField(rep sarif.Report, key string) string {
	for _, p := range rep.Provenance {
		for _, f := range p.Fields {
			if f.Key == key {
				return f.Value
			}
		}
	}
	return ""
}

// twistcliFile is a hand-written file of one image, named name, of distro, listing packages, with
// vulns.
func twistcliFileOf(name, distro, packages, vulns string) string {
	return fmt.Sprintf(`{"results":[{"id":"sha256:1","name":%q,"distro":%q,"packages":[%s],"vulnerabilities":[%s]}]}`,
		name, distro, packages, vulns)
}

// twistcliVuln is a hand-written vulnerability id of pkg at version, rated severity and cvss, with
// status.
func twistcliVuln(id, pkg, version, severity, cvss, status string) string {
	return fmt.Sprintf(`{"id":%q,"packageName":%q,"packageVersion":%q,"severity":%q,"cvss":%s,"status":%q}`,
		id, pkg, version, severity, cvss, status)
}

// Shapes the real files lack, each hand-written: an operating-system package's fixes are ordered by
// its distro, so an older release line is left out, and a status naming only older ones, or in words
// that are not "fixed in", stays in the detail; the packages list makes a package the operating
// system's or a language ecosystem's; important is high; a score less severe than the severity is not
// taken, and a score may be a string; and the same vulnerability of a package listed twice is one
// finding, rated by the worse copy.
func TestTwistcliShapesTheRealFilesLack(t *testing.T) {
	vulns := strings.Join([]string{
		twistcliVuln("CVE-2024-1", "openssl (used in libssl3)", "3.0.1-1", "important", `"7.5"`,
			"fixed in 3.0.0-9, 3.0.2-1, 3.1.0-1"),
		twistcliVuln("CVE-2024-2", "openssl (used in libssl3)", "3.0.1-1", "moderate", "null", "fixed in 3.0.0-9"),
		twistcliVuln("CVE-2024-3", "zlib", "1.2.13", "critical", "5.3", "will not fix"),
		twistcliVuln("CVE-2024-4", "requests", "2.30.0", "medium", `""`, "fixed in 2.31.0"),
		twistcliVuln("CVE-2024-5", "zlib", "1.2.13", "low", "2.0", "open"),
		twistcliVuln("CVE-2024-5", "zlib", "1.2.13", "high", "8.0", "open"),
	}, ",")
	packages := `{"type":"os","name":"zlib","version":"1.2.13"},{"type":"python","name":"requests","version":"2.30.0"}`
	rep := importTwistcli(t, writeFile(t, twistcliFileOf("ghcr.io/acme/web:1.0", "Ubuntu 22.04.4 LTS", packages, vulns)))
	if len(rep.Results) != 5 {
		t.Fatalf("%d findings, want 5", len(rep.Results))
	}
	for _, c := range []struct {
		rule, name, ecosystem, fixed, status string
		severity                             sarif.Severity
		scored, os                           bool
	}{
		{"CVE-2024-1", "openssl", "ubuntu", "3.0.2-1, 3.1.0-1", "", sarif.SeverityHigh, true, true},
		{"CVE-2024-2", "openssl", "ubuntu", "", "fixed in 3.0.0-9", sarif.SeverityMedium, false, true},
		{"CVE-2024-3", "zlib", "ubuntu", "", "will not fix", sarif.SeverityCritical, false, true},
		{"CVE-2024-4", "requests", "python", "2.31.0", "", sarif.SeverityMedium, false, false},
		{"CVE-2024-5", "zlib", "ubuntu", "", "", sarif.SeverityHigh, true, true},
	} {
		r := twistcliFinding(t, rep.Results, c.rule)
		if r.Package.Name != c.name || r.Package.Ecosystem != c.ecosystem || r.Package.FixedVersion != c.fixed ||
			r.Severity("") != c.severity || r.HasScore != c.scored || (r.OperatingSystem == "Ubuntu 22.04.4 LTS") != c.os {
			t.Errorf("%s = %+v, severity %s, scored %v, os %q", c.rule, r.Package, r.Severity(""), r.HasScore,
				r.OperatingSystem)
		}
		if has := strings.Contains(r.Detail, "twistcli's status: "+c.status+"."); has != (c.status != "") ||
			(c.status == "" && strings.Contains(r.Detail, "twistcli's status")) {
			t.Errorf("%s: detail %q", c.rule, r.Detail)
		}
	}
}

// An image finding's location is the image, which names nothing in a checkout, so it is placed in no
// repository: a component's paths: leave it in, and it is not reported as naming a file the checkout
// lacks.
func TestTwistcliFindingsAreNotPlacedInACheckout(t *testing.T) {
	repo := t.TempDir()
	rep := importTwistcli(t, veracodeFixture("twistcli-packagename.json"),
		plugin.RepositoryTarget{URL: repo, Paths: []string{"services/api"}})
	if len(rep.Results) != 1 || rep.Results[0].ImportedRepository != "" {
		t.Fatalf("findings = %+v", rep.Results)
	}
	if len(rep.Inputs) != 0 {
		t.Errorf("inputs = %+v", rep.Inputs)
	}
}

// A file that is not the JSON twistcli writes, or whose image or vulnerability lacks what places and
// names it, or that rates one outside twistcli's severities or scores one with something other than
// a number, is refused with an error naming what, rather than read as a scan that found less.
func TestATwistcliFileOfTheWrongShapeIsRefused(t *testing.T) {
	ok := twistcliVuln("CVE-1", "zlib", "1.0", "high", "7.5", "open")
	for name, c := range map[string]struct{ body, want string }{
		"a list":     {`[]`, "not twistcli's JSON"},
		"no results": {`{"consoleURL":"https://console.test"}`, "not twistcli's JSON"},
		"not JSON":   {`{`, "not twistcli's JSON"},
		"bad rows":   {`{"results":[1]}`, "not twistcli's JSON"},
		"no image":   {`{"results":[{"vulnerabilities":[]}]}`, "an image has no id"},
		"no id": {twistcliFileOf("web", "", "", `{"packageName":"zlib","severity":"high"}`),
			"a vulnerability in web has no id"},
		"no package": {twistcliFileOf("web", "", "", `{"id":"CVE-1","severity":"high"}`),
			"vulnerability CVE-1 in web has no packageName"},
		"bad severity": {twistcliFileOf("web", "", "", twistcliVuln("CVE-1", "zlib", "1.0", "severe", "7.5", "")),
			`severity "severe" of CVE-1 in zlib; twistcli rates a vulnerability critical, high, medium or low`},
		"bad score": {twistcliFileOf("web", "", "", twistcliVuln("CVE-1", "zlib", "1.0", "high", `"high"`, "")),
			`cvss "high" of CVE-1 in zlib; twistcli writes a number from 0 to 10. Import the file twistcli wrote`},
		"score past 10": {twistcliFileOf("web", "", "", twistcliVuln("CVE-1", "zlib", "1.0", "high", "11", "")),
			"cvss 11 of CVE-1 in zlib; twistcli writes a number from 0 to 10"},
	} {
		_, err := NewSARIFImport().Scan(context.Background(),
			plugin.FileTarget{Path: writeFile(t, c.body), Format: saga.ImportFormatTwistcliJSON}, nil)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
	// An image with no vulnerabilities, and a file of no images, are scans that found none.
	for _, body := range []string{`{"results":[]}`, twistcliFileOf("web", "", "", "")} {
		if rep := importTwistcli(t, writeFile(t, body)); len(rep.Results) != 0 {
			t.Errorf("%s: %d findings", body, len(rep.Results))
		}
	}
	if rep := importTwistcli(t, writeFile(t, twistcliFileOf("web", "", "", ok))); len(rep.Results) != 1 {
		t.Errorf("one vulnerability: %d findings", len(rep.Results))
	}
}
