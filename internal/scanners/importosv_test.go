package scanners

import (
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// testdata/sarif-import/osv-scanner-lodash.json is what OSV-Scanner 2.7.1 wrote, `osv-scanner scan
// --format json`, over a directory holding a package-lock.json pinning lodash 4.17.20 (lodashLock).
// It is unedited but for the lockfile's path, which OSV-Scanner writes absolute and the file holds
// relative to the directory scanned, package-lock.json.

// osvLodash is the path of the recorded OSV-Scanner JSON.
var osvLodash = filepath.Join("testdata", "sarif-import", "osv-scanner-lodash.json")

// osvAdvisory is what the recorded file says of one lodash advisory: the CVE it lists among the
// group's aliases, the group's max_severity, and the fix lodash's own range names.
type osvAdvisory struct {
	cve   string
	score float64
	fixed string
}

// osvLodashAdvisories are the four groups the recorded file lists for lodash 4.17.20.
var osvLodashAdvisories = map[string]osvAdvisory{
	"GHSA-29mw-wpgm-hmr9": {"CVE-2020-28500", 5.3, "4.17.21"},
	"GHSA-35jh-r3h4-6jhm": {"CVE-2021-23337", 7.2, "4.17.21"},
	"GHSA-r5fr-rjxr-66jc": {"CVE-2026-4800", 8.1, "4.18.0"},
	"GHSA-xxjr-mmjv-4gpg": {"CVE-2025-13465", 6.9, "4.17.23"},
}

// Each of the four advisories becomes one finding, keyed on the advisory OSV-Scanner matched, with
// the CVE it lists as an alias, lodash's own fixed version rather than lodash-es's or lodash-rails's,
// the package URL without the registry qualifier, the score OSV-Scanner gave the group, and its
// place: the lockfile, at the line of lodash's entry in the checkout.
func TestAnImportedOSVScannerJSONKeepsEachAdvisorysPackageFixAndCVE(t *testing.T) {
	dir := checkoutWith(t, map[string]string{"package-lock.json": lodashLock})
	ft := plugin.FileTarget{Path: osvLodash, Format: saga.ImportFormatOSVScannerJSON, Component: "app",
		Repositories: []plugin.RepositoryTarget{{URL: dir}}}
	rep, err := NewSARIFImport().Scan(context.Background(), ft, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != len(osvLodashAdvisories) {
		t.Fatalf("%d findings, want the file's four", len(rep.Results))
	}
	for _, got := range rep.Results {
		want, ok := osvLodashAdvisories[got.RuleID]
		if !ok {
			t.Errorf("finding under %q, which the file groups under no id", got.RuleID)
			continue
		}
		pkg := sarif.Package{Name: "lodash", Version: "4.17.20", FixedVersion: want.fixed, PURL: "pkg:npm/lodash@4.17.20", Ecosystem: "npm"}
		if got.Package == nil || *got.Package != pkg {
			t.Errorf("%s: package %+v, want %+v", got.RuleID, got.Package, pkg)
		}
		if !slices.Equal(got.Aliases, []string{want.cve}) {
			t.Errorf("%s: aliases %q, want the CVE the group lists, %s", got.RuleID, got.Aliases, want.cve)
		}
		if !got.HasScore || got.Score != want.score {
			t.Errorf("%s: score %v (%v), want the group's max_severity %v", got.RuleID, got.Score, got.HasScore, want.score)
		}
		if got.Location.URI != "package-lock.json" || got.Location.StartLine != 1 {
			t.Errorf("%s: at %s:%d, want lodash's entry in package-lock.json", got.RuleID, got.Location.URI, got.Location.StartLine)
		}
		if got.ImportFormat != saga.ImportFormatOSVScannerJSON || got.ImportedRepository == "" {
			t.Errorf("%s: format %q, repository %q", got.RuleID, got.ImportFormat, got.ImportedRepository)
		}
		if !strings.HasPrefix(got.Message, "lodash 4.17.20 → "+want.fixed+": ") {
			t.Errorf("%s: message %q", got.RuleID, got.Message)
		}
		if rule := rep.Rules[got.RuleID]; rule.HelpURI != "https://osv.dev/"+got.RuleID || rule.ShortDescription == "" {
			t.Errorf("%s: rule %+v", got.RuleID, rule)
		}
	}
	high := rep.Results[slices.IndexFunc(rep.Results, func(r sarif.Result) bool { return r.RuleID == "GHSA-35jh-r3h4-6jhm" })]
	if high.Severity("") != sarif.SeverityHigh || high.Level != sarif.LevelError {
		t.Errorf("GHSA-35jh-r3h4-6jhm at %s, level %s, want 7.2 read as high", high.Severity(""), high.Level)
	}
	high.Scanner = plugin.ImportScanner
	if got := high.Reporter(); got != "imported osv-scanner (osv-scanner-json)" {
		t.Errorf("reporter = %q", got)
	}
	for key, want := range map[string]string{
		"tool": "osv-scanner", "format": "osv-scanner-json", "severity": "CVSS score", "commit": notStated,
	} {
		if got := field(t, rep, key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
}

// An OSV-Scanner finding keyed on a GitHub advisory is raised by the CVE the group lists, whether
// that CVE is on KEV or scored above the EPSS threshold.
func TestAnImportedOSVScannerFindingIsRaisedByItsCVE(t *testing.T) {
	rep, err := NewSARIFImport().Scan(context.Background(), plugin.FileTarget{Path: osvLodash, Format: saga.ImportFormatOSVScannerJSON,
		Repositories: []plugin.RepositoryTarget{{URL: "https://github.com/acme/web"}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(rep.Results, func(r sarif.Result) bool { return r.RuleID == "GHSA-35jh-r3h4-6jhm" })
	if i < 0 {
		t.Fatalf("no GHSA-35jh-r3h4-6jhm in %d findings", len(rep.Results))
	}
	checkRaisedByCVE(t, rep.Results[i], "CVE-2021-23337")
}

// osvAt is the recorded file with its lockfile's path replaced by path, as OSV-Scanner writes it,
// absolute.
func osvAt(t *testing.T, path string) string {
	t.Helper()
	quoted, err := json.Marshal(path)
	if err != nil {
		t.Fatal(err)
	}
	return writeFile(t, strings.Replace(string(importTestdata(t, "osv-scanner-lodash.json")),
		`"path": "package-lock.json"`, `"path": `+string(quoted), 1))
}

// OSV-Scanner writes the absolute path of the file it read. Inside the component's local checkout it
// is made relative to it, as a SARIF file's is; anywhere else it is kept as written, still counted,
// and listed as a file no checkout holds.
func TestAnImportedOSVScannerPathIsReadAgainstTheCheckout(t *testing.T) {
	dir := checkoutWith(t, map[string]string{"package-lock.json": lodashLock})
	for _, c := range []struct {
		name, path, want string
		unread           bool
	}{
		{"inside the checkout", filepath.Join(dir, "package-lock.json"), "package-lock.json", false},
		{"outside it", "/elsewhere/app/package-lock.json", "/elsewhere/app/package-lock.json", true},
	} {
		rep, err := NewSARIFImport().Scan(context.Background(), plugin.FileTarget{Path: osvAt(t, c.path),
			Format: saga.ImportFormatOSVScannerJSON, Repositories: []plugin.RepositoryTarget{{URL: dir}}}, nil)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if len(rep.Results) != len(osvLodashAdvisories) {
			t.Fatalf("%s: %d findings, want all four counted", c.name, len(rep.Results))
		}
		for _, r := range rep.Results {
			if r.Location.URI != c.want {
				t.Errorf("%s: %s at %q, want %q", c.name, r.RuleID, r.Location.URI, c.want)
			}
		}
		unread := slices.ContainsFunc(rep.Inputs, func(in sarif.Input) bool { return in.Path == c.path && in.Unread == outsideCheckout })
		if unread != c.unread {
			t.Errorf("%s: listed as unread %v, want %v (inputs %+v)", c.name, unread, c.unread, rep.Inputs)
		}
	}
}

// Without a max_severity a finding is read at its advisory's own rating, the highest the grouped
// advisories give, and without either as not scored yet, at high. A database_specific.severity that is not a word, or
// is absent, rates nothing and refuses nothing. An advisory no group lists is a finding of its own.
func TestAnImportedOSVScannerFindingWithoutAScoreIsReadAtItsAdvisorysRating(t *testing.T) {
	doc := `{"results": [{"source": {"path": "go.mod", "type": "lockfile"}, "packages": [{
	  "package": {"name": "golang.org/x/text", "version": "0.3.5", "ecosystem": "Go", "purl": "pkg:golang/golang.org/x/text@0.3.5"},
	  "groups": [
	    {"ids": ["GHSA-aaaa-bbbb-cccc", "GO-2099-0001"], "aliases": ["CVE-2099-0001"], "max_severity": ""},
	    {"ids": ["GO-2099-0002"]}
	  ],
	  "vulnerabilities": [
	    {"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2099-0001"], "database_specific": {"severity": "MODERATE"}},
	    {"id": "GO-2099-0001", "aliases": ["GHSA-aaaa-bbbb-cccc"], "database_specific": {"severity": "CRITICAL"}},
	    {"id": "GO-2099-0002", "database_specific": {"severity": {"score": 5}}},
	    {"id": "GHSA-dddd-eeee-ffff", "aliases": ["CVE-2099-0003"], "database_specific": {"severity": "LOW"}}
	  ]}]}]}`
	rep, err := NewSARIFImport().Scan(context.Background(), plugin.FileTarget{Path: writeFile(t, doc),
		Format: saga.ImportFormatOSVScannerJSON}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		severity sarif.Severity
		aliases  []string
		rated    bool
	}{
		"GHSA-aaaa-bbbb-cccc": {sarif.SeverityCritical, []string{"GO-2099-0001", "CVE-2099-0001"}, true},
		"GO-2099-0002":        {sarif.SeverityHigh, nil, true},
		"GHSA-dddd-eeee-ffff": {sarif.SeverityLow, []string{"CVE-2099-0003"}, true},
	}
	if len(rep.Results) != len(want) {
		t.Fatalf("%d findings, want %d", len(rep.Results), len(want))
	}
	for _, r := range rep.Results {
		w := want[r.RuleID]
		if r.HasScore || r.Severity("") != w.severity || !slices.Equal(r.Aliases, w.aliases) || (r.Rating != nil) != w.rated {
			t.Errorf("%s: severity %s, score %v, rating %+v, aliases %q, want %s, aliases %q",
				r.RuleID, r.Severity(""), r.HasScore, r.Rating, r.Aliases, w.severity, w.aliases)
		}
	}
	if r := rep.Results[0]; r.Rating == nil || r.Rating.Detail != "severity CRITICAL" {
		t.Errorf("rating %+v, want the GO advisory's CRITICAL, the higher of the group's two", r.Rating)
	}
	if got, want := field(t, rep, "severity"), "the advisory's severity for 2, OSV-Scanner states none, not scored yet, read as high for 1"; got != want {
		t.Errorf("severity = %q, want %q", got, want)
	}
}

// osvPackageOf decodes one package entry as OSV-Scanner writes it.
func osvPackageOf(t *testing.T, doc string) osvPackage {
	t.Helper()
	var p osvPackage
	if err := json.Unmarshal([]byte(doc), &p); err != nil {
		t.Fatal(err)
	}
	return p
}

// The fix is the one closing the range of the package's own entries that holds the installed
// version; a range closed by last_affected, or by nothing, holds a version no release fixes.
func TestOSVFixedVersionIsTheFixOfTheRangeHoldingTheInstalledVersion(t *testing.T) {
	affected := `"affected": [
	  {"package": {"ecosystem": "npm", "name": "widget"}, "ranges": [
	    {"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.3"}]},
	    {"type": "SEMVER", "events": [{"introduced": "2.0.0"}, {"fixed": "2.0.5"}, {"introduced": "3.0.0"}, {"last_affected": "3.1.0"}]},
	    {"type": "SEMVER", "events": [{"introduced": "4.0.0"}]},
	    {"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "abc123"}]}]},
	  {"package": {"ecosystem": "npm", "name": "widget-es"}, "ranges": [
	    {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}]}]`
	for _, c := range []struct{ installed, want string }{
		{"1.1.0", "1.2.3"},
		{"2.0.1", "2.0.5"},
		{"3.0.5", ""},
		{"4.1.0", ""},
		// Held by no range: the lowest fix above it.
		{"0.5.0", "1.2.3"},
	} {
		p := osvPackageOf(t, `{"package": {"name": "widget", "version": "`+c.installed+`", "ecosystem": "npm",
		  "purl": "pkg:npm/widget@`+c.installed+`"}, "vulnerabilities": [{"id": "GHSA-1", `+affected+`}]}`)
		if got := osvFixedVersion(p, p.Vulnerabilities); got != c.want {
			t.Errorf("widget %s: fixed %q, want %q", c.installed, got, c.want)
		}
	}
}

// Two advisories grouped as one vulnerability that name two fixes give the later, which fixes it by
// both; versions that cannot be ordered give every fix named; and a PyPI name matches its other
// spellings.
func TestOSVFixedVersionAcrossAdvisoriesAndEcosystems(t *testing.T) {
	two := osvPackageOf(t, `{"package": {"name": "widget", "version": "1.0.0", "ecosystem": "npm"}, "vulnerabilities": [
	  {"id": "GHSA-1", "affected": [{"package": {"ecosystem": "npm", "name": "widget"}, "ranges": [
	    {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}]}]},
	  {"id": "GHSA-2", "affected": [{"package": {"ecosystem": "npm", "name": "widget"}, "ranges": [
	    {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.5"}]}]}]}]}`)
	if got := osvFixedVersion(two, two.Vulnerabilities); got != "1.2.5" {
		t.Errorf("two advisories: fixed %q, want the later 1.2.5", got)
	}

	unordered := osvPackageOf(t, `{"package": {"name": "thing", "version": "r7", "ecosystem": "Nowhere"}, "vulnerabilities": [
	  {"id": "X-1", "affected": [{"package": {"ecosystem": "Nowhere", "name": "thing"}, "ranges": [
	    {"type": "ECOSYSTEM", "events": [{"introduced": "r1"}, {"fixed": "r8"}]},
	    {"type": "ECOSYSTEM", "events": [{"introduced": "s1"}, {"fixed": "s3"}]}]}]},
	  {"id": "X-2", "affected": [{"package": {"ecosystem": "Nowhere", "name": "thing"}, "ranges": [
	    {"type": "ECOSYSTEM", "events": [{"introduced": "r1"}, {"fixed": "r9"}]}]}]}]}`)
	if got := osvFixedVersion(unordered, unordered.Vulnerabilities[:1]); got != "r8, s3" {
		t.Errorf("unordered, two ranges: fixed %q, want both", got)
	}
	if got := osvFixedVersion(unordered, unordered.Vulnerabilities[1:]); got != "r9" {
		t.Errorf("unordered, one range: fixed %q, want its fix", got)
	}
	if got := osvFixedVersion(unordered, unordered.Vulnerabilities); got != "r8, s3, r9" {
		t.Errorf("unordered, two advisories: fixed %q, want every fix", got)
	}

	pypi := osvPackageOf(t, `{"package": {"name": "zope-interface", "version": "4.0.0", "ecosystem": "PyPI",
	  "purl": "pkg:pypi/zope-interface@4.0.0"}, "vulnerabilities": [
	  {"id": "PYSEC-1", "affected": [{"package": {"ecosystem": "PyPI", "name": "Zope.Interface"}, "ranges": [
	    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.0.0"}]}]}]}]}`)
	if got := osvFixedVersion(pypi, pypi.Vulnerabilities); got != "5.0.0" {
		t.Errorf("PyPI: fixed %q, want 5.0.0 from Zope.Interface's range", got)
	}
}

// The registry qualifier OSV-Scanner adds is dropped, so the package URL is the one other scanners
// write; any other qualifier names the artifact and stays.
func TestOSVPURLDropsOnlyTheSourceQualifier(t *testing.T) {
	for in, want := range map[string]string{
		"pkg:npm/lodash@4.17.20?source=PUBLIC_REGISTRY":                        "pkg:npm/lodash@4.17.20",
		"pkg:npm/lodash@4.17.20":                                               "pkg:npm/lodash@4.17.20",
		"pkg:maven/org.acme/lib@1.0?classifier=sources&source=PUBLIC_REGISTRY": "pkg:maven/org.acme/lib@1.0?classifier=sources",
		"pkg:npm/odd@1.0?%zz":                                                  "pkg:npm/odd@1.0?%zz",
		"":                                                                     "",
	} {
		if got := osvPURL(in); got != want {
			t.Errorf("osvPURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// A file that is not OSV-Scanner's JSON is refused rather than read as a clean scan, and so is one
// with a container image's or a git repository's results, which no file in the repository places. A
// clean scan, which lists no result, is a clean result.
func TestAnOSVScannerImportRefusesAFileItCannotPlace(t *testing.T) {
	notOSV := "not OSV-Scanner JSON. Write it with osv-scanner scan --format json"
	for _, c := range []struct{ name, body, want string }{
		{"SARIF", exampleLog(scoredResult, ""), notOSV},
		{"Trivy JSON", `{"SchemaVersion":2,"Results":[]}`, notOSV},
		{"Grype JSON", `{"matches":[],"descriptor":{"name":"grype"}}`, notOSV},
		{"not JSON", "{not json", notOSV},
		{"no results", `{"results": null}`, notOSV},
		{"mistyped results", `{"results": [{"source": "package-lock.json"}]}`, notOSV},
		{"a result naming no source type", `{"results": [{"source": {"path": "package-lock.json"}, "packages": []}]}`, notOSV},
		{"a group naming no id", `{"results": [{"source": {"path": "go.mod", "type": "lockfile"},
		  "packages": [{"package": {"name": "x", "version": "1"}, "groups": [{"ids": []}]}]}]}`, notOSV},
		{"an image", `{"results": [{"source": {"path": "/usr/lib/node_modules/x/package.json", "type": "docker"}}]}`,
			"docker source; Draugr reads only lockfiles and SBOMs. Scan the directory"},
		{"a git repository", `{"results": [{"source": {"path": "/src/vendor/lib", "type": "git"}}]}`,
			"git source; Draugr reads only lockfiles and SBOMs. Scan the directory"},
	} {
		_, err := NewSARIFImport().Scan(context.Background(), plugin.FileTarget{Path: writeFile(t, c.body),
			Format: saga.ImportFormatOSVScannerJSON}, nil)
		if err == nil || !strings.HasSuffix(err.Error(), ": "+c.want) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
			continue
		}
		if len(c.want) > 80 {
			t.Errorf("%s: the errors block's reason %q is %d characters", c.name, c.want, len(c.want))
		}
	}
	for _, clean := range []string{`{"results": []}`, `{"results": [{"source": {"path": "sbom.cdx.json", "type": "sbom"}, "packages": []}]}`} {
		rep, err := NewSARIFImport().Scan(context.Background(), plugin.FileTarget{Path: writeFile(t, clean),
			Format: saga.ImportFormatOSVScannerJSON}, nil)
		if err != nil || len(rep.Results) != 0 || field(t, rep, "tool") != "osv-scanner" || field(t, rep, "severity") != "no findings" {
			t.Errorf("a clean scan %s: %v, %+v", clean, err, rep.Provenance)
		}
	}
}

// An OSV-Scanner JSON is placed and scoped by the component's repositories: with one, its paths:
// leave out what lies outside them; with two, its findings are in neither and are counted as not
// scoped.
func TestAnImportedOSVScannerJSONIsScopedByTheComponentsRepositories(t *testing.T) {
	ft := plugin.FileTarget{Path: osvLodash, Format: saga.ImportFormatOSVScannerJSON,
		Repositories: []plugin.RepositoryTarget{{URL: "https://github.com/acme/api", Paths: []string{"web"}}}}
	rep, err := NewSARIFImport().Scan(context.Background(), ft, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 0 || field(t, rep, "left out") != "4 findings outside paths, not counted" {
		t.Errorf("one repository scoped to web/: %d findings kept, left out %q", len(rep.Results), field(t, rep, "left out"))
	}
	ft.Repositories = append(ft.Repositories, plugin.RepositoryTarget{URL: "https://github.com/acme/web", Paths: []string{"web"}})
	rep, err = NewSARIFImport().Scan(context.Background(), ft, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := "4 findings, not in any one repository, so paths and ignore were not applied. " +
		"Move the osv-scanner-json import to a component with one repository"
	if len(rep.Results) != 4 || field(t, rep, "not scoped") != want {
		t.Errorf("two repositories: %d findings, not scoped %q", len(rep.Results), field(t, rep, "not scoped"))
	}
}

// trivyLodash is a Trivy JSON report in the shape `trivy fs --format json` writes, holding the one
// field set trivy-fs reads for a finding: CVE-2021-23337 in lodash 4.17.20 in package-lock.json.
// Built for this test rather than recorded, and listing no GitHub advisory id, so the two copies can
// meet only through the CVE OSV-Scanner lists.
const trivyLodash = `{"SchemaVersion": 2, "ArtifactName": ".", "ArtifactType": "filesystem", "Results": [{
  "Target": "package-lock.json", "Class": "lang-pkgs", "Type": "npm",
  "Vulnerabilities": [{"VulnerabilityID": "CVE-2021-23337", "PkgName": "lodash", "InstalledVersion": "4.17.20",
    "FixedVersion": "4.17.21", "Status": "fixed", "PkgIdentifier": {"PURL": "pkg:npm/lodash@4.17.20"},
    "Severity": "HIGH", "Title": "lodash: command injection via template", "CVSS": {"ghsa": {"V3Score": 7.2}}}]}]}`

// OSV-Scanner's JSON imported into sca beside trivy-fs over the same package-lock.json, in two
// components of a repository each: GHSA-35jh-r3h4-6jhm, which OSV-Scanner lists with CVE-2021-23337,
// is counted once with trivy-fs's finding of that CVE, each naming the other, and the three advisories
// only the file reports are counted as they are.
func TestAnImportedOSVScannerJSONBesideTrivyFSCountsTheCVEOnce(t *testing.T) {
	trivy := NewTrivyFS().(repoScanner)
	trivy.checkout, trivy.prewarm, trivy.cacheVersion, trivy.dataState = checkoutAt, nil, nil, nil
	trivy.runLogged = trivyFSRun(func(context.Context, string, []string) ([]byte, []byte, error) {
		return []byte(trivyLodash), nil, nil
	})
	comps := twoComponents("osv-scanner-lodash.json")
	for name, c := range comps {
		c.format = saga.ImportFormatOSVScannerJSON
		comps[name] = c
	}
	res, _ := runBesideImport(t, controllers.NewSCA(), trivy, saga.ControllerSettings{"enabled": true}, comps)
	if len(res.ScanErrors) > 0 {
		t.Fatalf("errors: %v", res.ScanErrors)
	}
	got := countedFlaws(t, res, "sca")
	for _, comp := range []string{"api", "web"} {
		if len(got[comp]) != len(osvLodashAdvisories) {
			t.Fatalf("%s: counted %+v, want each of the file's four advisories once", comp, got[comp])
		}
		for _, f := range got[comp] {
			switch f.rule {
			case "CVE-2021-23337", "GHSA-35jh-r3h4-6jhm":
				if len(f.also) != 1 || (f.also[0] != "trivy" && f.also[0] != "imported osv-scanner (osv-scanner-json)") {
					t.Errorf("%s %s: also found by %v, want the other scanner's copy", comp, f.rule, f.also)
				}
			default:
				if _, ok := osvLodashAdvisories[f.rule]; !ok || len(f.also) != 0 {
					t.Errorf("%s %s: also found by %v, want an advisory only the file reports", comp, f.rule, f.also)
				}
			}
		}
	}
}
