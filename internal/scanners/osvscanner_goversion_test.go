package scanners

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// goModExcludingAnOlderText is a go.mod naming golang.org/x/text twice: an exclude of an older
// version on line 5, and the requirement itself on line 7, the line a finding about v0.3.0 belongs on.
const goModExcludingAnOlderText = `module example.com/app

go 1.22

exclude golang.org/x/text v0.1.0

require golang.org/x/text v0.3.0
`

// osvGoText is OSV-Scanner's JSON for path, holding golang.org/x/text 0.3.0 as OSV-Scanner writes a Go
// module's version, without its "v", with GO-2020-0015 fixed in 0.3.3, and lodash 4.17.20 with one
// advisory, whose version has no "v" to gain.
func osvGoText(path string) string {
	return `{"results": [{"source": {"path": "` + path + `", "type": "lockfile"}, "packages": [
	  {"package": {"name": "golang.org/x/text", "version": "0.3.0", "ecosystem": "Go", "purl": "pkg:golang/golang.org/x/text@0.3.0"},
	   "groups": [{"ids": ["GO-2020-0015"], "aliases": ["CVE-2020-14040", "GHSA-5rcv-m4m3-hfh7"], "max_severity": "7.5"}],
	   "vulnerabilities": [{"id": "GO-2020-0015", "aliases": ["CVE-2020-14040", "GHSA-5rcv-m4m3-hfh7"],
	     "summary": "Infinite loop when decoding some inputs in golang.org/x/text",
	     "affected": [{"package": {"ecosystem": "Go", "name": "golang.org/x/text"},
	       "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.3.3"}]}]}]}]},
	  {"package": {"name": "lodash", "version": "4.17.20", "ecosystem": "npm", "purl": "pkg:npm/lodash@4.17.20"},
	   "groups": [{"ids": ["GHSA-35jh-r3h4-6jhm"], "aliases": ["CVE-2021-23337"], "max_severity": "7.2"}],
	   "vulnerabilities": [{"id": "GHSA-35jh-r3h4-6jhm", "aliases": ["CVE-2021-23337"],
	     "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
	       "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]}]}]}]}`
}

// OSV-Scanner's Go module version is written as go.mod writes it, with its "v", in the package and
// its package URL, whether OSV-Scanner ran or its JSON was imported. The fix is kept without the "v",
// as Trivy and Grype write a Go fix, and the finding is placed at the requirement's line. lodash's
// version, from another ecosystem, is kept as written.
func TestOSVScannerWritesAGoModuleVersionAsGoModDoes(t *testing.T) {
	dir := checkoutWith(t, map[string]string{"go.mod": goModExcludingAnOlderText})
	ran, err := parseOSVScanner([]byte(osvGoText(filepath.Join(dir, "go.mod"))), dir, plugin.Config{})
	if err != nil {
		t.Fatal(err)
	}
	imported, err := NewSARIFImport().Scan(context.Background(), plugin.FileTarget{Path: writeFile(t, osvGoText("go.mod")),
		Format: saga.ImportFormatOSVScannerJSON, Repositories: []plugin.RepositoryTarget{{URL: dir}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]sarif.Package{
		"GO-2020-0015": {Name: "golang.org/x/text", Version: "v0.3.0", FixedVersion: "0.3.3",
			PURL: "pkg:golang/golang.org/x/text@v0.3.0", Ecosystem: "Go"},
		"GHSA-35jh-r3h4-6jhm": {Name: "lodash", Version: "4.17.20", FixedVersion: "4.17.21",
			PURL: "pkg:npm/lodash@4.17.20", Ecosystem: "npm"},
	}
	for how, rep := range map[string]sarif.Report{"ran": ran, "imported": imported} {
		if len(rep.Results) != len(want) {
			t.Fatalf("%s: %d findings, want %d", how, len(rep.Results), len(want))
		}
		for _, r := range rep.Results {
			if w := want[r.RuleID]; r.Package == nil || *r.Package != w {
				t.Errorf("%s %s: package %+v, want %+v", how, r.RuleID, r.Package, w)
			}
		}
		text := rep.Results[slices.IndexFunc(rep.Results, func(r sarif.Result) bool { return r.RuleID == "GO-2020-0015" })]
		if !strings.HasPrefix(text.Message, "golang.org/x/text v0.3.0 → 0.3.3: ") {
			t.Errorf("%s: message %q", how, text.Message)
		}
		if text.Location.URI != "go.mod" || text.Location.StartLine != 7 {
			t.Errorf("%s: at %s:%d, want go.mod:7, the requirement rather than the exclude", how, text.Location.URI, text.Location.StartLine)
		}
	}
}

// osvGoTextAt035 is OSV-Scanner's JSON for a go.mod requiring golang.org/x/text v0.3.5, holding the
// four advisories Trivy reports there in trivy-fs-gomod.json, each keyed on its Go advisory id with
// its CVE among the aliases, as OSV-Scanner groups them.
const osvGoTextAt035 = `{"results": [{"source": {"path": "go.mod", "type": "lockfile"}, "packages": [
  {"package": {"name": "golang.org/x/text", "version": "0.3.5", "ecosystem": "Go", "purl": "pkg:golang/golang.org/x/text@0.3.5"},
   "groups": [
     {"ids": ["GO-2021-0113"], "aliases": ["CVE-2021-38561", "GHSA-ppp9-7jff-5vj2"], "max_severity": "7.5"},
     {"ids": ["GO-2022-1059"], "aliases": ["CVE-2022-32149", "GHSA-69ch-w2m2-3vjp"], "max_severity": "7.5"},
     {"ids": ["GO-2026-5970"], "aliases": ["CVE-2026-56852"]},
     {"ids": ["GO-2026-6629"], "aliases": ["CVE-2026-56851"]}],
   "vulnerabilities": [
     {"id": "GO-2021-0113", "aliases": ["CVE-2021-38561", "GHSA-ppp9-7jff-5vj2"], "affected": [{"package": {"ecosystem": "Go", "name": "golang.org/x/text"},
       "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.3.7"}]}]}]},
     {"id": "GO-2022-1059", "aliases": ["CVE-2022-32149", "GHSA-69ch-w2m2-3vjp"], "affected": [{"package": {"ecosystem": "Go", "name": "golang.org/x/text"},
       "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.3.8"}]}]}]},
     {"id": "GO-2026-5970", "aliases": ["CVE-2026-56852"], "affected": [{"package": {"ecosystem": "Go", "name": "golang.org/x/text"},
       "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.39.0"}]}]}]},
     {"id": "GO-2026-6629", "aliases": ["CVE-2026-56851"], "affected": [{"package": {"ecosystem": "Go", "name": "golang.org/x/text"},
       "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.41.0"}]}]}]}]}]}]}`

// trivyFSReplaying is the trivy-fs scanner replaying out over every checkout.
func trivyFSReplaying(out []byte) plugin.Scanner {
	trivy := NewTrivyFS().(repoScanner)
	trivy.checkout, trivy.prewarm, trivy.cacheVersion, trivy.dataState = checkoutAt, nil, nil, nil
	trivy.runLogged = trivyFSRun(func(context.Context, string, []string) ([]byte, []byte, error) {
		return out, nil, nil
	})
	return trivy
}

// Trivy's run over a go.mod requiring golang.org/x/text v0.3.5, beside OSV-Scanner's JSON of the same
// go.mod, in two components of a repository each: each of the four advisories is counted once per
// component, under one scanner's copy with the other's behind it, though Trivy writes the version
// v0.3.5 and OSV-Scanner 0.3.5.
func TestOSVScannersGoFindingsBesideTrivysCountEachAdvisoryOnce(t *testing.T) {
	comps := map[string]importComponent{
		"api": {repos: []string{"api"}, file: writeFile(t, osvGoTextAt035), format: saga.ImportFormatOSVScannerJSON},
		"web": {repos: []string{"web"}, file: writeFile(t, osvGoTextAt035), format: saga.ImportFormatOSVScannerJSON},
	}
	res, _ := runBesideImport(t, controllers.NewSCA(), trivyFSReplaying(importTestdata(t, "trivy-fs-gomod.json")),
		saga.ControllerSettings{"enabled": true}, comps)
	if len(res.ScanErrors) > 0 {
		t.Fatalf("errors: %v", res.ScanErrors)
	}
	got := countedFlaws(t, res, "sca")
	for _, comp := range []string{"api", "web"} {
		if len(got[comp]) != 4 {
			t.Fatalf("%s: counted %+v, want each of the four advisories once", comp, got[comp])
		}
		for _, f := range got[comp] {
			if len(f.also) != 1 || (f.also[0] != "trivy" && f.also[0] != "imported osv-scanner (osv-scanner-json)") {
				t.Errorf("%s %s: also found by %v, want the other scanner's copy", comp, f.rule, f.also)
			}
		}
	}
}

// Grype's SARIF and OSV-Scanner's file, SARIF or JSON, imported into one component, each name
// golang.org/x/text at one version, Grype as v0.3.5 and OSV-Scanner as 0.3.5. The fix list holds one
// upgrade of it per component, over two components of a repository each.
func TestAGoModuleVersionFromGrypeAndOSVScannerIsOneUpgrade(t *testing.T) {
	grype := filepath.Join("testdata", "sarif-import", "grype-deps.sarif")
	for how, osv := range map[string]saga.Import{
		"OSV-Scanner's SARIF": {File: filepath.Join("testdata", "sarif-import", "osv-scanner-deps.sarif")},
		"OSV-Scanner's JSON":  {File: writeFile(t, osvGoTextAt035), Format: saga.ImportFormatOSVScannerJSON},
	} {
		comps := map[string]importComponent{
			"api": {repos: []string{"api"}, file: grype, more: []saga.Import{osv}},
			"web": {repos: []string{"web"}, file: grype, more: []saga.Import{osv}},
		}
		res, _ := runBesideImport(t, controllers.NewSCA(), trivyFSReplaying([]byte(`{"SchemaVersion": 2, "Results": []}`)),
			saga.ControllerSettings{"enabled": true}, comps)
		if len(res.ScanErrors) > 0 {
			t.Fatalf("%s: errors: %v", how, res.ScanErrors)
		}
		upgrades := map[string][]string{}
		for _, a := range report.ActionsFor(map[string]sarif.Report{"sca": res.Controls["sca"].Report}) {
			if strings.Contains(a.Title, "golang.org/x/text") {
				upgrades[a.Component] = append(upgrades[a.Component], a.Title)
			}
		}
		for _, comp := range []string{"api", "web"} {
			if len(upgrades[comp]) != 1 {
				t.Errorf("%s, %s: upgrades of golang.org/x/text %q, want one", how, comp, upgrades[comp])
			}
		}
	}
}
