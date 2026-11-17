package scanners

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// The Grype files these tests import are testdata/sarif-import/grype-dir-lodash.*, the SARIF and the
// JSON one run of Grype 0.121.0 wrote, `grype dir:. -o sarif=… -o json=…`, over a package-lock.json
// requiring lodash 4.17.20. The JSON is trimmed of its descriptor's configuration and database
// status, which name directories on the machine that ran it, and of each advisory's list of
// reference URLs, which neither report reads where the advisory has a dataSource.

// lodashLock is the package-lock.json Grype read for grype-dir-lodash.*.
const lodashLock = `{"name":"importdemo","lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.20"}}}`

// grypeLodash is the path of the recorded Grype JSON.
var grypeLodash = filepath.Join("testdata", "sarif-import", "grype-dir-lodash.json")

// Grype's JSON read through the import is, finding by finding and rule by rule, what grype-fs's
// parser makes of the SARIF and the JSON the same run wrote: the advisory, the package and its fixed
// version, the package URL, the score and level Grype gave it, its location and fingerprint, and the
// CVE Grype relates to it. The report names the format beside the tool.
func TestAnImportedGrypeJSONIsTheFindingGrypeFSMakesOfIt(t *testing.T) {
	dir := checkoutWith(t, map[string]string{"package-lock.json": lodashLock})
	native, err := parseGrypeRepoSARIF(grypeOutput(string(importTestdata(t, "grype-dir-lodash.sarif")),
		string(importTestdata(t, "grype-dir-lodash.json"))), dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	ft := plugin.FileTarget{Path: grypeLodash, Format: saga.ImportFormatGrypeJSON, Component: "app",
		Repositories: []plugin.RepositoryTarget{{URL: dir}}}
	rep, err := NewSARIFImport().Scan(context.Background(), ft, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != len(native.Results) || len(rep.Results) != 4 {
		t.Fatalf("imported %d findings, native %d, want Grype's four", len(rep.Results), len(native.Results))
	}
	for i, got := range rep.Results {
		if got.ImportFormat != saga.ImportFormatGrypeJSON || got.ImportedRepository == "" {
			t.Errorf("%s: format %q, repository %q, want grype-json placed in the component's repository",
				got.RuleID, got.ImportFormat, got.ImportedRepository)
		}
		if !reflect.DeepEqual(asNative(got), native.Results[i]) {
			t.Errorf("imported %+v\nnative   %+v", asNative(got), native.Results[i])
		}
	}
	if !reflect.DeepEqual(rep.Rules, native.Rules) {
		t.Errorf("rules\nimported %+v\nnative   %+v", rep.Rules, native.Rules)
	}
	first := rep.Results[0]
	want := sarif.Package{Name: "lodash", Version: "4.17.20", FixedVersion: "4.17.21", Ecosystem: "npm", PURL: "pkg:npm/lodash@4.17.20"}
	if first.RuleID != "GHSA-35jh-r3h4-6jhm-lodash" || first.Package == nil || *first.Package != want ||
		!slices.Equal(first.Aliases, []string{"CVE-2021-23337"}) || first.Location.URI != "package-lock.json" {
		t.Errorf("first finding %+v, package %+v", first, first.Package)
	}
	if first.Score != 7.2 || !first.HasScore || first.Severity("") != sarif.SeverityHigh {
		t.Errorf("GHSA-35jh-r3h4-6jhm rated %s at %v, want Grype's CVSS score, high", first.Severity(""), first.Score)
	}
	first.Scanner = plugin.ImportScanner
	if got := first.Reporter(); got != "imported grype (grype-json)" {
		t.Errorf("reporter = %q", got)
	}
	for key, want := range map[string]string{
		"tool": "grype 0.121.0", "format": "grype-json", "written": "2026-11-17 15:21 UTC",
		"severity": "CVSS score, else Grype's severity", "commit": notStated,
	} {
		if got := field(t, rep, key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
}

// The SARIF the reader writes from Grype's JSON reads as the SARIF Grype wrote in the same run, for
// each run recorded under testdata whose JSON is whole: lodash's npm advisories, and the Dart and
// Flutter scans, whose advisories Grype matched by CPE alone and rated from the NVD.
func TestGrypeSARIFOfIsTheSARIFGrypeWrites(t *testing.T) {
	for _, c := range []struct {
		name       string
		sarif, doc []byte
	}{
		{"lodash", importTestdata(t, "grype-dir-lodash.sarif"), importTestdata(t, "grype-dir-lodash.json")},
		{"dart", cpeOnlyRead(t, "dart.grype.sarif"), cpeOnlyRead(t, "dart.grype.json")},
		{"flutter", cpeOnlyRead(t, "flutter.grype.sarif"), cpeOnlyRead(t, "flutter.grype.json")},
	} {
		var doc grypeDoc
		var head struct {
			Descriptor struct {
				Version string `json:"version"`
			} `json:"descriptor"`
		}
		if err := json.Unmarshal(c.doc, &doc); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(c.doc, &head); err != nil {
			t.Fatal(err)
		}
		out, err := grypeSARIFOf(doc, head.Descriptor.Version)
		if err != nil {
			t.Fatal(err)
		}
		got, err := sarif.FromSARIF(out)
		if err != nil {
			t.Fatal(err)
		}
		want, err := sarif.FromSARIF(c.sarif)
		if err != nil {
			t.Fatal(err)
		}
		if len(want.Results) == 0 || !reflect.DeepEqual(got, want) {
			t.Errorf("%s:\nwritten  %+v\nGrype's  %+v", c.name, got, want)
		}
	}
}

// What Grype's SARIF writes for a match the recorded runs do not hold: a severity Grype does not
// rank, a vendor score beside the NVD's, no score, no fix, no data source, a relative location and
// none.
func TestGrypeSARIFOfFollowsGrypesRulesForEachMatch(t *testing.T) {
	cvss := func(scores ...float64) []grypeVulnerability {
		v := grypeVulnerability{}
		for _, s := range scores {
			var c struct {
				Metrics struct {
					BaseScore float64 `json:"baseScore"`
				} `json:"metrics"`
			}
			c.Metrics.BaseScore = s
			v.CVSS = append(v.CVSS, c)
		}
		return []grypeVulnerability{v}
	}
	nvd := cvss(9.8)
	nvd[0].Namespace = "nvd:cpe"
	vendor := cvss(5.0)
	for _, c := range []struct {
		name     string
		severity string
		related  []grypeVulnerability
		want     string
	}{
		{"negligible", "Negligible", nil, "0.0"},
		{"unknown", "Unknown", nil, "0.0"},
		{"low, unscored", "Low", nil, "1.0"},
		{"high, unscored", "High", nil, "7.0"},
		{"the vendor's score before the NVD's", "High", append(nvd, vendor...), "5.0"},
		{"the NVD's where no vendor scores it", "High", nvd, "9.8"},
	} {
		m := grypeMatch{RelatedVulnerabilities: c.related}
		m.Vulnerability.Severity = c.severity
		if got := grypeSecuritySeverity(m); got != c.want {
			t.Errorf("%s: security-severity %q, want %q", c.name, got, c.want)
		}
	}
	for severity, want := range map[string]string{"Negligible": "low", "Unknown": "low", "": "low", "Medium": "medium", "CRITICAL": "critical"} {
		if got := grypeSeverityText(severity); got != want {
			t.Errorf("severity %q written %q, want %q", severity, got, want)
		}
	}

	var m grypeMatch
	m.Vulnerability.ID = "CVE-2099-0001"
	m.Vulnerability.URLs = []string{"https://example.test/advisory"}
	m.Vulnerability.Fix.Versions = []string{"2.0.0"} // listed, but Grype's record says no fix exists
	m.Artifact.Name, m.Artifact.Version = "widget", "1.0.0"
	rule := grypeReportedRule(m, "CVE-2099-0001-widget", "low", "lib/widget.lock")
	if rule["helpUri"] != "https://example.test/advisory" || rule["name"] != "CVE-2099-0001" ||
		rule["fullDescription"].(map[string]any)["text"] != "Version 1.0.0 is affected with no fixes reported yet." ||
		!strings.Contains(rule["help"].(map[string]any)["text"].(string), "Fix Version: \nType") {
		t.Errorf("rule %+v", rule)
	}
	m.Vulnerability.Fix.State = "fixed"
	if got := grypeSubtitle(m); got != "Version 1.0.0 is affected with an available fix in versions 2.0.0" {
		t.Errorf("subtitle %q", got)
	}
	m.Vulnerability.URLs = nil
	if got := grypeReportedRule(m, "x", "low", "")["helpUri"]; got != "https://github.com/anchore/grype" {
		t.Errorf("help URI %q, want Grype's last resort", got)
	}

	for _, c := range []struct{ target, location, want string }{
		{`"."`, "/go.mod", "/go.mod"},
		{`"./svc"`, "go.mod", "svc/go.mod"},
		{`"svc"`, "./go.mod", "svc/go.mod"},
		{`"svc"`, "", "svc"},
		{`{"not":"a path"}`, "go.mod", "go.mod"},
	} {
		doc := grypeDoc{}
		doc.Source.Target = json.RawMessage(c.target)
		var m grypeMatch
		if c.location != "" {
			m.Artifact.Locations = append(m.Artifact.Locations, struct {
				Path       string `json:"path"`
				AccessPath string `json:"accessPath"`
			}{Path: c.location})
		}
		if got := grypePackagePath(m, grypeInputPath(doc)); got != c.want {
			t.Errorf("target %s, location %q: %q, want %q", c.target, c.location, got, c.want)
		}
	}
}

// A Grype finding reported under a GitHub advisory is raised by the CVE Grype relates to it, read
// from the JSON, whether that CVE is on KEV or scored above the EPSS threshold.
func TestAnImportedGrypeFindingIsRaisedByItsRelatedCVE(t *testing.T) {
	rep, err := NewSARIFImport().Scan(context.Background(), plugin.FileTarget{Path: grypeLodash, Format: saga.ImportFormatGrypeJSON,
		Repositories: []plugin.RepositoryTarget{{URL: "https://github.com/acme/web"}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(rep.Results, func(r sarif.Result) bool { return r.RuleID == "GHSA-29mw-wpgm-hmr9-lodash" })
	if i < 0 {
		t.Fatalf("no GHSA-29mw-wpgm-hmr9 in %d findings", len(rep.Results))
	}
	res := rep.Results[i]
	if !slices.Contains(res.Aliases, "CVE-2020-28500") {
		t.Fatalf("aliases %q, want the CVE Grype relates to the advisory", res.Aliases)
	}
	checkRaisedByCVE(t, res, "CVE-2020-28500")
}

// A match Grype's configuration ignored arrives set aside, as grype-fs reports it, naming the
// checkout's `.grype.yaml` where it holds the rule, and else the imported file.
func TestAnImportedGrypeJSONKeepsWhatGrypeIgnored(t *testing.T) {
	doc := `{"matches": [], "ignoredMatches": [` + grypeIgnoredJinja2 + `],
	  "source": {"type": "directory", "target": "."}, "descriptor": {"name": "grype", "version": "0.121.0"}}`
	path := writeFile(t, doc)
	rule := "ignore:\n  - vulnerability: CVE-2020-28493\n    reason: not reachable from the entry point\n"
	dir := checkoutWith(t, map[string]string{".grype.yaml": rule})
	for _, c := range []struct {
		name, url, source string
	}{
		{"a local checkout holding the rule", dir, ".grype.yaml"},
		{"a remote repository", "https://github.com/acme/web", path},
	} {
		rep, err := NewSARIFImport().Scan(context.Background(), plugin.FileTarget{Path: path, Format: saga.ImportFormatGrypeJSON,
			Repositories: []plugin.RepositoryTarget{{URL: c.url}}}, nil)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if len(rep.Results) != 1 {
			t.Fatalf("%s: %d findings, want the ignored match", c.name, len(rep.Results))
		}
		sup := rep.Results[0].Suppression
		if sup == nil || sup.Origin != sarif.OriginScanner || sup.Source != c.source || sup.Justification != "not reachable from the entry point" {
			t.Errorf("%s: suppression %+v, want Grype's own, from %s", c.name, sup, c.source)
		}
		if got := rep.Results[0].Location.URI; got != "requirements.txt" {
			t.Errorf("%s: location %q", c.name, got)
		}
	}
}

// A Grype JSON is placed and scoped by the component's repositories: with one, its paths: leave out
// what lies outside them; with two, its findings are in neither and are counted as not scoped.
func TestAnImportedGrypeJSONIsScopedByTheComponentsRepositories(t *testing.T) {
	ft := plugin.FileTarget{Path: grypeLodash, Format: saga.ImportFormatGrypeJSON,
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
		"Move the grype-json import to a component with one repository"
	if len(rep.Results) != 4 || field(t, rep, "not scoped") != want {
		t.Errorf("two repositories: %d findings, not scoped %q", len(rep.Results), field(t, rep, "not scoped"))
	}
}

// A file that is not a directory scan's Grype JSON is refused rather than read as a clean scan, and a
// clean scan, which lists no match, is a clean result.
func TestAGrypeImportRefusesAFileThatIsNotADirectoryScan(t *testing.T) {
	notGrype := "not Grype JSON. Write it with grype dir:. -o json"
	for _, c := range []struct{ name, body, want string }{
		{"SARIF", exampleLog(scoredResult, ""), notGrype},
		{"Trivy JSON", `{"SchemaVersion":2,"Results":[]}`, notGrype},
		{"not JSON", "{not json", notGrype},
		{"no matches", `{"descriptor":{"name":"grype"},"source":{"type":"directory","target":"."}}`, notGrype},
		{"mistyped matches", `{"matches":"none","descriptor":{"name":"grype"}}`, notGrype},
		{"an image scan", `{"matches":[],"source":{"type":"image","target":{"userInput":"alpine:3.19"}},"descriptor":{"name":"grype"}}`,
			"source type image, not a directory. Write it with grype dir:. -o json"},
	} {
		_, err := NewSARIFImport().Scan(context.Background(), plugin.FileTarget{Path: writeFile(t, c.body), Format: saga.ImportFormatGrypeJSON}, nil)
		if err == nil || !strings.HasSuffix(err.Error(), ": "+c.want) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
			continue
		}
		if len(c.want) > 80 {
			t.Errorf("%s: the errors block's reason %q is %d characters", c.name, c.want, len(c.want))
		}
	}
	clean := `{"matches":[],"source":{"type":"directory","target":"."},"descriptor":{"name":"grype","version":"0.121.0"}}`
	rep, err := NewSARIFImport().Scan(context.Background(), plugin.FileTarget{Path: writeFile(t, clean), Format: saga.ImportFormatGrypeJSON}, nil)
	if err != nil || len(rep.Results) != 0 || field(t, rep, "tool") != "grype 0.121.0" || field(t, rep, "severity") != "no findings" {
		t.Errorf("a clean scan: %v, %+v", err, rep.Provenance)
	}
}
