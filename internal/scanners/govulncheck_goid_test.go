package scanners

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/draugr-dev/draugr/internal/scanpolicy"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// govulncheckChiOutput is what govulncheck v1.5.0 printed with -format json for a module requiring
// github.com/go-chi/chi/v5 v5.2.5 whose main builds a router and never uses middleware.RealIP, cut to
// the config, the SBOM, chi's three advisories with the fields Draugr reads, and their findings.
// Each advisory has a Go id and a GitHub advisory id and no CVE.
const govulncheckChiOutput = `{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck","scanner_version":"v1.5.0","db":"https://vuln.go.dev","db_last_modified":"2026-10-27T21:16:18Z","go_version":"go1.26.10","scan_level":"symbol","scan_mode":"source"}}
{"SBOM":{"go_version":"go1.26.10","modules":[{"path":"example.com/app"},{"path":"github.com/go-chi/chi/v5","version":"v5.2.5"},{"path":"stdlib","version":"v1.26.10"}],"roots":["example.com/app"]}}
{"osv":{"schema_version":"1.3.1","id":"GO-2026-5774","aliases":["GHSA-3fxj-6jh8-hvhx"],"summary":"Chi has an IP spoofing vulnerability in middleware.RealIP in github.com/go-chi/chi","affected":[{"package":{"name":"github.com/go-chi/chi/v5","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"5.2.1"},{"fixed":"5.3.0"}]}],"ecosystem_specific":{"imports":[{"path":"github.com/go-chi/chi/v5/middleware","symbols":["RealIP"]}]}}]}}
{"osv":{"schema_version":"1.3.1","id":"GO-2026-5775","aliases":["GHSA-9g5q-2w5x-hmxf"],"summary":"Chi Middleware vulnerable to IP spoofing via X-Forwarded-For header in github.com/go-chi/chi","affected":[{"package":{"name":"github.com/go-chi/chi/v5","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"5.3.0"}]}],"ecosystem_specific":{"imports":[{"path":"github.com/go-chi/chi/v5/middleware","symbols":["RealIP"]}]}}]}}
{"osv":{"schema_version":"1.3.1","id":"GO-2026-5777","aliases":["GHSA-rjr7-jggh-pgcp"],"summary":"Chi's RealIP Middleware allows IP spoofing via unvalidated X-Forwarded-For header in github.com/go-chi/chi","affected":[{"package":{"name":"github.com/go-chi/chi/v5","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"5.3.0"}]}],"ecosystem_specific":{"imports":[{"path":"github.com/go-chi/chi/v5/middleware","symbols":["RealIP"]}]}}]}}
{"finding":{"osv":"GO-2026-5774","fixed_version":"v5.3.0","trace":[{"module":"github.com/go-chi/chi/v5","version":"v5.2.5"}]}}
{"finding":{"osv":"GO-2026-5775","fixed_version":"v5.3.0","trace":[{"module":"github.com/go-chi/chi/v5","version":"v5.2.5"}]}}
{"finding":{"osv":"GO-2026-5777","fixed_version":"v5.3.0","trace":[{"module":"github.com/go-chi/chi/v5","version":"v5.2.5"}]}}
`

// chiGrypeMatch is one of Grype's matches in chi, as a scan of the same module reported it: the Go
// id it was reported under, the severity and score its rule carries, and the GitHub advisory its
// rule links to.
type chiGrypeMatch struct {
	goID, ghsa, summary string
	score               float64
}

// chiGrypeMatches are the matches Grype 0.121.0 reported from the Go database for chi v5.2.5, every
// one rated low with the score its rule carried.
var chiGrypeMatches = []chiGrypeMatch{
	{"GO-2026-5774", "GHSA-3fxj-6jh8-hvhx", "Chi has an IP spoofing vulnerability in middleware.RealIP in github.com/go-chi/chi", 6.9},
	{"GO-2026-5775", "GHSA-9g5q-2w5x-hmxf", "Chi Middleware vulnerable to IP spoofing via X-Forwarded-For header in github.com/go-chi/chi", 7.7},
	{"GO-2026-5777", "GHSA-rjr7-jggh-pgcp", "Chi's RealIP Middleware allows IP spoofing via unvalidated X-Forwarded-For header in github.com/go-chi/chi", 7.7},
}

const chiPURL = "pkg:golang/github.com/go-chi/chi/v5@v5.2.5"

// chiGrypeSARIF is Grype's SARIF for chiGrypeMatches, in the shape Grype's presenter writes: one rule
// per advisory and package, and one result per match.
func chiGrypeSARIF(t *testing.T) string {
	t.Helper()
	var rules, results []any
	for _, m := range chiGrypeMatches {
		id := m.goID + "-github.com/go-chi/chi/v5"
		link := "https://github.com/go-chi/chi/security/advisories/" + m.ghsa
		rules = append(rules, map[string]any{
			"id": id, "name": "GoModuleMatcherExactDirectMatch",
			"shortDescription": map[string]any{"text": m.goID + " low vulnerability for github.com/go-chi/chi/v5 package"},
			"fullDescription":  map[string]any{"text": m.summary},
			"helpUri":          link,
			"help": map[string]any{"text": fmt.Sprintf("Vulnerability %s\nSeverity: low\nPackage: github.com/go-chi/chi/v5\n"+
				"Version: v5.2.5\nFix Version: 5.3.0\nType: go-module\nLocation: /go.mod\n"+
				"Data Namespace: govulndb:language:go\nLink: [%s](%s)", m.goID, m.goID, link)},
			"properties": map[string]any{"security-severity": fmt.Sprintf("%.1f", m.score), "purls": []string{chiPURL}},
		})
		results = append(results, map[string]any{
			"ruleId":  id,
			"level":   "note",
			"message": map[string]any{"text": "A low vulnerability in go-module package: github.com/go-chi/chi/v5, version v5.2.5 was found at: /go.mod"},
			"locations": []any{map[string]any{"physicalLocation": map[string]any{
				"artifactLocation": map[string]any{"uri": "/go.mod"},
				"region":           map[string]any{"startLine": 1, "startColumn": 1, "endLine": 1, "endColumn": 1},
			}}},
		})
	}
	return mustJSON(t, map[string]any{"version": "2.1.0", "runs": []any{map[string]any{
		"tool":    map[string]any{"driver": map[string]any{"name": "grype", "informationUri": "https://github.com/anchore/grype", "rules": rules}},
		"results": results,
	}}})
}

// chiGrypeJSON is Grype's JSON report of the same matches. Each relates no other vulnerability, so
// nothing on Grype's side names the GitHub advisory id govulncheck reports the flaw under.
func chiGrypeJSON(t *testing.T) string {
	t.Helper()
	ms := []any{}
	for _, m := range chiGrypeMatches {
		ms = append(ms, map[string]any{
			"vulnerability": map[string]any{
				"id": m.goID, "dataSource": "https://github.com/go-chi/chi/security/advisories/" + m.ghsa,
				"namespace": "govulndb:language:go", "severity": "Low",
				"fix": map[string]any{"versions": []string{"5.3.0"}, "state": "fixed"},
			},
			"relatedVulnerabilities": []any{},
			"matchDetails":           []any{map[string]any{"type": "exact-direct-match", "matcher": "go-module-matcher"}},
			"artifact": map[string]any{
				"name": "github.com/go-chi/chi/v5", "version": "v5.2.5", "type": "go-module", "purl": chiPURL,
				"locations": []any{map[string]any{"path": "/go.mod", "accessPath": "/go.mod"}},
			},
		})
	}
	return mustJSON(t, map[string]any{"matches": ms, "ignoredMatches": []any{}, "source": map[string]any{"type": "directory", "target": "/src"}})
}

// govulncheck reports each of chi's advisories under its GitHub advisory id and names its Go id
// beside it.
func TestGovulncheckNamesTheGoIDBesideTheGitHubAdvisory(t *testing.T) {
	report, err := parseGovulncheck([]byte(govulncheckChiOutput), "", plugin.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Results) != len(chiGrypeMatches) {
		t.Fatalf("results = %d, want one per advisory", len(report.Results))
	}
	for i, r := range report.Results {
		m := chiGrypeMatches[i]
		if r.RuleID != m.ghsa || !slices.Equal(r.Aliases, []string{m.goID}) {
			t.Errorf("result %d: %s naming %q, want %s naming %s", i, r.RuleID, r.Aliases, m.ghsa, m.goID)
		}
	}
}

// The other identifiers are the Go id and every alias of the entry but the rule id's own, each once,
// and the Go id alone where the advisory was not printed.
func TestGovulncheckAliases(t *testing.T) {
	advisory := &govulncheckOSV{ID: "GO-2021-0159", Aliases: []string{"CVE-2015-5739", "CVE-2015-5740", "GHSA-x", "CVE-2015-5739", ""}}
	if got := govulncheckAliases("CVE-2015-5739", advisory.ID, advisory); !slices.Equal(got, []string{"GO-2021-0159", "CVE-2015-5740", "GHSA-x"}) {
		t.Errorf("aliases = %q", got)
	}
	if got := govulncheckAliases("GO-2026-9999", "GO-2026-9999", nil); got != nil {
		t.Errorf("aliases = %q, want none for a finding under its Go id", got)
	}
}

// chi v5.2.5 in each of two components' repositories, through the engine: govulncheck reports each
// advisory under its GitHub advisory id and rules it unreachable, and Grype reports it from the Go
// database under the Go id. Each flaw counts once per component, as Grype's copy carrying the
// verdict and the band it moves to, with the Go id on the row, and the gate passes.
func TestAGoFlawGrypeReportsByGoIDCountsOnceUnderGovulnchecksVerdict(t *testing.T) {
	builtWith(t, "")
	orig := lookRuntime
	t.Cleanup(func() { lookRuntime = orig })
	lookRuntime = func(name string) (string, error) { return "/usr/bin/" + name, nil }

	tree := map[string]string{
		"go.mod":  "module example.com/app\n\ngo 1.22\n\nrequire github.com/go-chi/chi/v5 v5.2.5\n",
		"main.go": goMain,
	}
	dirs := map[string]string{"one": writeTree(t, tree), "two": writeTree(t, tree)}

	vuln := NewGovulncheck().(repoScanner)
	vuln.checkout, vuln.cacheVersion, vuln.preflight = checkoutOf(dirs), nil, nil
	vuln.run = func(context.Context, string, []string) ([]byte, error) { return []byte(govulncheckChiOutput), nil }

	prior := grypeRunInDir
	t.Cleanup(func() { grypeRunInDir = prior })
	grypeRunInDir = func(_ context.Context, _ string, argv []string) ([]byte, error) {
		fakeGrypeOutputs(t, argv, chiGrypeJSON(t))
		return []byte(chiGrypeSARIF(t)), nil
	}
	grype := NewGrypeFS().(repoScanner)
	grype.checkout, grype.prewarm, grype.cacheVersion, grype.dataState = checkoutOf(dirs), nil, nil, nil

	reg := engine.NewRegistry()
	reg.RegisterController(matchController{control: "sca", scanners: []string{govulncheckScanner, "grype-fs"}})
	reg.RegisterScanner(vuln)
	reg.RegisterScanner(grype)
	model := saga.Model{
		Config: saga.Config{Controls: map[string]saga.ControllerSettings{"sca": {"enabled": true}}},
		Components: []saga.Component{
			{Name: "api", Exposure: saga.ExposurePublic, Criticality: saga.CriticalityCritical, Repositories: []saga.Repository{{URL: "one"}}},
			{Name: "web", Exposure: saga.ExposurePublic, Criticality: saga.CriticalityCritical, Repositories: []saga.Repository{{URL: "two"}}},
		},
	}
	res, err := engine.New(reg, engine.WithPrioritization(scanpolicy.PrioritizerWith(nil, nil))).Run(context.Background(), model)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.ScanErrors) != 0 {
		t.Fatalf("scan errors = %v", res.ScanErrors)
	}

	report := res.Controls["sca"].Report
	counted := map[string][]string{}
	for _, r := range report.Results {
		if r.Correlated() || r.Suppressed() {
			continue
		}
		counted[r.Component] = append(counted[r.Component], r.RuleID)
		if r.Tool != "grype" {
			t.Errorf("%s: %s %s counted, want Grype's copy carrying the verdict", r.Component, r.Tool, r.RuleID)
		}
		if r.Reachability == nil || r.Reachability.State != sarif.ReachabilityUnreachable || r.Reachability.Analyzer != govulncheckScanner {
			t.Errorf("%s %s: verdict %+v, want govulncheck's unreachable", r.Component, r.RuleID, r.Reachability)
			continue
		}
		// Grype's own severity, one step down for the verdict, and the band public and critical
		// gives that.
		if want := r.Severity("").Deescalate(); r.Reachability.RankedAs != want || r.Priority == "P1" {
			t.Errorf("%s %s: ranked as %s at %s, want %s and below P1", r.Component, r.RuleID, r.Reachability.RankedAs, r.Priority, want)
		}
	}
	for _, component := range []string{"api", "web"} {
		got := counted[component]
		slices.Sort(got)
		var want []string
		for _, m := range chiGrypeMatches {
			want = append(want, m.goID+"-github.com/go-chi/chi/v5")
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s counts %q, want each flaw once under its Go id", component, got)
		}
	}
	if n := len(report.Results); n != 2*len(chiGrypeMatches) {
		t.Errorf("results = %d, want govulncheck's copies folded onto Grype's", n)
	}
	if s := res.Reachability; s.Unreachable != 2*len(chiGrypeMatches) || s.Reachable+s.Unknown != 0 {
		t.Errorf("reachability = %+v, want each flaw unreachable once per component", s)
	}
	verdict := norn.Policy{}.Evaluate(map[string]sarif.Report{"sca": report})
	if verdict.Verdict != norn.Pass {
		t.Errorf("gate = %+v, want pass: no flaw is reachable", verdict)
	}
}
