package scanners

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// testdata/grype-cpe-only holds what Grype 0.121.0 wrote, SARIF and JSON in one invocation with
// --by-cve, over two repositories. app is a Flutter app: a pubspec.lock pinning http 0.13.2, which
// Grype matches to its Dart advisory, and sentry 9.6.0, which it matches by CPE to advisories for
// the Sentry server, and an ios/Podfile.lock holding the Flutter pod at 1.0.0 from a local path,
// which it matches by CPE to the Flutter SDK's advisories. lib holds the same pubspec.lock alone.
const (
	cpePubspecLock = `packages:
  http:
    dependency: "direct main"
    description:
      name: http
      sha256: "aaaa"
      url: "https://pub.dev"
    source: hosted
    version: "0.13.2"
  sentry:
    dependency: "direct main"
    description:
      name: sentry
      sha256: "aaaa"
      url: "https://pub.dev"
    source: hosted
    version: "9.6.0"
sdks:
  dart: ">=2.12.0 <3.0.0"
`
	cpePodfileLock = `PODS:
  - Flutter (1.0.0)

DEPENDENCIES:
  - Flutter (from ` + "`" + `Flutter` + "`" + `)

EXTERNAL SOURCES:
  Flutter:
    :path: Flutter

SPEC CHECKSUMS:
  Flutter: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

PODFILE CHECKSUM: 0000000000000000000000000000000000000000

COCOAPODS: 1.16.2
`
)

// cpeOnlyRead returns one recorded output.
func cpeOnlyRead(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "grype-cpe-only", name)) // #nosec G304 -- under testdata
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// runCPEOnly scans two components, app and lib, each on its own repository, with grype-fs under the
// real sca control replaying what Grype wrote for the repository it was given.
func runCPEOnly(t *testing.T, sca saga.ControllerSettings, components map[string]saga.ControllerSettings) engine.Result {
	t.Helper()
	dirs := map[string]string{
		"app": writeTree(t, map[string]string{"pubspec.lock": cpePubspecLock, "ios/Podfile.lock": cpePodfileLock}),
		"lib": writeTree(t, map[string]string{"pubspec.lock": cpePubspecLock}),
	}
	recording := map[string]string{dirs["app"]: "flutter", dirs["lib"]: "dart"}
	checkout := func(_ context.Context, url, _ string, _ git.Scope) (git.Tree, func(), error) {
		return git.Tree{Dir: dirs[url]}, func() {}, nil
	}
	prior := grypeRunInDir
	t.Cleanup(func() { grypeRunInDir = prior })
	grypeRunInDir = func(_ context.Context, dir string, argv []string) ([]byte, error) {
		fakeGrypeOutputs(t, argv, string(cpeOnlyRead(t, recording[dir]+".grype.json")))
		return cpeOnlyRead(t, recording[dir]+".grype.sarif"), nil
	}
	grype := NewGrypeFS().(repoScanner)
	grype.checkout, grype.prewarm, grype.cacheVersion, grype.dataState = checkout, nil, nil, nil

	reg := engine.NewRegistry()
	reg.RegisterController(controllers.NewSCA())
	reg.RegisterScanner(grype)

	project := saga.ControllerSettings{"enabled": true, "trivyFs": map[string]any{"enabled": false}, "grypeFs": map[string]any{"enabled": true}}
	for k, v := range sca {
		project[k] = v
	}
	model := saga.Model{Config: saga.Config{Controls: map[string]saga.ControllerSettings{"sca": project}}}
	for _, name := range []string{"app", "lib"} {
		comp := saga.Component{Name: name, Repositories: []saga.Repository{{URL: name}}}
		if s, ok := components[name]; ok {
			comp.Controls = map[string]saga.ControllerSettings{"sca": s}
		}
		model.Components = append(model.Components, comp)
	}
	res, err := engine.New(reg).Run(context.Background(), model)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// cpeOutcome is one component's answer: the findings counted and the findings set aside, each as
// "<vulnerability> <package>" sorted, with the source of every suppression.
type cpeOutcome struct {
	counted, suppressed []string
	sources             map[string]bool
}

// cpeMatched is each package Grype matched only by CPE.
var cpeMatched = map[string]bool{"Flutter": true, "sentry": true}

func cpeOutcomeOf(t *testing.T, res engine.Result, component string) cpeOutcome {
	t.Helper()
	out := cpeOutcome{sources: map[string]bool{}}
	for _, r := range res.Controls["sca"].Report.Results {
		if r.Component != component {
			continue
		}
		if r.Package == nil {
			t.Fatalf("%s %s carries no package", component, r.RuleID)
		}
		if want := cpeMatched[r.Package.Name]; r.Package.CPEMatch != want {
			t.Errorf("%s %s: cpeMatch %v, want %v", component, r.RuleID, r.Package.CPEMatch, want)
		}
		id := r.VulnerabilityID() + " " + r.Package.Name
		if !r.Suppressed() {
			out.counted = append(out.counted, id)
			continue
		}
		s := r.Suppression
		if s.Origin != sarif.OriginSetting || s.Justification != sarif.JustificationCPEMatch {
			t.Errorf("%s %s: suppressed as %+v, want by the cpeMatches setting", component, id, *s)
		}
		out.suppressed = append(out.suppressed, id)
		out.sources[s.Source] = true
	}
	slices.Sort(out.counted)
	slices.Sort(out.suppressed)
	return out
}

var (
	cpeAppCPE = []string{"CVE-2022-3095 Flutter", "CVE-2023-36826 sentry", "CVE-2024-24829 sentry", "CVE-2026-27704 Flutter"}
	cpeLibCPE = []string{"CVE-2023-36826 sentry", "CVE-2024-24829 sentry"}
	cpeHTTP   = []string{"CVE-2020-35669 http"}
)

// By default a finding Grype matched only by CPE stays in the report, suppressed by the setting, and
// the Dart advisory it matched in the package's own ecosystem is counted, in both repositories.
func TestCPEOnlyMatchesAreSuppressedByDefault(t *testing.T) {
	res := runCPEOnly(t, nil, nil)
	for component, cpe := range map[string][]string{"app": cpeAppCPE, "lib": cpeLibCPE} {
		got := cpeOutcomeOf(t, res, component)
		if !slices.Equal(got.counted, cpeHTTP) || !slices.Equal(got.suppressed, cpe) {
			t.Errorf("%s: counted %v and set aside %v, want %v and %v", component, got.counted, got.suppressed, cpeHTTP, cpe)
		}
		if !got.sources["config.controls.sca.cpeMatches"] || len(got.sources) != 1 {
			t.Errorf("%s: sources %v, want the project's key", component, got.sources)
		}
	}
	if res.CPEMatches != len(cpeAppCPE)+len(cpeLibCPE) {
		t.Errorf("CPEMatches %d, want %d", res.CPEMatches, len(cpeAppCPE)+len(cpeLibCPE))
	}
}

// cpeMatches: report counts every one of them, still marked.
func TestCPEMatchesReportCountsThem(t *testing.T) {
	res := runCPEOnly(t, saga.ControllerSettings{"cpeMatches": "report"}, nil)
	for component, cpe := range map[string][]string{"app": cpeAppCPE, "lib": cpeLibCPE} {
		got := cpeOutcomeOf(t, res, component)
		want := slices.Sorted(slices.Values(slices.Concat(cpe, cpeHTTP)))
		if !slices.Equal(got.counted, want) || len(got.suppressed) != 0 {
			t.Errorf("%s: counted %v and set aside %v, want %v counted", component, got.counted, got.suppressed, want)
		}
	}
	if res.CPEMatches != 0 {
		t.Errorf("CPEMatches %d, want 0", res.CPEMatches)
	}
}

// A component's setting replaces the project's for that component alone, and its suppressions name
// the component's key.
func TestAComponentsCPEMatchesReplacesTheProjects(t *testing.T) {
	res := runCPEOnly(t, saga.ControllerSettings{"cpeMatches": "report"},
		map[string]saga.ControllerSettings{"lib": {"cpeMatches": "suppress"}})
	if got := cpeOutcomeOf(t, res, "app"); len(got.suppressed) != 0 {
		t.Errorf("app: set aside %v under the project's report", got.suppressed)
	}
	got := cpeOutcomeOf(t, res, "lib")
	if !slices.Equal(got.suppressed, cpeLibCPE) || !got.sources[`components["lib"].controls.sca.cpeMatches`] {
		t.Errorf("lib: set aside %v from %v, want %v from the component's key", got.suppressed, got.sources, cpeLibCPE)
	}
}

func TestGrypeCPEOnly(t *testing.T) {
	type detail = struct {
		Type    string `json:"type"`
		Matcher string `json:"matcher"`
	}
	match := func(kind string, details ...detail) grypeMatch {
		var m grypeMatch
		m.Artifact.Type = kind
		m.MatchDetails = details
		return m
	}
	cpe, direct := detail{"cpe-match", "stock-matcher"}, detail{"exact-direct-match", "stock-matcher"}
	for name, c := range map[string]struct {
		m    grypeMatch
		want bool
	}{
		"a pod matched by CPE":                       {match("pod", cpe), true},
		"a dart-pub package matched by CPE twice":    {match("dart-pub", cpe, cpe), true},
		"a package matched by CPE and in ecosystem":  {match("dart-pub", cpe, direct), false},
		"a package matched in its ecosystem":         {match("dart-pub", direct), false},
		"a binary matched by CPE":                    {match("binary", cpe), false},
		"a jar matched by CPE where Grype allows it": {match("java-archive", detail{"cpe-match", "java-matcher"}), false},
		"a match with no details":                    {match("pod"), false},
	} {
		if got := grypeCPEOnly(c.m); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
}

// Two matches of one advisory in one package at one place, one only by CPE, name one package, and
// it is not marked: one of the matches used the package's own ecosystem.
func TestOnePackageMatchedTwoWaysIsNotACPEMatch(t *testing.T) {
	m := func(kind string) grypeMatch {
		var g grypeMatch
		g.Vulnerability.ID = "CVE-2023-36826"
		g.Artifact.Name, g.Artifact.Version, g.Artifact.Type = "sentry", "9.6.0", "dart-pub"
		g.Artifact.Locations = []struct {
			Path       string `json:"path"`
			AccessPath string `json:"accessPath"`
		}{{Path: "/pubspec.lock"}}
		g.MatchDetails = []struct {
			Type    string `json:"type"`
			Matcher string `json:"matcher"`
		}{{Type: kind, Matcher: "stock-matcher"}}
		return g
	}
	msg := "A medium vulnerability in dart-pub package: sentry, version 9.6.0 was found at: /pubspec.lock"
	for _, order := range [][]grypeMatch{{m("cpe-match"), m("exact-direct-match")}, {m("exact-direct-match"), m("cpe-match")}} {
		pkg, _, ok := newGrypeMatchIndex(order).find("CVE-2023-36826-sentry", msg, "/pubspec.lock")
		if !ok || pkg.CPEMatch || pkg.Name != "sentry" {
			t.Errorf("package %+v (%v), want sentry, unmarked", pkg, ok)
		}
	}
	pkg, _, ok := newGrypeMatchIndex([]grypeMatch{m("cpe-match"), m("cpe-match")}).find("CVE-2023-36826-sentry", msg, "/pubspec.lock")
	if !ok || !pkg.CPEMatch {
		t.Errorf("package %+v (%v), want sentry, marked", pkg, ok)
	}
}
