package scanners

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// The recorded output under testdata/pom-scopes is Grype 0.121.0 (with --by-cve) and Trivy 0.76.1
// (with --include-dev-deps and --offline-scan), each run over the two poms below, with the
// directory scanned replaced by /checkout and the Grype JSON cut to the fields Draugr reads. One
// Trivy title is left out of billing.trivy.json, because its British spelling fails the spelling
// check every tracked file is held to and no test reads it. Grype
// reports every dependency either pom declares, with no scope. Trivy reports only the compile and
// runtime ones, and nothing for the provided, system, test or optional dependency.
const (
	// pomScopesShop declares one dependency in each scope, each written on the dependency itself.
	pomScopesShop = `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>shop</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-text</artifactId>
      <version>1.9</version>
      <scope>compile</scope>
    </dependency>
    <dependency>
      <groupId>org.yaml</groupId>
      <artifactId>snakeyaml</artifactId>
      <version>1.33</version>
      <scope>runtime</scope>
    </dependency>
    <dependency>
      <groupId>commons-collections</groupId>
      <artifactId>commons-collections</artifactId>
      <version>3.2.1</version>
      <scope>provided</scope>
    </dependency>
    <dependency>
      <groupId>commons-fileupload</groupId>
      <artifactId>commons-fileupload</artifactId>
      <version>1.3.1</version>
      <scope>system</scope>
      <systemPath>${project.basedir}/lib/commons-fileupload-1.3.1.jar</systemPath>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.12</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>commons-io</groupId>
      <artifactId>commons-io</artifactId>
      <version>2.6</version>
      <optional>true</optional>
    </dependency>
  </dependencies>
</project>
`
	// pomScopesBilling holds commons-collections with no scope, where shop provides it, a provided
	// dependency whose groupId is a property, and a test scope given by dependencyManagement.
	pomScopesBilling = `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>billing</artifactId>
  <version>1.0.0</version>
  <properties>
    <fileupload.group>commons-fileupload</fileupload.group>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>junit</groupId>
        <artifactId>junit</artifactId>
        <version>4.12</version>
        <scope>test</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-text</artifactId>
      <version>1.9</version>
    </dependency>
    <dependency>
      <groupId>commons-collections</groupId>
      <artifactId>commons-collections</artifactId>
      <version>3.2.1</version>
    </dependency>
    <dependency>
      <groupId>${fileupload.group}</groupId>
      <artifactId>commons-fileupload</artifactId>
      <version>1.3.1</version>
      <scope>provided</scope>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.12</version>
    </dependency>
  </dependencies>
</project>
`
)

// pomScopesRead returns one recorded output.
func pomScopesRead(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "pom-scopes", name)) // #nosec G304 -- under testdata
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// runPomScopes scans two components, shop and billing, each on its own repository holding its pom,
// with trivy-fs and grype-fs under the real sca control, each scanner replaying what it wrote for
// the repository it was given.
func runPomScopes(t *testing.T, sca saga.ControllerSettings, components map[string]saga.ControllerSettings) engine.Result {
	t.Helper()
	dirs := map[string]string{
		"shop":    writeTree(t, map[string]string{"pom.xml": pomScopesShop}),
		"billing": writeTree(t, map[string]string{"service/pom.xml": pomScopesBilling}),
	}
	repoOf := map[string]string{dirs["shop"]: "shop", dirs["billing"]: "billing"}
	checkout := func(_ context.Context, url, _ string, _ git.Scope) (git.Tree, func(), error) {
		return git.Tree{Dir: dirs[url]}, func() {}, nil
	}

	prior := grypeRunInDir
	t.Cleanup(func() { grypeRunInDir = prior })
	grypeRunInDir = func(_ context.Context, dir string, argv []string) ([]byte, error) {
		repo := repoOf[dir]
		fakeGrypeOutputs(t, argv, string(pomScopesRead(t, repo+".grype.json")))
		return pomScopesRead(t, repo+".grype.sarif"), nil
	}
	grype := NewGrypeFS().(repoScanner)
	grype.checkout, grype.prewarm, grype.cacheVersion, grype.dataState = checkout, nil, nil, nil

	trivy := NewTrivyFS().(repoScanner)
	trivy.checkout, trivy.prewarm, trivy.cacheVersion, trivy.dataState = checkout, nil, nil, nil
	trivy.runLogged = trivyFSRun(func(_ context.Context, dir string, _ []string) ([]byte, []byte, error) {
		return pomScopesRead(t, repoOf[dir]+".trivy.json"), nil, nil
	})

	reg := engine.NewRegistry()
	reg.RegisterController(controllers.NewSCA())
	reg.RegisterScanner(grype)
	reg.RegisterScanner(trivy)

	project := saga.ControllerSettings{"enabled": true, "grypeFs": map[string]any{"enabled": true}}
	for k, v := range sca {
		project[k] = v
	}
	model := saga.Model{Config: saga.Config{Controls: map[string]saga.ControllerSettings{"sca": project}}}
	for _, name := range []string{"shop", "billing"} {
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

// pomOutcome is one component's answer: the flaws counted, as "<vulnerability> <package>" sorted,
// and every finding set aside, as "<tool> <vulnerability> <package>" with its suppression.
type pomOutcome struct {
	counted    []string
	suppressed map[string]sarif.Suppression
}

// pomScopeOf is the scope each package is declared in, per component.
var pomScopeOf = map[string]map[string]string{
	"shop": {
		"commons-text": "compile", "snakeyaml": "runtime", "commons-collections": "provided",
		"commons-fileupload": "system", "junit": "test", "commons-io": "optional",
	},
	"billing": {
		"commons-text": "compile", "commons-collections": "compile", "commons-fileupload": "provided",
		"junit": "test",
	},
}

func pomOutcomeOf(t *testing.T, res engine.Result, component string) pomOutcome {
	t.Helper()
	out := pomOutcome{suppressed: map[string]sarif.Suppression{}}
	for _, r := range res.Controls["sca"].Report.Results {
		if r.Component != component {
			continue
		}
		if r.Package == nil {
			t.Fatalf("%s %s %s carries no package", component, r.Tool, r.RuleID)
		}
		// Trivy names a Maven package groupId:artifactId and Grype by its artifactId.
		name := r.Package.Name[strings.LastIndex(r.Package.Name, ":")+1:]
		scope, declared := pomScopeOf[component][name]
		if !declared {
			t.Fatalf("%s %s %s: %s is not a dependency the pom declares", component, r.Tool, r.RuleID, r.Package.Name)
		}
		if r.Tool == "trivy" && scope != "compile" && scope != "runtime" {
			t.Errorf("%s: trivy reported %s, a %s dependency its pom parser leaves out", component, name, scope)
		}
		if want := scope == "provided" || scope == "system"; r.Package.Provided != want {
			t.Errorf("%s %s %s (%s): provided %v, want %v", component, r.Tool, r.RuleID, scope, r.Package.Provided, want)
		}
		if want := scope == "test"; r.Package.Dev != want {
			t.Errorf("%s %s %s (%s): dev %v, want %v", component, r.Tool, r.RuleID, scope, r.Package.Dev, want)
		}
		id := r.VulnerabilityID() + " " + name
		switch {
		case r.Suppressed():
			out.suppressed[r.Tool+" "+id] = *r.Suppression
		case !r.Correlated():
			out.counted = append(out.counted, id)
		}
	}
	slices.Sort(out.counted)
	return out
}

var (
	pomShopShips = []string{
		"CVE-2021-29425 commons-io", "CVE-2022-1471 snakeyaml", "CVE-2022-42889 commons-text",
		"CVE-2024-47554 commons-io",
	}
	pomBillingShips = []string{
		"CVE-2015-6420 commons-collections", "CVE-2015-7501 commons-collections", "CVE-2022-42889 commons-text",
	}
	pomCollections = []string{"CVE-2015-6420 commons-collections", "CVE-2015-7501 commons-collections"}
	pomFileupload  = []string{
		"CVE-2016-1000031 commons-fileupload", "CVE-2016-3092 commons-fileupload",
		"CVE-2023-24998 commons-fileupload", "CVE-2025-48976 commons-fileupload",
	}
	pomJunit = []string{"CVE-2020-15250 junit"}
)

// checkPomSetAside checks that exactly the Grype findings named are suppressed, each by a setting
// with the source and reason given for its package.
func checkPomSetAside(t *testing.T, component string, got pomOutcome, want map[string]sarif.Suppression) {
	t.Helper()
	for key, s := range got.suppressed {
		w, ok := want[key]
		if !ok {
			t.Errorf("%s: %s suppressed (%s), want counted", component, key, s.Justification)
			continue
		}
		if s.Origin != sarif.OriginSetting || s.Justification != w.Justification || s.Source != w.Source {
			t.Errorf("%s: %s suppression %+v, want origin %q, reason %q, source %q",
				component, key, s, sarif.OriginSetting, w.Justification, w.Source)
		}
	}
	for key := range want {
		if _, ok := got.suppressed[key]; !ok {
			t.Errorf("%s: %s not suppressed", component, key)
		}
	}
}

// setAside is the suppression expected on each Grype finding about the packages named.
func setAside(into map[string]sarif.Suppression, ids []string, reason, source string) map[string]sarif.Suppression {
	for _, id := range ids {
		into["grype "+id] = sarif.Suppression{Justification: reason, Source: source}
	}
	return into
}

func union(lists ...[]string) []string {
	var out []string
	for _, l := range lists {
		out = append(out, l...)
	}
	slices.Sort(out)
	return out
}

const (
	providedKey = "config.controls.sca.providedDependencies"
	devKey      = "config.controls.sca.devDependencies"
)

// With nothing written, a provided or system dependency is suppressed as provided by the runtime and
// a test one as a development dependency, in each repository whichever way the pom gives the scope;
// compile, runtime and optional dependencies count. billing declares commons-collections with no
// scope, so the copy shop provides is set aside and billing's is counted.
func TestPomScopesAreSuppressedByDefault(t *testing.T) {
	res := runPomScopes(t, nil, nil)
	shop, billing := pomOutcomeOf(t, res, "shop"), pomOutcomeOf(t, res, "billing")
	if !slices.Equal(shop.counted, pomShopShips) {
		t.Errorf("shop counted %v, want %v", shop.counted, pomShopShips)
	}
	if !slices.Equal(billing.counted, pomBillingShips) {
		t.Errorf("billing counted %v, want %v", billing.counted, pomBillingShips)
	}
	checkPomSetAside(t, "shop", shop, setAside(setAside(map[string]sarif.Suppression{},
		union(pomCollections, pomFileupload), sarif.JustificationProvidedByRuntime, providedKey),
		pomJunit, sarif.JustificationDevDependency, devKey))
	checkPomSetAside(t, "billing", billing, setAside(setAside(map[string]sarif.Suppression{},
		pomFileupload, sarif.JustificationProvidedByRuntime, providedKey),
		pomJunit, sarif.JustificationDevDependency, devKey))
	if want := (2 + 4) + 4; res.ProvidedDependencies != want {
		t.Errorf("ProvidedDependencies = %d, want %d", res.ProvidedDependencies, want)
	}
	if want := 1 + 1; res.DevDependencies != want {
		t.Errorf("DevDependencies = %d, want %d", res.DevDependencies, want)
	}
	if res.Suppressed != 0 {
		t.Errorf("Suppressed = %d, want 0: config.exclude set nothing aside", res.Suppressed)
	}
}

// providedDependencies: report counts the provided and system dependencies, marked provided, and
// leaves the test one to devDependencies.
func TestProvidedDependenciesReportCountsThem(t *testing.T) {
	res := runPomScopes(t, saga.ControllerSettings{"providedDependencies": "report"}, nil)
	shop, billing := pomOutcomeOf(t, res, "shop"), pomOutcomeOf(t, res, "billing")
	if want := union(pomShopShips, pomCollections, pomFileupload); !slices.Equal(shop.counted, want) {
		t.Errorf("shop counted %v, want %v", shop.counted, want)
	}
	if want := union(pomBillingShips, pomFileupload); !slices.Equal(billing.counted, want) {
		t.Errorf("billing counted %v, want %v", billing.counted, want)
	}
	for c, got := range map[string]pomOutcome{"shop": shop, "billing": billing} {
		checkPomSetAside(t, c, got, setAside(map[string]sarif.Suppression{}, pomJunit, sarif.JustificationDevDependency, devKey))
	}
	if res.ProvidedDependencies != 0 {
		t.Errorf("ProvidedDependencies = %d, want 0", res.ProvidedDependencies)
	}
}

// devDependencies: report counts the test dependency, Grype's copy being the only one, and leaves
// the provided ones suppressed.
func TestDevDependenciesReportCountsAPomsTestScope(t *testing.T) {
	res := runPomScopes(t, saga.ControllerSettings{"devDependencies": "report"}, nil)
	shop := pomOutcomeOf(t, res, "shop")
	if want := union(pomShopShips, pomJunit); !slices.Equal(shop.counted, want) {
		t.Errorf("shop counted %v, want %v", shop.counted, want)
	}
	checkPomSetAside(t, "shop", shop, setAside(map[string]sarif.Suppression{},
		union(pomCollections, pomFileupload), sarif.JustificationProvidedByRuntime, providedKey))
}

// A component's providedDependencies replaces the project's, and the suppression names the
// component's key.
func TestAComponentsProvidedDependenciesReplacesTheProjects(t *testing.T) {
	res := runPomScopes(t, saga.ControllerSettings{"providedDependencies": "report"},
		map[string]saga.ControllerSettings{"billing": {"providedDependencies": "suppress"}})
	shop, billing := pomOutcomeOf(t, res, "shop"), pomOutcomeOf(t, res, "billing")
	if want := union(pomShopShips, pomCollections, pomFileupload); !slices.Equal(shop.counted, want) {
		t.Errorf("shop counted %v, want %v", shop.counted, want)
	}
	if !slices.Equal(billing.counted, pomBillingShips) {
		t.Errorf("billing counted %v, want %v", billing.counted, pomBillingShips)
	}
	checkPomSetAside(t, "billing", billing, setAside(setAside(map[string]sarif.Suppression{},
		pomFileupload, sarif.JustificationProvidedByRuntime, `components["billing"].controls.sca.providedDependencies`),
		pomJunit, sarif.JustificationDevDependency, devKey))
}

func TestMavenCoordinate(t *testing.T) {
	for purl, want := range map[string]string{
		"pkg:maven/org.apache.commons/commons-text@1.9": "org.apache.commons:commons-text",
		"pkg:maven/junit/junit@4.12?type=jar":           "junit:junit",
		"pkg:maven/g/a?classifier=tests":                "g:a",
		"pkg:maven/g/a#sub":                             "g:a",
		"pkg:maven/org.example/my%2Dlib@1":              "org.example:my-lib",
		"pkg:npm/lodash@4.17.20":                        "",
		"pkg:maven/only-one-segment@1":                  "",
		"pkg:maven//a@1":                                "",
		"pkg:maven/g%zz/a@1":                            "",
		"pkg:maven/g/a%zz@1":                            "",
		"":                                              "",
	} {
		got, ok := mavenCoordinate(purl)
		if got != want || ok != (want != "") {
			t.Errorf("mavenCoordinate(%q) = (%q, %v), want %q", purl, got, ok, want)
		}
	}
}

// A finding is marked only where its package is a Maven package declared in the pom at its
// location; anything else keeps what its scanner said, and a mark already there stays.
func TestMarkPomScopes(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"pom.xml":        pomScopesShop,
		"broken/pom.xml": "<project><dependencies>",
		"other.xml":      pomScopesShop,
	})
	pkg := func(purl string, dev, provided bool) *sarif.Package {
		return &sarif.Package{Name: "x", PURL: purl, Dev: dev, Provided: provided}
	}
	at := func(uri string, p *sarif.Package) sarif.Result {
		r := sarif.Result{RuleID: "r", Package: p}
		r.Location.URI = uri
		return r
	}
	const (
		provided = "pkg:maven/commons-collections/commons-collections@3.2.1"
		test     = "pkg:maven/junit/junit@4.12"
		compile  = "pkg:maven/org.apache.commons/commons-text@1.9"
	)
	results := []sarif.Result{
		at("pom.xml", pkg(provided, false, false)),
		at("pom.xml", pkg(test, false, false)),
		at("pom.xml", pkg(compile, false, false)),
		at("pom.xml", pkg(provided, false, true)),
		at("pom.xml", pkg(test, true, false)),
		at("pom.xml", pkg("pkg:npm/junit@4.12", false, false)),
		at("pom.xml", nil),
		at("other.xml", pkg(provided, false, false)),
		at("broken/pom.xml", pkg(provided, false, false)),
		at("missing/pom.xml", pkg(provided, false, false)),
		at("../pom.xml", pkg(provided, false, false)),
	}
	shared := results[0].Package
	markPomScopes(results, dir)
	type marks struct{ dev, provided bool }
	want := []marks{
		{false, true}, {true, false}, {}, {false, true}, {true, false}, {}, {}, {}, {}, {}, {},
	}
	for i, w := range want {
		p := results[i].Package
		if p == nil {
			continue
		}
		if p.Dev != w.dev || p.Provided != w.provided {
			t.Errorf("result %d at %s (%s): dev %v provided %v, want %+v", i, results[i].Location.URI, p.PURL, p.Dev, p.Provided, w)
		}
	}
	if shared.Provided {
		t.Error("the scanner's package value was changed in place rather than copied")
	}
}
