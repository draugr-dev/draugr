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

// The recorded output under testdata/devdeps is Trivy 0.76.1 (with --include-dev-deps) and Grype
// 0.121.0 (with --by-cve), each run over two repositories holding the same two packages:
// lodash 4.17.20 as a dependency and nanoid 3.3.7 as a devDependency. `web` holds them in
// npm/package-lock.json and `tools` in pnpm/pnpm-lock.yaml. Trivy marks nanoid `Dev` in both; Grype
// reports nanoid from the pnpm lockfile only, with no mark, and from the npm one not at all.
//
// One component per repository, so each lockfile format is a component's whole answer and the two
// answers can be compared.

// devDepsRead returns one recorded output.
func devDepsRead(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "devdeps", name)) // #nosec G304 -- under testdata
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// runDevDeps scans both components with trivy-fs and grype-fs under the real sca control, each
// scanner replaying what it wrote for the repository it was given.
func runDevDeps(t *testing.T, sca saga.ControllerSettings, components map[string]saga.ControllerSettings) engine.Result {
	t.Helper()
	dirs := map[string]string{"web": t.TempDir(), "tools": t.TempDir()}
	repoOf := map[string]string{dirs["web"]: "web", dirs["tools"]: "tools"}
	checkout := func(_ context.Context, url, _ string, _ git.Scope) (git.Tree, func(), error) {
		return git.Tree{Dir: dirs[url]}, func() {}, nil
	}

	prior := grypeRunInDir
	t.Cleanup(func() { grypeRunInDir = prior })
	grypeRunInDir = func(_ context.Context, dir string, argv []string) ([]byte, error) {
		repo := repoOf[dir]
		fakeGrypeOutputs(t, argv, string(devDepsRead(t, repo+".grype.json")))
		return devDepsRead(t, repo+".grype.sarif"), nil
	}
	grype := NewGrypeFS().(repoScanner)
	grype.checkout, grype.prewarm, grype.cacheVersion, grype.dataState = checkout, nil, nil, nil

	trivy := NewTrivyFS().(repoScanner)
	trivy.checkout, trivy.prewarm, trivy.cacheVersion, trivy.dataState = checkout, nil, nil, nil
	trivy.runLogged = trivyFSRun(func(_ context.Context, dir string, argv []string) ([]byte, []byte, error) {
		if !slices.Contains(argv, "--include-dev-deps") {
			t.Errorf("trivy argv %v: Trivy would leave the development dependencies out", argv)
		}
		return devDepsRead(t, repoOf[dir]+".trivy.json"), nil, nil
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
	for _, name := range []string{"web", "tools"} {
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

// devOutcome is one component's answer: the flaws counted, as "<vulnerability> <package>" sorted,
// and every finding set aside, as "<tool> <vulnerability> <package>" with the suppression.
type devOutcome struct {
	counted    []string
	suppressed map[string]sarif.Suppression
}

func devOutcomeOf(t *testing.T, res engine.Result, component string) devOutcome {
	t.Helper()
	out := devOutcome{suppressed: map[string]sarif.Suppression{}}
	for _, r := range res.Controls["sca"].Report.Results {
		if r.Component != component {
			continue
		}
		if r.Package == nil {
			t.Fatalf("%s %s %s carries no package", component, r.Tool, r.RuleID)
		}
		// Every copy of nanoid is a development dependency, Grype's included, and lodash never is.
		if want := r.Package.Name == "nanoid"; r.Package.Dev != want {
			t.Errorf("%s %s %s: dev %v, want %v", component, r.Tool, r.RuleID, r.Package.Dev, want)
		}
		id := r.VulnerabilityID() + " " + r.Package.Name
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
	devDepsLodash = []string{"CVE-2021-23337 lodash"}
	devDepsAll    = []string{
		"CVE-2021-23337 lodash", "CVE-2024-55565 nanoid", "CVE-2026-67213 nanoid",
		"CVE-2026-67214 nanoid", "CVE-2026-73086 nanoid",
	}
	devDepsNanoid = []string{"CVE-2024-55565", "CVE-2026-67213", "CVE-2026-67214", "CVE-2026-73086"}
)

// checkSetAside checks that exactly the given tools' nanoid findings are suppressed by the setting
// named, with the development reason.
func checkSetAside(t *testing.T, component string, got devOutcome, tools []string, source string) {
	t.Helper()
	want := map[string]bool{}
	for _, tool := range tools {
		for _, v := range devDepsNanoid {
			want[tool+" "+v+" nanoid"] = true
		}
	}
	for key, s := range got.suppressed {
		if !want[key] {
			t.Errorf("%s: %s suppressed, want counted", component, key)
			continue
		}
		if s.Origin != sarif.OriginSetting || s.Justification != sarif.JustificationDevDependency || s.Source != source {
			t.Errorf("%s: %s suppression %+v, want origin %q, reason %q, source %q",
				component, key, s, sarif.OriginSetting, sarif.JustificationDevDependency, source)
		}
	}
	for key := range want {
		if _, ok := got.suppressed[key]; !ok {
			t.Errorf("%s: %s not suppressed", component, key)
		}
	}
}

// With nothing written, an npm and a pnpm lockfile holding the same development dependency give the
// same answer: lodash counts, and every finding in nanoid stays in the report suppressed, Grype's
// pnpm copies included, though Grype marks none of them.
func TestDevDependenciesAreSuppressedByDefaultWhateverTheLockfile(t *testing.T) {
	res := runDevDeps(t, nil, nil)
	web, tools := devOutcomeOf(t, res, "web"), devOutcomeOf(t, res, "tools")
	if !slices.Equal(web.counted, devDepsLodash) || !slices.Equal(tools.counted, devDepsLodash) {
		t.Errorf("counted: npm %v, pnpm %v, want %v in both", web.counted, tools.counted, devDepsLodash)
	}
	const source = "config.controls.sca.devDependencies"
	checkSetAside(t, "web", web, []string{"trivy"}, source)
	checkSetAside(t, "tools", tools, []string{"trivy", "grype"}, source)
	if want := 4 + 8; res.DevDependencies != want {
		t.Errorf("DevDependencies = %d, want %d", res.DevDependencies, want)
	}
	if res.Suppressed != 0 {
		t.Errorf("Suppressed = %d, want 0: config.exclude set nothing aside", res.Suppressed)
	}
}

// report counts every finding in nanoid, marked dev, the same in both lockfiles.
func TestDevDependenciesReportCountsThemMarked(t *testing.T) {
	res := runDevDeps(t, saga.ControllerSettings{"devDependencies": "report"}, nil)
	for _, c := range []string{"web", "tools"} {
		got := devOutcomeOf(t, res, c)
		if !slices.Equal(got.counted, devDepsAll) {
			t.Errorf("%s counted %v, want %v", c, got.counted, devDepsAll)
		}
		if len(got.suppressed) != 0 {
			t.Errorf("%s suppressed %v, want none", c, got.suppressed)
		}
	}
	if res.DevDependencies != 0 {
		t.Errorf("DevDependencies = %d, want 0", res.DevDependencies)
	}
}

// A component's setting replaces the project's, and the suppression names the component's key.
func TestAComponentsDevDependenciesReplacesTheProjects(t *testing.T) {
	res := runDevDeps(t, saga.ControllerSettings{"devDependencies": "report"},
		map[string]saga.ControllerSettings{"tools": {"devDependencies": "suppress"}})
	web, tools := devOutcomeOf(t, res, "web"), devOutcomeOf(t, res, "tools")
	if !slices.Equal(web.counted, devDepsAll) || len(web.suppressed) != 0 {
		t.Errorf("web counted %v, suppressed %v, want every finding counted", web.counted, web.suppressed)
	}
	if !slices.Equal(tools.counted, devDepsLodash) {
		t.Errorf("tools counted %v, want %v", tools.counted, devDepsLodash)
	}
	checkSetAside(t, "tools", tools, []string{"trivy", "grype"}, `components["tools"].controls.sca.devDependencies`)
}

// The deprecated includeDevDeps: true is read as report, and named in a warning with its
// replacement.
func TestIncludeDevDepsIsReadAsReport(t *testing.T) {
	res := runDevDeps(t, saga.ControllerSettings{"trivyFs": map[string]any{"includeDevDeps": true}}, nil)
	for _, c := range []string{"web", "tools"} {
		if got := devOutcomeOf(t, res, c); !slices.Equal(got.counted, devDepsAll) || len(got.suppressed) != 0 {
			t.Errorf("%s counted %v, suppressed %v, want every finding counted", c, got.counted, got.suppressed)
		}
	}
	model := saga.Model{Config: saga.Config{Controls: map[string]saga.ControllerSettings{
		"sca": {"trivyFs": map[string]any{"includeDevDeps": true}},
	}}}
	warnings := controllers.NewSCA().(interface{ Warnings(saga.Model) []string }).Warnings(model)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "config.controls.sca.trivyFs.includeDevDeps is deprecated") ||
		!strings.Contains(warnings[0], "config.controls.sca.devDependencies: report") {
		t.Errorf("warnings %q, want one naming includeDevDeps and devDependencies: report", warnings)
	}
}
