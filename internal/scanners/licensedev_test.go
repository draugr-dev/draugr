package scanners

import (
	"context"
	"errors"
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

// The recorded output under testdata/licensedev is Trivy 0.76.1 (`fs --scanners license --format
// json --include-dev-deps --offline-scan`) over two repositories holding the same package-lock.json
// packages: chalk 4.1.2 (MIT) and ckeditor5 41.4.2 (GPL-2.0-or-later). `web` declares both as
// devDependencies and `tools` as dependencies. One component per repository.

// runLicenseDev scans both components with trivy-license under the real licenses control, each
// scan replaying what Trivy wrote for its repository.
func runLicenseDev(t *testing.T, project saga.ControllerSettings, components map[string]saga.ControllerSettings) engine.Result {
	t.Helper()
	dirs := map[string]string{"web": t.TempDir(), "tools": t.TempDir()}
	repoOf := map[string]string{}
	for name, dir := range dirs {
		repoOf[dir] = name
		lock, err := os.ReadFile(filepath.Join("testdata", "licensedev", name+".package-lock.json")) // #nosec G304 -- under testdata
		if err != nil {
			t.Fatal(err)
		}
		// #nosec G703 -- a fixture copied into t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), lock, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	checkout := func(_ context.Context, url, _ string, _ git.Scope) (git.Tree, func(), error) {
		return git.Tree{Dir: dirs[url]}, func() {}, nil
	}
	// The process-wide version probe answers once and keeps the answer, and a later test reading it
	// would build another command line. A probe of this test's own fails it if anything asks.
	was := sharedTrivyVersion
	t.Cleanup(func() { sharedTrivyVersion = was })
	sharedTrivyVersion = &trivyVersionProbe{run: func(context.Context, []string) ([]byte, error) {
		t.Error("the scan asked Trivy its version, and the process keeps the answer")
		return nil, errors.New("no Trivy in this test")
	}}
	// The repository mode alone: the dispatcher's CacheVersion, Prewarm and DataState call the
	// process-wide Trivy, whatever the repository mode was given.
	repo := NewTrivyLicense().(licenseScanner).repo.(repoScanner)
	repo.checkout, repo.prewarm, repo.cacheVersion, repo.dataState = checkout, nil, nil, nil
	repo.runLogged = trivyFSRun(func(_ context.Context, dir string, argv []string) ([]byte, []byte, error) {
		if !slices.Contains(argv, "--include-dev-deps") {
			t.Errorf("trivy argv %v: Trivy would leave the development dependencies out", argv)
		}
		b, err := os.ReadFile(filepath.Join("testdata", "licensedev", repoOf[dir]+".trivy.json")) // #nosec G304 -- under testdata
		return b, nil, err
	})
	reg := engine.NewRegistry()
	reg.RegisterController(controllers.NewLicenses())
	reg.RegisterScanner(repo)

	settings := saga.ControllerSettings{"enabled": true}
	for k, v := range project {
		settings[k] = v
	}
	model := saga.Model{Config: saga.Config{Controls: map[string]saga.ControllerSettings{"licenses": settings}}}
	for _, name := range []string{"web", "tools"} {
		comp := saga.Component{Name: name, Repositories: []saga.Repository{{URL: name}}}
		if s, ok := components[name]; ok {
			comp.Controls = map[string]saga.ControllerSettings{"licenses": s}
		}
		model.Components = append(model.Components, comp)
	}
	res, err := engine.New(reg).Run(context.Background(), model)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// licenseDevOutcome is one component's ckeditor5 finding: whether it carries the development mark,
// and the setting that set it aside, or "" where it counts.
type licenseDevOutcome struct {
	dev      bool
	setAside string
}

func licenseDevOf(t *testing.T, res engine.Result, component string) licenseDevOutcome {
	t.Helper()
	var found []licenseDevOutcome
	for _, r := range res.Controls["licenses"].Report.Results {
		if r.Component != component || r.RuleID != "license/GPL-2.0-or-later/ckeditor5" {
			continue
		}
		var o licenseDevOutcome
		o.dev = r.Package != nil && r.Package.Dev
		if r.Suppressed() {
			if r.Suppression.Origin != sarif.OriginSetting || r.Suppression.Justification != sarif.JustificationDevDependency {
				t.Errorf("%s: suppressed by %+v, want the development-dependency setting", component, *r.Suppression)
			}
			o.setAside = r.Suppression.Source
		}
		found = append(found, o)
	}
	if len(found) != 1 {
		t.Fatalf("%s: %d ckeditor5 license findings, want 1", component, len(found))
	}
	return found[0]
}

// A lockfile of development dependencies is read, and its licenses are set aside by default with the
// key that decided it. The same packages declared for runtime count.
func TestLicensesSetsAsideDevelopmentDependenciesByDefault(t *testing.T) {
	res := runLicenseDev(t, nil, nil)
	if got, want := licenseDevOf(t, res, "web"), (licenseDevOutcome{dev: true, setAside: "config.controls.licenses.devDependencies"}); got != want {
		t.Errorf("web: %+v, want %+v", got, want)
	}
	if got := licenseDevOf(t, res, "tools"); got != (licenseDevOutcome{}) {
		t.Errorf("tools: %+v, want counted with no mark", got)
	}
	for _, in := range res.Controls["licenses"].Report.Inputs {
		if in.Unread != "" {
			t.Errorf("%s %s listed as unread: %s", in.Component, in.Path, in.Unread)
		}
	}
}

// A component's setting replaces the project's, for that component alone.
func TestLicensesCountsDevelopmentDependenciesWhereAComponentAsks(t *testing.T) {
	res := runLicenseDev(t, nil, map[string]saga.ControllerSettings{"web": {"devDependencies": "report"}})
	if got := licenseDevOf(t, res, "web"); got != (licenseDevOutcome{dev: true}) {
		t.Errorf("web: %+v, want counted and marked dev", got)
	}
	res = runLicenseDev(t, saga.ControllerSettings{"devDependencies": "report"},
		map[string]saga.ControllerSettings{"web": {"devDependencies": "suppress"}})
	if got, want := licenseDevOf(t, res, "web"), (licenseDevOutcome{dev: true, setAside: `components["web"].controls.licenses.devDependencies`}); got != want {
		t.Errorf("web: %+v, want %+v", got, want)
	}
}

// A name that is a development dependency in one entry and a runtime one in another is not marked:
// a license carries no version, so it may be the shipped copy's.
func TestALicenseIsMarkedOnlyWhereEveryCopyIsDev(t *testing.T) {
	doc := trivyLicenseDoc{}
	doc.Results = append(doc.Results, struct {
		Target   string                 `json:"Target"`
		Class    string                 `json:"Class"`
		Type     string                 `json:"Type"`
		Packages []trivyPackage         `json:"Packages"`
		Licenses []trivyLicense         `json:"Licenses"`
		Modified []trivyLicenseModified `json:"ExperimentalModifiedFindings"`
	}{Target: "package-lock.json", Packages: []trivyPackage{
		{Name: "a", Version: "1", Dev: true}, {Name: "a", Version: "2"}, {Name: "b", Version: "1", Dev: true},
	}})
	mark := doc.devLicenses()
	for name, want := range map[string]bool{"a": false, "b": true} {
		r := mark(sarif.Result{}, trivyLicense{PkgName: name, FilePath: "package-lock.json"})
		if got := r.Package != nil && r.Package.Dev; got != want {
			t.Errorf("%s: dev %v, want %v", name, got, want)
		}
	}
	if r := mark(sarif.Result{}, trivyLicense{FilePath: "LICENSE"}); r.Package != nil {
		t.Errorf("a license found in a file was marked: %+v", r.Package)
	}
}
