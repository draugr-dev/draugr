package scanners

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/draugr-dev/draugr/internal/tools"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// builtWith makes the govulncheck a scan would run report go as the Go it was built with.
func builtWith(t *testing.T, goRelease string) {
	t.Helper()
	orig := govulncheckBuildGo
	t.Cleanup(func() { govulncheckBuildGo = orig })
	govulncheckBuildGo = func() string { return goRelease }
}

// scaController plans one scanner over every repository a component declares.
type scaController struct{ scanner string }

func (c scaController) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: "sca", Scope: plugin.ScopeComponent, DefaultScanners: []string{c.scanner}}
}

func (c scaController) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	var jobs []plugin.ScanJob
	for _, r := range comp.Repositories {
		jobs = append(jobs, plugin.ScanJob{Scanner: c.scanner, Target: plugin.RepositoryTarget{URL: r.URL}})
	}
	return jobs, nil
}

func (c scaController) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	return plugin.ControlResult{Control: "sca", Report: sarif.Merge(reports...)}, nil
}

// govulncheckRun is one module's recorded run: symbol level, the module and gjson analyzed, and
// gjson's advisory called from main.
func govulncheckRun(module string) string {
	return `{"config":{"scan_level":"symbol"}}
{"SBOM":{"modules":[{"path":"` + module + `"},{"path":"github.com/tidwall/gjson","version":"v1.6.5"}],"roots":["` + module + `"]}}
{"osv":{"id":"GO-2021-0054","aliases":["CVE-2020-36067"]}}
{"finding":{"osv":"GO-2021-0054","fixed_version":"v1.6.6","trace":[{"module":"github.com/tidwall/gjson","version":"v1.6.5","package":"github.com/tidwall/gjson","function":"Get"},{"module":"` + module + `","package":"` + module + `","function":"main"}]}}
`
}

// Two components in two repositories, one of them declaring a newer Go than govulncheck was built
// with. That repository's job fails with the module named by its path in the repository, both
// versions and the command, without govulncheck running over it; the other is analyzed as before.
func TestGovulncheckRefusesAModuleNewerThanItsBuildGoAndAnalyzesTheOther(t *testing.T) {
	useGoVulnDB(t, noCopy)
	builtWith(t, "go1.26.10")
	orig := lookRuntime
	t.Cleanup(func() { lookRuntime = orig })
	lookRuntime = func(name string) (string, error) { return "/usr/bin/" + name, nil }

	dirs := map[string]string{
		"one": writeTree(t, map[string]string{"services/api/go.mod": "module example.com/api\n\ngo 1.27.1\n"}),
		"two": writeTree(t, map[string]string{"go.mod": "module example.com/worker\n\ngo 1.26\n"}),
	}
	var mu sync.Mutex
	var ran []string
	origExec := execArgvInDirWithEnv
	t.Cleanup(func() { execArgvInDirWithEnv = origExec })
	execArgvInDirWithEnv = func(_ context.Context, _ string, argv, _ []string) ([]byte, error) {
		mod := argv[slices.Index(argv, "-C")+1]
		mu.Lock()
		ran = append(ran, mod)
		mu.Unlock()
		return []byte(govulncheckRun(goModulePath(filepath.Join(mod, "go.mod")))), nil
	}

	s := NewGovulncheck().(repoScanner)
	s.cacheVersion = func(context.Context) string { return "govulncheck@v1.9.0" }
	s.checkout = checkoutOf(dirs)
	reg := engine.NewRegistry()
	reg.RegisterController(scaController{scanner: govulncheckScanner})
	reg.RegisterScanner(s)
	model := saga.Model{
		Config: saga.Config{Controls: map[string]saga.ControllerSettings{"sca": {"enabled": true}}},
		Components: []saga.Component{
			{Name: "api", Repositories: []saga.Repository{{URL: "one"}}},
			{Name: "worker", Repositories: []saga.Repository{{URL: "two"}}},
		},
	}
	res, err := engine.New(reg).Run(context.Background(), model)

	const want = "govulncheck was built with go1.26.10 and cannot load services/api/go.mod, which declares go 1.27.1. " +
		"Run draugr tools install govulncheck --force."
	// The run reports the job's failure, as it reports any scan error, and goes on with the rest.
	if err == nil || !strings.HasSuffix(err.Error(), "run govulncheck: "+want) {
		t.Errorf("run err = %v, want %q", err, want)
	}
	if len(res.Stats.Unscanned) != 1 {
		t.Fatalf("unscanned = %+v, want the api repository alone", res.Stats.Unscanned)
	}
	u := res.Stats.Unscanned[0]
	if u.Component != "api" || u.Target != (plugin.RepositoryTarget{URL: "one"}).Identity() || !strings.HasSuffix(u.Detail, want) {
		t.Errorf("unscanned = %+v, want api's repository with %q", u, want)
	}
	if errs := res.ScanErrors["sca"]; len(errs) != 1 || !strings.Contains(errs[0], want) {
		t.Errorf("scan errors = %q, want one naming the module", errs)
	}
	if !slices.Equal(ran, []string{dirs["two"]}) {
		t.Errorf("govulncheck ran over %v, want the worker's module alone", ran)
	}
	var got []string
	for _, r := range res.Controls["sca"].Report.Results {
		got = append(got, r.RuleID+" "+r.Location.URI+" "+string(r.Reachability.State))
	}
	if !slices.Equal(got, []string{"CVE-2020-36067 go.mod reachable"}) {
		t.Errorf("results = %v, want the worker's finding", got)
	}
}

// A go.work governs the modules under it, and the go command reads its go line, so a workspace
// declaring a newer Go is refused by name even where the module's own go.mod is old enough.
// GOWORK=off takes the workspace out of the build, and the module runs.
func TestGovulncheckReadsTheGoWorkThatGovernsAModule(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.work":    "go 1.27.0\n\nuse ./api\n",
		"api/go.mod": "module example.com/api\n\ngo 1.26\n",
	})
	argv := []string{"govulncheck", "-C", filepath.Join(root, "api"), "-format", "json", "./..."}
	run := func(context.Context, string, []string) ([]byte, error) { return []byte("ran"), nil }
	builtWith(t, "go1.26.10")

	t.Setenv("GOWORK", "")
	_, err := onBuildGo(run)(context.Background(), root, argv)
	want := "govulncheck was built with go1.26.10 and cannot load go.work, which declares go 1.27.0. " +
		"Run draugr tools install govulncheck --force."
	if err == nil || err.Error() != want {
		t.Errorf("err = %v, want %q", err, want)
	}

	t.Setenv("GOWORK", "off")
	if out, err := onBuildGo(run)(context.Background(), root, argv); err != nil || string(out) != "ran" {
		t.Errorf("under GOWORK=off: out=%q err=%v, want the module run", out, err)
	}

	// A GOWORK naming a file is the workspace, wherever it is.
	elsewhere := writeTree(t, map[string]string{"ci.work": "go 1.27.2\n"})
	t.Setenv("GOWORK", filepath.Join(elsewhere, "ci.work"))
	if _, err := onBuildGo(run)(context.Background(), root, argv); err == nil ||
		!strings.Contains(err.Error(), filepath.Join(elsewhere, "ci.work")+", which declares go 1.27.2") {
		t.Errorf("err = %v, want the workspace GOWORK names", err)
	}
}

// A go.work above the checkout is not the checkout's, and is not read.
func TestGovulncheckDoesNotReadAGoWorkOutsideTheCheckout(t *testing.T) {
	t.Setenv("GOWORK", "")
	outer := writeTree(t, map[string]string{
		"go.work":         "go 1.27.0\n",
		"repo/api/go.mod": "module example.com/api\n\ngo 1.26\n",
	})
	root := filepath.Join(outer, "repo")
	argv := []string{"govulncheck", "-C", filepath.Join(root, "api")}
	if err := checkBuildGo("go1.26.10", root, argv); err != nil {
		t.Errorf("a go.work outside the checkout was read: %v", err)
	}
}

// A module declaring a Go newer than the pin cannot be loaded by a rebuild at the pin either, so
// the command names the toolchain the module needs, and the alternative of a newer Draugr.
func TestGovulncheckNamesTheToolchainWhenTheModuleIsNewerThanThePin(t *testing.T) {
	for _, tc := range []struct{ declares, toolchain string }{
		{"1.99.2", "go1.99.2"},
		{"1.99", "go1.99.0"},
		{"1.99rc1", "go1.99rc1"},
	} {
		root := writeTree(t, map[string]string{"go.mod": "module example.com/m\n\ngo " + tc.declares + "\n"})
		err := checkBuildGo("go1.26.10", root, []string{"govulncheck", "-C", root})
		want := "govulncheck was built with go1.26.10 and cannot load go.mod, which declares go " + tc.declares + ". " +
			"Run GOTOOLCHAIN=" + tc.toolchain + " draugr tools install govulncheck --force, or upgrade Draugr."
		if err == nil || err.Error() != want {
			t.Errorf("go %s: err = %v, want %q", tc.declares, err, want)
		}
	}
}

// The build Go is read from the govulncheck on PATH, the binary a scan runs. The test binary stands
// in for it, being a Go binary, and with none on PATH there is nothing to read.
func TestReadGovulncheckBuildGoReadsTheBinaryOnPath(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	if err := os.Symlink(self, filepath.Join(bin, "govulncheck")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	if got, want := readGovulncheckBuildGo(), strings.Fields(runtime.Version())[0]; got != want {
		t.Errorf("build Go = %q, want %q", got, want)
	}
	t.Setenv("PATH", t.TempDir())
	if got := readGovulncheckBuildGo(); got != "" {
		t.Errorf("with no govulncheck on PATH, build Go = %q", got)
	}
}

// Nothing is refused where go/types would load the module, or where there is nothing to compare:
// the same language version at a later patch, a build Go that could not be read, a go.mod with no
// go line, and an argv with no module.
func TestGovulncheckRunsWhereTheBuildGoCanLoadTheModule(t *testing.T) {
	t.Setenv("GOWORK", "off")
	pin := tools.GoToolchain(govulncheckScanner)
	newer := writeTree(t, map[string]string{"go.mod": "module example.com/m\n\ngo 1.27.9\n"})
	bare := writeTree(t, map[string]string{"go.mod": "module example.com/m\n"})
	for _, tc := range []struct {
		name, built, root string
		argv              []string
	}{
		{"a later patch of the same language version", pin, newer, []string{"govulncheck", "-C", newer}},
		{"the build Go could not be read", "", newer, []string{"govulncheck", "-C", newer}},
		{"no go line", "go1.26.10", bare, []string{"govulncheck", "-C", bare}},
		{"no module in the argv", "go1.26.10", newer, []string{"govulncheck", "-C"}},
	} {
		if err := checkBuildGo(tc.built, tc.root, tc.argv); err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}
