package scanners

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/internal/scanpolicy"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// requiringGoMod is a go.mod for module that requires gjson, which govulncheckRun's SBOM lists,
// echo and x/net, which it does not, and a module a replace directive swaps for a fork.
func requiringGoMod(module string) string {
	return "module " + module + "\n\ngo 1.22\n\nrequire (\n" +
		"\tgithub.com/tidwall/gjson v1.6.5\n" +
		"\tgithub.com/labstack/echo/v4 v4.9.0\n" +
		"\tgolang.org/x/net v0.17.0\n" +
		"\texample.com/forked v1.0.0\n" +
		")\n\nreplace example.com/forked => example.com/fork v1.0.1\n"
}

// onLinux runs the test as if the machine were linux/amd64, with no build tags or workspace set in
// the environment, so the build a verdict names is the same on every machine.
func onLinux(t *testing.T) {
	t.Helper()
	onHost(t, linuxHost)
	t.Setenv("GOFLAGS", "")
	t.Setenv("GOWORK", "")
}

// notBuiltOf is each verdict as "path package platforms tags".
func notBuiltOf(report sarif.Report) []string {
	var out []string
	for _, v := range report.PackageVerdicts {
		r := v.Reachability
		if r.State != sarif.ReachabilityUnreachable || r.Method != sarif.MethodNotBuilt || r.Analyzer != govulncheckScanner ||
			r.AsOf != "2026-11-16" || r.Build == nil {
			out = append(out, "malformed "+v.Package)
			continue
		}
		out = append(out, v.Path+" "+v.Package+" "+strings.Join(r.Build.Platforms, ",")+" "+strings.Join(r.Build.Tags, ","))
	}
	return out
}

var analyzedOn = time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)

// After a clean load at symbol level, a requirement missing from the SBOM is marked as not built,
// with the build named. A requirement the SBOM lists, and one a replace directive swaps out, are
// not: the SBOM names a replaced module by its replacement.
func TestParseGovulncheckMarksARequirementTheBuildDoesNotCompile(t *testing.T) {
	onLinux(t)
	t.Setenv("GOFLAGS", "")
	t.Setenv("GOWORK", "")
	dir := writeTree(t, map[string]string{"go.mod": requiringGoMod("example.com/app"), "main.go": goMain})

	report, err := parseGovulncheckAt([]byte(govulncheckRun("example.com/app")), dir, analyzedOn)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"go.mod github.com/labstack/echo/v4 linux/amd64 ",
		"go.mod golang.org/x/net linux/amd64 ",
	}
	if got := notBuiltOf(report); !slices.Equal(got, want) {
		t.Errorf("verdicts = %q, want %q", got, want)
	}

	// The tags GOFLAGS sets are part of the build, and named with it.
	t.Setenv("GOFLAGS", "-tags=dev")
	report, err = parseGovulncheckAt([]byte(govulncheckRun("example.com/app")), dir, analyzedOn)
	if err != nil {
		t.Fatal(err)
	}
	if got := notBuiltOf(report); len(got) != 2 || got[0] != "go.mod github.com/labstack/echo/v4 linux/amd64 dev" {
		t.Errorf("verdicts with -tags=dev = %q, want the tag named", got)
	}
}

// Uncertainty marks nothing: a run below symbol level, a run that wrote no SBOM, a module that did
// not load, a go.mod that does not parse, and a go.work replacing the requirement.
func TestParseGovulncheckMarksNothingItCannotRead(t *testing.T) {
	onLinux(t)
	t.Setenv("GOFLAGS", "")
	t.Setenv("GOWORK", "")
	dir := writeTree(t, map[string]string{"go.mod": requiringGoMod("example.com/app"), "main.go": goMain})
	run := govulncheckRun("example.com/app")
	sbomLess := strings.Join(slices.DeleteFunc(strings.Split(run, "\n"), func(l string) bool {
		return strings.HasPrefix(l, `{"SBOM"`)
	}), "\n")

	for name, out := range map[string]string{
		"package level": strings.Replace(run, `"scan_level":"symbol"`, `"scan_level":"package"`, 1),
		"no SBOM":       sbomLess,
		"not loaded":    `{"draugrUnloaded":{"goMod":"go.mod","reason":"govulncheck: main.go:5:2: undefined: Assets"}}` + "\n",
	} {
		report, err := parseGovulncheckAt([]byte(out), dir, analyzedOn)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(report.PackageVerdicts) != 0 {
			t.Errorf("%s: verdicts = %q, want none", name, notBuiltOf(report))
		}
		if name == "not loaded" && (len(report.Inputs) != 1 || report.Inputs[0].Path != "go.mod" || !report.Inputs[0].Analysis) {
			t.Errorf("not loaded: inputs = %+v, want go.mod kept as unread", report.Inputs)
		}
	}

	broken := writeTree(t, map[string]string{"go.mod": "module example.com/app\n\nrequire (\n", "main.go": goMain})
	if report, err := parseGovulncheckAt([]byte(govulncheckRun("example.com/app")), broken, analyzedOn); err != nil || len(report.PackageVerdicts) != 0 {
		t.Errorf("unparsable go.mod: verdicts = %q, err = %v, want none", notBuiltOf(report), err)
	}

	workspace := writeTree(t, map[string]string{
		"go.work":     "go 1.22\n\nuse ./app\n\nreplace github.com/labstack/echo/v4 => ./echo\n",
		"app/go.mod":  requiringGoMod("example.com/app"),
		"app/main.go": goMain,
	})
	report, err := parseGovulncheckAt([]byte(govulncheckRun("example.com/app")), workspace, analyzedOn)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := notBuiltOf(report), []string{"app/go.mod golang.org/x/net linux/amd64 "}; !slices.Equal(got, want) {
		t.Errorf("workspace verdicts = %q, want %q, echo replaced by the go.work", got, want)
	}
}

// A module holding Windows-only code gets a run for windows/amd64 beside the host's. A requirement in
// the SBOM of either is not marked, and the one in neither is marked with both platforms named.
// Where the Windows run did not load, the module's build was not read whole, and nothing is marked.
func TestParseGovulncheckReadsTheBuildOfEveryPlatform(t *testing.T) {
	onLinux(t)
	t.Setenv("GOFLAGS", "")
	t.Setenv("GOWORK", "")
	dir := writeTree(t, map[string]string{
		"go.mod": "module example.com/app\n\ngo 1.22\n\nrequire (\n" +
			"\tgolang.org/x/sys v0.20.0\n\tgithub.com/labstack/echo/v4 v4.9.0\n)\n",
		"main.go": goMain,
		"win.go":  "//go:build windows\n\npackage main\n\nimport _ \"golang.org/x/sys/windows\"\n",
	})
	if plan, _ := govulncheckPlan(dir); len(plan) != 2 || plan[1].build == nil || plan[1].build.Platform.String() != "windows/amd64" {
		t.Fatalf("plan = %+v, want the host and windows/amd64", plan)
	}
	host := `{"config":{"scan_level":"symbol"}}
{"SBOM":{"modules":[{"path":"example.com/app"}],"roots":["example.com/app"]}}
`
	windows := `{"config":{"scan_level":"symbol"}}
{"SBOM":{"modules":[{"path":"example.com/app"},{"path":"golang.org/x/sys","version":"v0.20.0"}],"roots":["example.com/app"]}}
`
	report, err := parseGovulncheckAt([]byte(host+windows), dir, analyzedOn)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := notBuiltOf(report), []string{"go.mod github.com/labstack/echo/v4 linux/amd64,windows/amd64 "}; !slices.Equal(got, want) {
		t.Errorf("verdicts = %q, want %q", got, want)
	}

	unloaded := `{"draugrUnloaded":{"goMod":"go.mod","reason":"govulncheck: x","platform":"windows/amd64"}}` + "\n"
	report, err = parseGovulncheckAt([]byte(host+unloaded), dir, analyzedOn)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.PackageVerdicts) != 0 {
		t.Errorf("windows run unloaded: verdicts = %q, want none", notBuiltOf(report))
	}
}

// requirementScanner reports one advisory per package at each go.mod it is given, as a manifest
// scanner reads a go.mod, so the test can see which findings a verdict reaches.
type requirementScanner struct {
	goMods map[string]map[string][]string
}

func (requirementScanner) Info() plugin.ScannerInfo {
	return plugin.ScannerInfo{Name: "manifest", Controls: []string{"sca"}, TargetKinds: []plugin.TargetKind{plugin.TargetRepository}}
}

func (m requirementScanner) Scan(_ context.Context, target plugin.Target, _ plugin.Config) (sarif.Report, error) {
	repo := target.(plugin.RepositoryTarget)
	var results []sarif.Result
	for gomod, pkgs := range m.goMods[repo.URL] {
		for _, pkg := range pkgs {
			rule := map[string]string{
				"github.com/tidwall/gjson":    "CVE-2020-36067",
				"github.com/labstack/echo/v4": "CVE-2022-40083",
			}[pkg]
			results = append(results, sarif.Result{
				Tool: "manifest", RuleID: rule, Level: sarif.LevelError, Message: pkg,
				Location:   sarif.Location{URI: gomod},
				Repository: repo.Source(),
				Package:    &sarif.Package{Name: pkg, Version: "v1.0.0", Ecosystem: "gomod"},
			})
		}
	}
	return sarif.Report{Tool: "manifest", Results: results}, nil
}

// Two components in two repositories, through the engine. In the first, the root module loads
// cleanly and its build does not compile echo, so echo's finding is marked not built and ranked as an
// unreachable one is; a nested module requiring echo fails to load, and its echo finding keeps its
// band, no verdict and the unread-files caveat. In the second, the build compiles echo, so its echo
// finding is not marked. A verdict reached in one repository does not reach the other.
func TestGovulncheckMarksWhatACleanBuildDoesNotCompile(t *testing.T) {
	useGoVulnDB(t, noCopy)
	builtWith(t, "")
	onLinux(t)
	t.Setenv("GOFLAGS", "")
	t.Setenv("GOWORK", "")
	orig := lookRuntime
	t.Cleanup(func() { lookRuntime = orig })
	lookRuntime = func(name string) (string, error) { return "/usr/bin/" + name, nil }

	dirs := map[string]string{
		"one": writeTree(t, map[string]string{
			"go.mod":  requiringGoMod("example.com/app"),
			"main.go": goMain,
			"fixtures/go.mod": "module github.com/syncthing/syncthing\n\ngo 1.22\n\n" +
				"require github.com/labstack/echo/v4 v4.9.0\n",
			"fixtures/cmd/infra/strelaypoolsrv/main.go":          relaypoolMain,
			"fixtures/cmd/infra/strelaypoolsrv/auto/doc.go":      "// Package auto contains auto generated files for web assets.\npackage auto\n",
			"fixtures/cmd/infra/strelaypoolsrv/auto/noassets.go": noassets,
		}),
		"two": writeTree(t, map[string]string{
			"go.mod":  requiringGoMod("example.com/worker"),
			"main.go": goMain,
		}),
	}
	failing := filepath.Join(dirs["one"], "fixtures")

	origExec := execArgvInDirWithEnv
	t.Cleanup(func() { execArgvInDirWithEnv = origExec })
	execArgvInDirWithEnv = func(ctx context.Context, dir string, argv, _ []string) ([]byte, error) {
		mod := argv[slices.Index(argv, "-C")+1]
		if mod == failing {
			return failLoading(ctx, t, dir, loadStderr(t, "undefined-tagged.stderr", mod))
		}
		run := govulncheckRun(goModulePath(filepath.Join(mod, "go.mod")))
		if mod == dirs["two"] {
			run = strings.Replace(run, `{"path":"github.com/tidwall/gjson","version":"v1.6.5"}`,
				`{"path":"github.com/tidwall/gjson","version":"v1.6.5"},{"path":"github.com/labstack/echo/v4","version":"v4.9.0"}`, 1)
		}
		return []byte(run), nil
	}

	s := NewGovulncheck().(repoScanner)
	s.cacheVersion = func(context.Context) string { return "govulncheck@v1.9.0" }
	s.checkout = checkoutOf(dirs)
	reg := engine.NewRegistry()
	reg.RegisterController(twoScannerSCA{scaController{scanner: govulncheckScanner}})
	reg.RegisterScanner(s)
	reg.RegisterScanner(requirementScanner{goMods: map[string]map[string][]string{
		"one": {
			"go.mod":          {"github.com/tidwall/gjson", "github.com/labstack/echo/v4"},
			"fixtures/go.mod": {"github.com/labstack/echo/v4"},
		},
		"two": {"go.mod": {"github.com/tidwall/gjson", "github.com/labstack/echo/v4"}},
	}})
	model := saga.Model{
		Config: saga.Config{Controls: map[string]saga.ControllerSettings{"sca": {"enabled": true}}},
		Components: []saga.Component{
			{Name: "api", Exposure: saga.ExposurePublic, Criticality: saga.CriticalityCritical,
				Repositories: []saga.Repository{{URL: "one"}}},
			{Name: "worker", Exposure: saga.ExposurePublic, Criticality: saga.CriticalityCritical,
				Repositories: []saga.Repository{{URL: "two"}}},
		},
	}
	res, err := engine.New(reg, engine.WithPrioritization(scanpolicy.PrioritizerWith(nil, nil))).Run(context.Background(), model)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(res.ScanErrors) != 0 {
		t.Fatalf("scan errors = %v", res.ScanErrors)
	}

	verdicts, bands := map[string]string{}, map[string]string{}
	var build *sarif.AnalyzedBuild
	for _, r := range res.Controls["sca"].Report.Results {
		key := r.Component + " " + r.Location.URI + " " + r.Package.Name
		bands[key] = r.Priority
		verdicts[key] = "none"
		if v := r.Reachability; v != nil {
			verdicts[key] = string(v.State) + " " + v.Method
			if v.Method == sarif.MethodNotBuilt {
				verdicts[key] += " ranked " + string(v.RankedAs)
				build = v.Build
			}
		}
	}
	want := map[string]string{
		"api go.mod github.com/tidwall/gjson":             "reachable call-graph",
		"api go.mod github.com/labstack/echo/v4":          "unreachable not-built ranked medium",
		"api fixtures/go.mod github.com/labstack/echo/v4": "none",
		"worker go.mod github.com/tidwall/gjson":          "reachable call-graph",
		"worker go.mod github.com/labstack/echo/v4":       "none",
	}
	if len(verdicts) != len(want) {
		t.Errorf("findings = %v, want %v", verdicts, want)
	}
	for k, v := range want {
		if verdicts[k] != v {
			t.Errorf("%s: verdict = %q, want %q", k, verdicts[k], v)
		}
	}
	if build == nil || !slices.Equal(build.Platforms, []string{"linux/amd64"}) || len(build.Tags) != 0 {
		t.Errorf("build = %+v, want linux/amd64 and no tags", build)
	}
	if lowered, kept := bands["api go.mod github.com/labstack/echo/v4"], bands["worker go.mod github.com/labstack/echo/v4"]; lowered == kept ||
		kept != bands["api fixtures/go.mod github.com/labstack/echo/v4"] {
		t.Errorf("bands = %v, want the not-built finding below the same finding unmarked", bands)
	}

	var unread []string
	for _, cov := range res.Inputs {
		for _, u := range cov.Unread {
			unread = append(unread, cov.Component+" "+u.Path)
		}
	}
	if !slices.Equal(unread, []string{"api fixtures/go.mod"}) {
		t.Errorf("unread = %q, want the module that did not load", unread)
	}
}
