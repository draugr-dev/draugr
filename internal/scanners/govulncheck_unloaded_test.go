package scanners

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/draugr-dev/draugr/internal/scanpolicy"
	"github.com/draugr-dev/draugr/internal/toolexec"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// loadStderr reads a recorded govulncheck stderr from testdata/govulncheck-load, with {{module}}
// standing for the module's directory and {{modcache}} for the module cache, as they were on the
// machine it was recorded on.
func loadStderr(t *testing.T, name, module string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "govulncheck-load", name)) // #nosec G304 -- a fixture of this package
	if err != nil {
		t.Fatal(err)
	}
	s := strings.ReplaceAll(string(raw), "{{module}}", module)
	return strings.ReplaceAll(s, "{{modcache}}", "/home/dev/go/pkg/mod")
}

// failLoading runs a real process that does what govulncheck does over a module it cannot load:
// writes its config message to stdout, the recorded stderr to stderr, and exits 1.
func failLoading(ctx context.Context, t *testing.T, dir, stderr string) ([]byte, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stderr")
	if err := os.WriteFile(path, []byte(stderr), 0o600); err != nil {
		t.Fatal(err)
	}
	return toolexec.RunWithEnv(ctx, dir, []string{"sh", "-c",
		`printf '{"config":{"scan_level":"symbol"}}\n'; cat "$0" >&2; exit 1`, path}, nil)
}

// manifestScanner reports gjson's advisory at each go.mod it is given, and each go.mod as read, as a
// manifest scanner does, so the test can see which of them a verdict reaches and which stays unread.
type manifestScanner struct{ goMods map[string][]string }

func (manifestScanner) Info() plugin.ScannerInfo {
	return plugin.ScannerInfo{Name: "manifest", Controls: []string{"sca"}, TargetKinds: []plugin.TargetKind{plugin.TargetRepository}}
}

func (m manifestScanner) Scan(_ context.Context, target plugin.Target, _ plugin.Config) (sarif.Report, error) {
	repo := target.(plugin.RepositoryTarget)
	var results []sarif.Result
	var inputs []sarif.Input
	for _, gomod := range m.goMods[repo.URL] {
		inputs = append(inputs, sarif.Input{Scanner: "manifest", Repository: repo.Source(), Path: gomod, Packages: 1})
		results = append(results, sarif.Result{
			Tool: "manifest", RuleID: "CVE-2020-36067", Level: sarif.LevelError, Message: "gjson",
			Location:   sarif.Location{URI: gomod},
			Repository: repo.Source(),
			Package:    &sarif.Package{Name: "github.com/tidwall/gjson", Version: "v1.6.5", Ecosystem: "gomod"},
		})
	}
	return sarif.Report{Tool: "manifest", Results: results, Inputs: inputs}, nil
}

// twoScannerSCA plans the manifest scanner and govulncheck over every repository a component
// declares.
type twoScannerSCA struct{ scaController }

func (twoScannerSCA) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	var jobs []plugin.ScanJob
	for _, r := range comp.Repositories {
		for _, s := range []string{"manifest", govulncheckScanner} {
			jobs = append(jobs, plugin.ScanJob{Scanner: s, Target: plugin.RepositoryTarget{URL: r.URL}})
		}
	}
	return jobs, nil
}

// Two components in two repositories. In the first, the root module loads and a nested module
// fails to load; in the second, the root module loads and a nested module holds only a
// `//go:build tools` file. The run does not fail. The modules that loaded keep their verdicts, the
// failed module's go.mod is listed as unread with its first diagnostic, and its finding keeps its
// band with no verdict. The tools-only module never runs and is named nowhere.
func TestGovulncheckKeepsTheModulesThatLoadedWhenOneDoesNot(t *testing.T) {
	useGoVulnDB(t, noCopy)
	builtWith(t, "")
	orig := lookRuntime
	t.Cleanup(func() { lookRuntime = orig })
	lookRuntime = func(name string) (string, error) { return "/usr/bin/" + name, nil }

	dirs := map[string]string{
		"one": writeTree(t, map[string]string{
			"go.mod":                     "module example.com/app\n\ngo 1.22\n",
			"main.go":                    goMain,
			"fixtures/go.mod":            "module example.com/fixtures\n\ngo 1.22\n",
			"fixtures/lib/api/api.go":    "package api\n",
			"fixtures/lib/api/auto/x.go": "package auto\n",
		}),
		"two": writeTree(t, map[string]string{
			"go.mod":         "module example.com/worker\n\ngo 1.22\n",
			"main.go":        goMain,
			"tools/go.mod":   "module example.com/tools\n\ngo 1.22\n",
			"tools/tools.go": "//go:build tools\n\npackage tools\n\nimport _ \"example.com/gen\"\n",
		}),
	}
	failing := filepath.Join(dirs["one"], "fixtures")

	var mu sync.Mutex
	var ran []string
	origExec := execArgvInDirWithEnv
	t.Cleanup(func() { execArgvInDirWithEnv = origExec })
	execArgvInDirWithEnv = func(ctx context.Context, dir string, argv, _ []string) ([]byte, error) {
		mod := argv[slices.Index(argv, "-C")+1]
		mu.Lock()
		ran = append(ran, mod)
		mu.Unlock()
		if mod == failing {
			return failLoading(ctx, t, dir, loadStderr(t, "undefined-tagged.stderr", mod))
		}
		return []byte(govulncheckRun(goModulePath(filepath.Join(mod, "go.mod")))), nil
	}

	s := NewGovulncheck().(repoScanner)
	s.cacheVersion = func(context.Context) string { return "govulncheck@v1.9.0" }
	s.checkout = checkoutOf(dirs)
	reg := engine.NewRegistry()
	reg.RegisterController(twoScannerSCA{scaController{scanner: govulncheckScanner}})
	reg.RegisterScanner(s)
	reg.RegisterScanner(manifestScanner{goMods: map[string][]string{
		"one": {"go.mod", "fixtures/go.mod"},
		"two": {"go.mod"},
	}})
	model := saga.Model{
		Config: saga.Config{Controls: map[string]saga.ControllerSettings{"sca": {"enabled": true}}},
		Components: []saga.Component{
			{Name: "api", Exposure: saga.ExposurePublic, Criticality: saga.CriticalityCritical,
				Repositories: []saga.Repository{{URL: "one"}}},
			{Name: "worker", Repositories: []saga.Repository{{URL: "two"}}},
		},
	}
	res, err := engine.New(reg, engine.WithPrioritization(scanpolicy.PrioritizerWith(nil, nil))).Run(context.Background(), model)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(res.ScanErrors) != 0 || len(res.Stats.Unscanned) != 0 {
		t.Errorf("scan errors = %v, unscanned = %+v, want neither", res.ScanErrors, res.Stats.Unscanned)
	}

	slices.Sort(ran)
	want := []string{dirs["one"], failing, dirs["two"]}
	slices.Sort(want)
	if !slices.Equal(ran, want) {
		t.Errorf("govulncheck ran over %v, want %v and not the tools-only module", ran, want)
	}

	verdicts := map[string]string{}
	bands := map[string]string{}
	for _, r := range res.Controls["sca"].Report.Results {
		key := r.Component + " " + r.Location.URI
		bands[key] = r.Priority
		verdicts[key] = "none"
		if r.Reachability != nil {
			verdicts[key] = string(r.Reachability.State)
		}
	}
	wantVerdicts := map[string]string{
		"api go.mod":          "reachable",
		"api fixtures/go.mod": "none",
		"worker go.mod":       "reachable",
	}
	if len(verdicts) != len(wantVerdicts) {
		t.Errorf("findings = %v, want %v", verdicts, wantVerdicts)
	}
	for k, v := range wantVerdicts {
		if verdicts[k] != v {
			t.Errorf("%s: verdict = %q, want %q", k, verdicts[k], v)
		}
	}
	if bands["api fixtures/go.mod"] == "" || bands["api fixtures/go.mod"] != bands["api go.mod"] {
		t.Errorf("bands = %v, want the unanalyzed finding banded as the analyzed one of the same severity", bands)
	}

	var unread []string
	for _, cov := range res.Inputs {
		for _, u := range cov.Unread {
			unread = append(unread, cov.Component+" "+cov.Control+" "+u.Path+": "+u.Reason)
		}
	}
	wantUnread := []string{"api sca fixtures/go.mod: not loaded by govulncheck: fixtures/cmd/infra/strelaypoolsrv/main.go:294:17: undefined: auto.Assets"}
	if !slices.Equal(unread, wantUnread) {
		t.Errorf("unread = %q, want %q", unread, wantUnread)
	}
}

// Only a failure to load packages is recorded against the module. A refusal before the run, an
// error govulncheck reports for every module, a run with no module named and a missing binary
// still fail the job.
func TestOnUnloadedPassesOtherFailuresThrough(t *testing.T) {
	root := t.TempDir()
	mod := filepath.Join(root, "svc")
	argv := []string{"govulncheck", "-C", mod, "-format", "json", "./..."}
	exit := func(stderr string) error { return &exec.ExitError{Stderr: []byte(stderr)} }
	for _, tc := range []struct {
		name string
		argv []string
		err  error
	}{
		{"not an exit", argv, errors.New("govulncheck was built with go1.26.10 and cannot load svc/go.mod")},
		{"a database it cannot reach", argv, exit("govulncheck: fetching vulnerabilities: Get \"https://vuln.go.dev/index/modules.json\": dial tcp: lookup vuln.go.dev: no such host\n")},
		{"a toolchain mismatch", argv, exit("govulncheck: Loading packages failed, possibly due to a mismatch between the Go version\n")},
		{"no module in the argv", []string{"govulncheck", "./..."}, exit("govulncheck: loading packages: \nmain.go:1:1: expected 'package'\n")},
		{"a missing binary", argv, exec.ErrNotFound},
	} {
		run := onUnloaded(func(context.Context, string, []string) ([]byte, error) { return []byte("partial"), tc.err })
		out, err := run(context.Background(), root, tc.argv)
		if !errors.Is(err, tc.err) || string(out) != "partial" {
			t.Errorf("%s: out = %q, err = %v, want the run's own answer", tc.name, out, err)
		}
	}
}

// A module that loads nothing, and one at the checkout root, are each recorded with their go.mod and
// the line that says why, with the checkout and the module cache taken off the paths.
func TestOnUnloadedNamesTheGoModAndTheFirstDiagnostic(t *testing.T) {
	root := t.TempDir()
	for _, tc := range []struct {
		name, mod, stderr, want string
	}{
		{"no packages", filepath.Join(root, "man"), "govulncheck: no packages matched the provided patterns\n",
			`{"draugrUnloaded":{"goMod":"man/go.mod","reason":"not loaded by govulncheck: no packages matched the provided patterns"}}`},
		{"a header with the cause on it", root,
			"govulncheck: loading packages: err: exit status 1: stderr: go: updates to go.mod needed; to update it:\n\tgo mod tidy\n",
			`{"draugrUnloaded":{"goMod":"go.mod","reason":"not loaded by govulncheck: err: exit status 1: stderr: go: updates to go.mod needed; to update it:"}}`},
		{"a diagnostic in the module cache", root,
			"govulncheck: loading packages: \nThere are errors with the provided package patterns:\n\n-: # example.com/x\n" +
				"# [pkg-config --cflags  -- gtk4]\n/home/dev/go/pkg/mod/example.com/x@v1.0.0/x.go:9:8: could not import C (no metadata for C)\n",
			`{"draugrUnloaded":{"goMod":"go.mod","reason":"not loaded by govulncheck: example.com/x@v1.0.0/x.go:9:8: could not import C (no metadata for C)"}}`},
		{"nothing past the framing", root, "govulncheck: loading packages: \n",
			`{"draugrUnloaded":{"goMod":"go.mod","reason":"not loaded by govulncheck: no diagnostic"}}`},
	} {
		run := onUnloaded(func(context.Context, string, []string) ([]byte, error) {
			return []byte(`{"config":{}}`), &exec.ExitError{Stderr: []byte(tc.stderr)}
		})
		out, err := run(context.Background(), root, []string{"govulncheck", "-C", tc.mod, "./..."})
		if err != nil || strings.TrimSpace(string(out)) != tc.want {
			t.Errorf("%s: out = %s, err = %v, want %s", tc.name, out, err, tc.want)
		}
	}
}

// Every module failing still parses: each is unread, and nothing is reported as analyzed.
func TestParseGovulncheckWithEveryModuleUnloaded(t *testing.T) {
	dir := twoGoModules(t)
	out := []byte(`{"draugrUnloaded":{"goMod":"service/go.mod","reason":"r1"}}
{"draugrUnloaded":{"goMod":"tools/go.mod","reason":"r2"}}
`)
	report, err := parseGovulncheck(out, dir, plugin.Config{})
	if err != nil {
		t.Fatal(err)
	}
	want := []sarif.Input{
		{Path: "service/go.mod", Unread: "r1", Analysis: true},
		{Path: "tools/go.mod", Unread: "r2", Analysis: true},
	}
	if !slices.Equal(report.Inputs, want) || len(report.Results) != 0 {
		t.Errorf("inputs = %+v, results = %d, want %+v and none", report.Inputs, len(report.Results), want)
	}
}

// Build constraints decide whether a module holds a package: a tools file, an ignored file and a
// file for another platform hold none, a tag GOFLAGS sets brings a file in, and a directory `./...`
// passes by is passed by.
func TestHoldsGoPackageHonorsBuildConstraints(t *testing.T) {
	t.Setenv("GOFLAGS", "")
	other := "plan9"
	if runtime.GOOS == "plan9" {
		other = "linux"
	}
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  bool
	}{
		{"a plain file", map[string]string{"main.go": goMain}, true},
		{"tools only", map[string]string{"tools.go": "//go:build tools\n\npackage tools\n"}, false},
		{"ignored", map[string]string{"gen.go": "//go:build ignore\n\npackage main\n"}, false},
		{"another platform", map[string]string{"x_" + other + ".go": "package x\n"}, false},
		{"tests only", map[string]string{"x_test.go": "package x\n"}, false},
		{"under an underscore", map[string]string{"_examples/main.go": goMain}, false},
		{"under a dot", map[string]string{".hidden/main.go": goMain}, false},
		{"under a directory", map[string]string{"cmd/x/main.go": goMain}, true},
	} {
		if got := holdsGoPackage(writeTree(t, tc.files)); got != tc.want {
			t.Errorf("%s: holdsGoPackage = %v, want %v", tc.name, got, tc.want)
		}
	}
	t.Setenv("GOFLAGS", "-mod=mod --tags=tools,extra")
	if !holdsGoPackage(writeTree(t, map[string]string{"tools.go": "//go:build tools\n\npackage tools\n"})) {
		t.Error("a tools file with -tags=tools set in GOFLAGS: holdsGoPackage = false, want true")
	}
}

// GOFLAGS sets build tags with -tags or --tags, comma-separated, and the last setting wins.
func TestGoflagsTags(t *testing.T) {
	for in, want := range map[string][]string{
		"":                             nil,
		"-mod=mod":                     nil,
		"-tags=a,b":                    {"a", "b"},
		"--tags=a -tags=b":             {"b"},
		"tags=a":                       nil,
		"-modcacherw -tags=noassets, ": {"noassets"},
	} {
		if got := goflagsTags(in); !slices.Equal(got, want) {
			t.Errorf("goflagsTags(%q) = %q, want %q", in, got, want)
		}
	}
}

// A tree whose go.mod files hold nothing to build runs nothing, and says so rather than claiming it
// holds no go.mod.
func TestParseGovulncheckWithNothingToBuild(t *testing.T) {
	dir := writeTree(t, map[string]string{"go.mod": "module x\n", "tools.go": "//go:build tools\n\npackage tools\n"})
	if args := govulncheckArgs(dir, nil, plugin.Config{}); len(args) != 0 {
		t.Errorf("args = %v, want none", args)
	}
	report, err := parseGovulncheck(nil, dir, plugin.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Provenance) != 1 || report.Provenance[0].Fields[0].Value != "no Go package to build, so nothing here carries a verdict" {
		t.Errorf("provenance = %+v, want the tree reported as holding nothing to build", report.Provenance)
	}
}
