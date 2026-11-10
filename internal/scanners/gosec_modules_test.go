package scanners

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/manifests"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// The gosec fixtures are recorded from gosec 2.30.0, run as gosecArgs runs it, over the tree in
// gosecRepository: command-injection.sarif is its report over the module at the root.
// invalid-severity.stderr is its log from `-severity bogus`, which exits 1, standing for a module
// whose run fails. no-rules.stderr is its log from `-fmt sarif -no-fail -concurrency 2 -include
// G101 -exclude G101`, which prints its rule settings and then the reason it exits 1, the shape a
// failure after gosec's banner takes. The module at docs/ holds a go.mod and a hugo.toml and no Go
// file, so the go command lists no package in it and gosec does not run over it.

// gosecMain is the root module's main.go in the recorded tree.
const gosecMain = "package main\n\nimport (\n\t\"os\"\n\t\"os/exec\"\n)\n\nfunc main() { _ = exec.Command(\"sh\", \"-c\", os.Args[1]) }\n"

// gosecRepository is a repository with a Go module at its root and, at docs/, a documentation site
// with its own go.mod and no Go package. With broken, it also holds a module at tools/ whose run
// fails.
func gosecRepository(t *testing.T, broken bool) string {
	t.Helper()
	files := map[string]string{
		"go.mod":         "module example.com/app\n\ngo 1.22\n",
		"main.go":        gosecMain,
		"docs/go.mod":    "module example.com/app/docs\n\ngo 1.19\n",
		"docs/hugo.toml": "title = \"docs\"\n",
	}
	if broken {
		files["tools/go.mod"] = "module example.com/app/tools\n\ngo 1.22\n"
		files["tools/main.go"] = goMain
	}
	return writeTree(t, files)
}

// replayGosec stands in for gosec over each module, whose one package is at the module's root: over
// a module whose directory's name is in logs, a process that writes the recorded log named there to
// stderr and exits 1, which is how toolexec sees gosec's own exit, and over any other module the
// recorded report.
func replayGosec(t *testing.T, logs map[string]string) func(ctx context.Context, dir string, argv, env []string) ([]byte, error) {
	t.Helper()
	report, err := os.ReadFile(filepath.Join("testdata", "gosec", "command-injection.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	orig := execArgvInDirWithEnv
	return func(ctx context.Context, dir string, argv, env []string) ([]byte, error) {
		name, ok := logs[filepath.Base(argv[len(argv)-1])]
		if !ok {
			return replayAsGosec(argv, report)
		}
		log, err := filepath.Abs(filepath.Join("testdata", "gosec", name))
		if err != nil {
			t.Fatal(err)
		}
		return orig(ctx, dir, []string{"sh", "-c", `cat "$0" >&2; exit 1`, log}, env)
	}
}

// gosecReplaying is a gosec scanner whose runs replay the recordings and whose checkout of each
// repository is its own directory.
func gosecReplaying(t *testing.T, trees map[string]string, logs map[string]string) repoScanner {
	t.Helper()
	origLook := lookRuntime
	t.Cleanup(func() { lookRuntime = origLook })
	lookRuntime = func(name string) (string, error) { return "/usr/bin/" + name, nil }
	loadsAnyModule(t)
	origExec := execArgvInDirWithEnv
	t.Cleanup(func() { execArgvInDirWithEnv = origExec })
	execArgvInDirWithEnv = replayGosec(t, logs)

	s := NewGosec().(repoScanner)
	s.cacheVersion = func(context.Context) string { return "gosec@2.30.0" }
	s.checkout = checkoutOf(trees)
	return s
}

// runGosec scans one component over both repositories with gosec alone and returns the result.
func runGosec(t *testing.T, s repoScanner) engine.Result {
	t.Helper()
	reg := engine.NewRegistry()
	reg.RegisterController(sastController{scanner: gosecScannerName})
	reg.RegisterScanner(s)
	model := saga.Model{
		Config:     saga.Config{Controls: map[string]saga.ControllerSettings{"sast": {"enabled": true}}},
		Components: []saga.Component{{Name: "app", Repositories: []saga.Repository{{URL: "one"}, {URL: "two"}}}},
	}
	res, _ := engine.New(reg, engine.WithConcurrency(2)).Run(context.Background(), model)
	return res
}

// findingsOf lists a control's findings as `repository rule path`, sorted.
func findingsOf(res engine.Result, control string) []string {
	var got []string
	for _, r := range res.Controls[control].Report.Results {
		got = append(got, r.Repository+" "+r.RuleID+" "+r.Location.URI)
	}
	slices.Sort(got)
	return got
}

// gosec's findings over the module at each repository's root, as the recorded report has them.
var gosecRootFindings = []string{"one G204 main.go", "one G702 main.go", "two G204 main.go", "two G702 main.go"}

// A module holding no Go package says nothing about the module beside it: in each of two
// repositories, the root module's findings reach the report, the docs module's go.mod is unread
// with its reason, and the control is not in error.
func TestAGoModuleWithNoPackagesIsUnreadAndTheOtherModulesKeepTheirFindings(t *testing.T) {
	trees := map[string]string{"one": gosecRepository(t, false), "two": gosecRepository(t, false)}
	res := runGosec(t, gosecReplaying(t, trees, nil))

	if res.Incomplete("sast") {
		t.Fatalf("sast is in error: %v", res.ScanErrors["sast"])
	}
	if got := findingsOf(res, "sast"); !slices.Equal(got, gosecRootFindings) {
		t.Errorf("findings %v, want %v", got, gosecRootFindings)
	}
	want := []engine.InputCoverage{{
		Component: "app", Control: "sast", Scanners: []string{"gosec"},
		Unread: []engine.UnreadInput{
			{Repository: "one", Path: "docs/go.mod", Reason: string(manifests.NoGoPackages)},
			{Repository: "two", Path: "docs/go.mod", Reason: string(manifests.NoGoPackages)},
		},
	}}
	if !reflect.DeepEqual(res.Inputs, want) {
		t.Errorf("inputs\n%+v\nwant\n%+v", res.Inputs, want)
	}
}

// A module whose run fails for another reason fails the control, with the module named in the
// error, and in each of two repositories the findings of the modules gosec did read stay in the
// report, as does the module it found no package in.
func TestAGosecRunThatFailsOnAModuleKeepsTheFindingsOfTheOthers(t *testing.T) {
	trees := map[string]string{"one": gosecRepository(t, true), "two": gosecRepository(t, true)}
	res := runGosec(t, gosecReplaying(t, trees, map[string]string{"tools": "invalid-severity.stderr"}))

	errs := res.ScanErrors["sast"]
	if len(errs) != 2 {
		t.Fatalf("sast errors %q, want one per repository", errs)
	}
	for _, e := range errs {
		if !strings.HasPrefix(e, "run gosec over tools/go.mod: exit status 1: ") || !strings.Contains(e, "Invalid severity value") {
			t.Errorf("error %q does not name the module that failed and why", e)
		}
		if strings.Contains(e, "docs") {
			t.Errorf("error %q names the module with no package as a failure", e)
		}
	}
	if got := findingsOf(res, "sast"); !slices.Equal(got, gosecRootFindings) {
		t.Errorf("findings %v, want %v", got, gosecRootFindings)
	}
	if len(res.Inputs) != 1 || len(res.Inputs[0].Unread) != 2 {
		t.Errorf("inputs %+v, want each docs/go.mod unread", res.Inputs)
	}
	if len(res.FailedScans) != 2 {
		t.Errorf("failed scans %+v, want one per repository", res.FailedScans)
	}
	// Each repository was read, in part, so neither is a target nothing reached.
	if len(res.Stats.Unscanned) != 0 || len(res.Stats.Failures) != 0 {
		t.Errorf("unscanned %+v, failures %+v, want none", res.Stats.Unscanned, res.Stats.Failures)
	}
}

// A repository where every module's run failed was not read, and fails as any other scan does,
// with no report kept beside the error.
func TestAGosecScanWhoseEveryModuleFailedReadsNothing(t *testing.T) {
	trees := map[string]string{"one": gosecRepository(t, true)}
	// The root module's directory is the checkout, named for its temp directory.
	root := filepath.Base(trees["one"])
	s := gosecReplaying(t, trees, map[string]string{root: "invalid-severity.stderr", "tools": "invalid-severity.stderr"})

	_, err := s.Scan(context.Background(), plugin.RepositoryTarget{URL: "one"}, nil)
	if err == nil {
		t.Fatal("a scan whose every module failed returned no error")
	}
	if _, partial := errors.AsType[*plugin.PartialScanError](err); partial {
		t.Errorf("err %v is partial, with nothing read", err)
	}
	for _, want := range []string{"run gosec over go.mod: exit status 1: ", "; over tools/go.mod: exit status 1: "} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err %q, want %q in it", err, want)
		}
	}
}

// The scan returns what it read beside the failure, with its paths and repository stamped as any
// report's are.
func TestAPartialGosecScanReturnsWhatItRead(t *testing.T) {
	trees := map[string]string{"one": gosecRepository(t, true)}
	s := gosecReplaying(t, trees, map[string]string{"tools": "invalid-severity.stderr"})
	rep, err := s.Scan(context.Background(), plugin.RepositoryTarget{URL: "one"}, nil)
	partial, ok := errors.AsType[*plugin.PartialScanError](err)
	if !ok {
		t.Fatalf("err %v, want a partial scan", err)
	}
	if !reflect.DeepEqual(partial.Report, rep) {
		t.Error("the error's report is not the report returned")
	}
	if len(rep.Results) != 2 || rep.Results[0].Repository != "one" || rep.Results[0].Tool != "gosec" {
		t.Errorf("results %+v, want the root module's two, stamped", rep.Results)
	}
	want := []sarif.Input{{Scanner: "gosec", Repository: "one", Path: "docs/go.mod", Unread: "no Go packages", Analysis: true}}
	if !slices.Equal(rep.Inputs, want) {
		t.Errorf("inputs %+v, want %+v", rep.Inputs, want)
	}
}

// An error that is not gosec's own exit holds for every module, and fails the job as it is: gosec
// missing, or the run canceled.
func TestOnGosecModulePassesOnWhatIsNotAnExit(t *testing.T) {
	missing := fmt.Errorf("run: %w", exec.ErrNotFound)
	run := onGosecModule(func(context.Context, string, []string) ([]byte, error) { return nil, missing })
	if _, err := run(context.Background(), "/repo", []string{"gosec", "/repo/..."}); !errors.Is(err, exec.ErrNotFound) {
		t.Errorf("err %v, want gosec's absence as it was", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	exitErr := exec.Command("sh", "-c", "exit 1").Run()
	run = onGosecModule(func(context.Context, string, []string) ([]byte, error) { return nil, exitErr })
	if out, err := run(ctx, "/repo", []string{"gosec", "/repo/..."}); !errors.Is(err, exitErr) || out != nil {
		t.Errorf("out %q, err %v, want the canceled run's exit as it was", out, err)
	}

	ok := onGosecModule(func(context.Context, string, []string) ([]byte, error) { return []byte("{}"), nil })
	if out, err := ok(context.Background(), "/repo", []string{"gosec", "/repo/..."}); err != nil || string(out) != "{}" {
		t.Errorf("out %q, err %v, want the run's own output", out, err)
	}
}

// A gosec failure that logs its rule settings before the reason names the reason, without gosec's
// log prefix, in each of two repositories.
func TestAGosecFailureNamesItsCauseAfterTheBanner(t *testing.T) {
	trees := map[string]string{"one": gosecRepository(t, true), "two": gosecRepository(t, true)}
	res := runGosec(t, gosecReplaying(t, trees, map[string]string{"tools": "no-rules.stderr"}))
	errs := res.ScanErrors["sast"]
	if len(errs) != 2 {
		t.Fatalf("sast errors %q, want one per repository", errs)
	}
	for _, e := range errs {
		if want := "run gosec over tools/go.mod: exit status 1: No rules/analyzers are configured"; e != want {
			t.Errorf("error %q, want %q", e, want)
		}
	}
}
