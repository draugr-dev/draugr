package scanners

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// loadsAnyModule stands in for the go command's listing of a module's packages with one that loads
// any module and lists its directory as its one package where that holds a Go file, for a test about
// what gosec's own run does.
func loadsAnyModule(t *testing.T) {
	t.Helper()
	orig := goListPackages
	t.Cleanup(func() { goListPackages = orig })
	goListPackages = func(_ context.Context, dir string, _, _ []string) ([]string, error) {
		if matches, _ := filepath.Glob(filepath.Join(dir, "*.go")); len(matches) > 0 {
			return []string{dir}, nil
		}
		return nil, nil
	}
}

// gosecWorkspaceRun is what a stand-in for gosec saw of one run over a module.
type gosecWorkspaceRun struct {
	env      []string
	writable bool
}

// gosecOverWorkspaces stands in for gosec: it loads the module's module graph with the go command
// under the run's environment, as gosec's own load does, fails where that fails, and otherwise
// answers with the recorded report. It records each run by module.
func gosecOverWorkspaces(t *testing.T, runs map[string]gosecWorkspaceRun, mu *sync.Mutex) func(ctx context.Context, root string, argv, env []string) ([]byte, error) {
	t.Helper()
	report, err := os.ReadFile(filepath.Join("testdata", "gosec", "command-injection.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	return func(ctx context.Context, root string, argv, env []string) ([]byte, error) {
		// Each module's one package is at the module's root, the directory gosec is given.
		mod := argv[len(argv)-1]
		cmd := exec.CommandContext(ctx, "go", "list", "-m", "all")
		cmd.Dir = mod
		cmd.Env = append(os.Environ(), env...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("go list -m all in %s: %w: %s", mod, err, out)
		}
		info, err := os.Stat(root)
		if err != nil {
			return nil, err
		}
		mu.Lock()
		runs[mod] = gosecWorkspaceRun{env: env, writable: info.Mode().Perm()&0o200 != 0}
		mu.Unlock()
		return replayAsGosec(argv, report)
	}
}

// runGosecOn scans one component per repository with gosec alone, on checkouts Draugr's own pool
// makes read-only.
func runGosecOn(t *testing.T, dirs map[string]string, run func(ctx context.Context, root string, argv, env []string) ([]byte, error)) engine.Result {
	t.Helper()
	origLook := lookRuntime
	t.Cleanup(func() { lookRuntime = origLook })
	lookRuntime = func(name string) (string, error) { return "/usr/bin/" + name, nil }
	origExec := execArgvInDirWithEnv
	t.Cleanup(func() { execArgvInDirWithEnv = origExec })
	execArgvInDirWithEnv = run

	s := NewGosec().(repoScanner)
	s.cacheVersion = func(context.Context) string { return "gosec@2.30.0" }
	s.checkout = checkoutOf(dirs)
	reg := engine.NewRegistry()
	reg.RegisterController(sastController{scanner: gosecScannerName})
	reg.RegisterScanner(s)
	var components []saga.Component
	for _, url := range []string{"one", "two"} {
		components = append(components, saga.Component{Name: url, Repositories: []saga.Repository{{URL: url}}})
	}
	model := saga.Model{
		Config:     saga.Config{Controls: map[string]saga.ControllerSettings{"sast": {"enabled": true}}},
		Components: components,
	}
	pool := git.NewPool()
	// A scan in error is the run's error as well as the control's, and the tests read the control's.
	res, _ := engine.New(reg).Run(git.WithPool(context.Background(), pool), model)
	pool.Close()
	return res
}

// Two repositories, each a workspace of two modules that commits go.work and no go.work.sum, on
// checkouts Draugr's own pool makes read-only. Neither module's go.sum lists the dependency both
// require, so the go command has to write its checksum somewhere. gosec runs over every module with
// GOWORK naming a copy of go.work outside the checkout, its load check passes under the same
// environment, and each module's findings reach the report. No go.work.sum is written into either
// checkout, and each copy is gone once its run ends.
func TestGosecLoadsEveryModuleOfAWorkspaceWithNoGoWorkSumOnTheReadOnlyCheckout(t *testing.T) {
	goProxy(t)
	workspace := func() string {
		return writeTree(t, map[string]string{
			"go.work":   "go 1.22\n\nuse (\n\t./a\n\t./b\n)\n",
			"a/go.mod":  "module example.com/a\n\ngo 1.22\n\nrequire example.com/dep v1.0.0\n",
			"a/main.go": goMain,
			"b/go.mod":  "module example.com/b\n\ngo 1.22\n\nrequire example.com/dep v1.0.0\n",
			"b/main.go": goMain,
		})
	}
	dirs := map[string]string{"one": workspace(), "two": workspace()}

	var mu sync.Mutex
	runs := map[string]gosecWorkspaceRun{}
	res := runGosecOn(t, dirs, gosecOverWorkspaces(t, runs, &mu))

	if res.Incomplete("sast") {
		t.Fatalf("sast is in error: %v", res.ScanErrors["sast"])
	}
	for name, root := range dirs {
		for _, m := range []string{"a", "b"} {
			mod := filepath.Join(root, m)
			run, ok := runs[mod]
			if !ok {
				t.Errorf("repository %s: gosec did not run over %s", name, m)
				continue
			}
			if run.writable {
				t.Errorf("repository %s: checkout was writable during the run, so the test proves nothing", name)
			}
			i := slices.IndexFunc(run.env, func(v string) bool { return strings.HasPrefix(v, "GOWORK=") })
			if i < 0 {
				t.Errorf("repository %s: %s ran with %q, want GOWORK naming a copy", name, m, run.env)
				continue
			}
			copied := strings.TrimPrefix(run.env[i], "GOWORK=")
			for _, r := range dirs {
				if _, inside := relSlash(r, copied); inside {
					t.Errorf("repository %s: %s read %s, inside a checkout", name, m, copied)
				}
			}
			if _, err := os.Stat(filepath.Dir(copied)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("repository %s: the copy for %s is still on disk: %v", name, m, err)
			}
		}
		if _, err := os.Stat(filepath.Join(root, "go.work.sum")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("repository %s: go.work.sum in the checkout: %v", name, err)
		}
	}
	want := []string{
		"one G204 a/main.go", "one G204 b/main.go", "one G702 a/main.go", "one G702 b/main.go",
		"two G204 a/main.go", "two G204 b/main.go", "two G702 a/main.go", "two G702 b/main.go",
	}
	if got := findingsOf(res, "sast"); !slices.Equal(got, want) {
		t.Errorf("findings %v, want %v", got, want)
	}
}

// In each of two repositories, a module declaring a Go newer than the go command, which
// GOTOOLCHAIN=local forbids it to fetch, is not handed to gosec. gosec 2.30.0 over that module skips
// every package, reports nothing and exits 0. The control is in error with the module and the go
// command's reason named, and the findings of the module beside it stay in the report.
func TestAGoModuleTheGoCommandCannotLoadFailsTheControlInsteadOfPassing(t *testing.T) {
	goProxy(t)
	repository := func() string {
		return writeTree(t, map[string]string{
			"go.mod":         "module example.com/app\n\ngo 1.22\n",
			"main.go":        goMain,
			"broken/go.mod":  "module example.com/broken\n\ngo 1.99\n",
			"broken/main.go": goMain,
		})
	}
	dirs := map[string]string{"one": repository(), "two": repository()}

	var mu sync.Mutex
	runs := map[string]gosecWorkspaceRun{}
	res := runGosecOn(t, dirs, gosecOverWorkspaces(t, runs, &mu))

	errs := res.ScanErrors["sast"]
	if len(errs) != 2 {
		t.Fatalf("sast errors %q, want one per repository", errs)
	}
	for _, e := range errs {
		if !strings.HasPrefix(e, "run gosec over broken/go.mod: go list -e -deps ./... cannot load the module, so gosec did not run: exit status 1: ") ||
			!strings.Contains(e, "go.mod requires go >= 1.99") {
			t.Errorf("error %q does not name the module and the go command's reason", e)
		}
	}
	for name, root := range dirs {
		if _, ran := runs[filepath.Join(root, "broken")]; ran {
			t.Errorf("repository %s: gosec ran over the module the go command cannot load", name)
		}
	}
	want := []string{"one G204 main.go", "one G702 main.go", "two G204 main.go", "two G702 main.go"}
	if got := findingsOf(res, "sast"); !slices.Equal(got, want) {
		t.Errorf("findings %v, want %v", got, want)
	}
}

// A go.work that cannot be parsed fails gosec's run over a module it governs, and gosec does not run.
func TestGosecFailsOnAWorkspaceItCannotRead(t *testing.T) {
	t.Setenv("GOWORK", "")
	root := writeTree(t, map[string]string{"go.work": "go 1.22\n\nuse (\n", "a/go.mod": "module example.com/a\n"})
	ran := false
	run := onGosecWorkspace(func(context.Context, string, []string, []string) ([]byte, error) {
		ran = true
		return nil, nil
	})
	_, err := run(context.Background(), root, []string{"gosec", filepath.Join(root, "a", "...")}, nil)
	if err == nil || !strings.Contains(err.Error(), "go.work") || ran {
		t.Errorf("err = %v, ran = %v, want go.work named and gosec not run", err, ran)
	}
}
