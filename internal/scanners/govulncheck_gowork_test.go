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

// goProxy serves example.com/dep v1.0.0 from a directory, so the go command resolves a dependency
// with no network, and points the go command at it with a module cache of the test's own.
func goProxy(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go on PATH")
	}
	proxy := writeTree(t, map[string]string{
		"example.com/dep/@v/list":        "v1.0.0\n",
		"example.com/dep/@v/v1.0.0.info": `{"Version":"v1.0.0","Time":"2026-01-01T00:00:00Z"}` + "\n",
		"example.com/dep/@v/v1.0.0.mod":  "module example.com/dep\n\ngo 1.22\n",
	})
	t.Setenv("GOPROXY", "file://"+filepath.ToSlash(proxy))
	t.Setenv("GOSUMDB", "off")
	t.Setenv("GOMODCACHE", t.TempDir())
	// The module cache is read-only by default, and the test's temporary directory could not be
	// removed after it.
	t.Setenv("GOFLAGS", "-modcacherw")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("GOWORK", "")
}

// Two components in two repositories, each a workspace that commits go.work and no go.work.sum, on
// checkouts Draugr's own pool makes read-only. The go command loads every module: a module the
// workspace uses through a copy of go.work outside the checkout, with a relative replace resolved
// from the copy, and a module the workspace does not use with GOWORK=off. No go.work.sum is
// written into either checkout, and each copy is gone once its run ends.
func TestGovulncheckLoadsAWorkspaceWithNoGoWorkSumOnTheReadOnlyCheckout(t *testing.T) {
	goProxy(t)
	useGoVulnDB(t, noCopy)
	builtWith(t, "")

	dirs := map[string]string{
		"one": writeTree(t, map[string]string{
			"go.work":    "go 1.22\n\nuse ./api\n",
			"api/go.mod": "module example.com/api\n\ngo 1.22\n\nrequire example.com/dep v1.0.0\n",
		}),
		"two": writeTree(t, map[string]string{
			"go.work": "go 1.22\n\nuse (\n\t.\n)\n\nreplace example.com/lib => ./lib\n",
			"go.mod": "module example.com/worker\n\ngo 1.22\n\n" +
				"require (\n\texample.com/dep v1.0.0\n\texample.com/lib v0.0.0\n)\n",
			"lib/go.mod":   "module example.com/lib\n\ngo 1.22\n",
			"tools/go.mod": "module example.com/tools\n\ngo 1.22\n",
		}),
	}

	var mu sync.Mutex
	listed := map[string]string{}
	envs := map[string][]string{}
	writable := map[string]bool{}
	origExec := execArgvInDirWithEnv
	t.Cleanup(func() { execArgvInDirWithEnv = origExec })
	execArgvInDirWithEnv = func(ctx context.Context, root string, argv, env []string) ([]byte, error) {
		mod := argv[slices.Index(argv, "-C")+1]
		cmd := exec.CommandContext(ctx, "go", "list", "-m", "all")
		cmd.Dir = mod
		cmd.Env = append(os.Environ(), env...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("go list -m all in %s: %w: %s", mod, err, out)
		}
		info, err := os.Stat(root)
		if err != nil {
			return nil, err
		}
		// What the go command could not write into the checkout, it wrote beside the copy.
		if len(env) == 1 && env[0] != "GOWORK=off" {
			if _, err := os.Stat(strings.TrimPrefix(env[0], "GOWORK=") + ".sum"); err != nil {
				return nil, fmt.Errorf("no go.work.sum beside the copy for %s: %w", mod, err)
			}
		}
		mu.Lock()
		listed[mod], envs[mod] = string(out), env
		writable[root] = info.Mode().Perm()&0o200 != 0
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
	pool := git.NewPool()
	res, err := engine.New(reg).Run(git.WithPool(context.Background(), pool), model)
	pool.Close()
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	for root, w := range writable {
		if w {
			t.Errorf("checkout %s was writable during the run, so the test proves nothing", root)
		}
	}
	api, worker := filepath.Join(dirs["one"], "api"), dirs["two"]
	if !strings.Contains(listed[api], "example.com/dep v1.0.0") {
		t.Errorf("api's module graph = %q, want example.com/dep", listed[api])
	}
	if want := "example.com/lib v0.0.0 => " + filepath.Join(worker, "lib"); !strings.Contains(listed[worker], want) {
		t.Errorf("worker's module graph = %q, want %q", listed[worker], want)
	}
	for _, mod := range []string{api, worker} {
		if len(envs[mod]) != 1 || !strings.HasPrefix(envs[mod][0], "GOWORK=") {
			t.Fatalf("%s ran with %q, want GOWORK naming a copy", mod, envs[mod])
		}
		copied := strings.TrimPrefix(envs[mod][0], "GOWORK=")
		for _, root := range dirs {
			if _, inside := relSlash(root, copied); inside {
				t.Errorf("%s read %s, inside a checkout", mod, copied)
			}
		}
		if _, err := os.Stat(filepath.Dir(copied)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the copy for %s is still on disk: %v", mod, err)
		}
	}
	for _, mod := range []string{filepath.Join(worker, "lib"), filepath.Join(worker, "tools")} {
		if !slices.Equal(envs[mod], []string{"GOWORK=off"}) {
			t.Errorf("%s, which the workspace does not use, ran with %q, want GOWORK=off", mod, envs[mod])
		}
	}
	for name, root := range dirs {
		if _, err := os.Stat(filepath.Join(root, "go.work.sum")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("repository %s: go.work.sum in the checkout: %v", name, err)
		}
	}
	if got := len(res.Controls["sca"].Report.Results); got != 4 {
		t.Errorf("results = %d, want one per module", got)
	}
}

// The copy names every module and directory replacement by its absolute path, in a block or on a
// line of its own, and keeps the go line, a replacement by a module and an absolute path as
// written. go.work.sum is copied beside it.
func TestGoWorkEnvCopiesTheWorkspaceWithAbsolutePaths(t *testing.T) {
	t.Setenv("GOWORK", "")
	root := writeTree(t, map[string]string{
		"go.work": "go 1.22\n\nuse (\n\t./api\n\t\"./has space\"\n)\n\nuse ./worker\n\nuse /opt/elsewhere\n\n" +
			"replace example.com/lib => ../shared/lib\n\n" +
			"replace (\n\texample.com/old v1.0.0 => example.com/new v1.1.0\n\texample.com/abs => /opt/abs\n)\n",
		"go.work.sum":      "example.com/dep v1.0.0/go.mod h1:AAAA=\n",
		"api/go.mod":       "module example.com/api\n",
		"has space/go.mod": "module example.com/space\n",
		"worker/go.mod":    "module example.com/worker\n",
	})
	env, cleanup, err := goWorkEnv(root, []string{"govulncheck", "-C", filepath.Join(root, "api"), "./..."})
	if err != nil {
		t.Fatal(err)
	}
	if len(env) != 1 || !strings.HasPrefix(env[0], "GOWORK=") {
		t.Fatalf("env = %q", env)
	}
	copied := strings.TrimPrefix(env[0], "GOWORK=")
	raw, err := os.ReadFile(copied) // #nosec G304 -- the copy the code under test wrote
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	for _, want := range []string{
		"go 1.22",
		"\t" + filepath.Join(root, "api") + "\n",
		"\t\"" + filepath.Join(root, "has space") + "\"\n",
		"use " + filepath.Join(root, "worker") + "\n",
		"use /opt/elsewhere\n",
		"replace example.com/lib => " + filepath.Join(filepath.Dir(root), "shared", "lib") + "\n",
		"example.com/old v1.0.0 => example.com/new v1.1.0",
		"example.com/abs => /opt/abs",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("copied go.work lacks %q:\n%s", want, got)
		}
	}
	sum, err := os.ReadFile(copied + ".sum") // #nosec G304 -- the copy the code under test wrote
	if err != nil || string(sum) != "example.com/dep v1.0.0/go.mod h1:AAAA=\n" {
		t.Errorf("go.work.sum = %q, %v, want the checkout's", sum, err)
	}
	cleanup()
	if _, err := os.Stat(filepath.Dir(copied)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("cleanup left the copy: %v", err)
	}
}

// Nothing changes where no workspace applies: no module in the argv, a GOWORK the environment
// already sets, or no go.work in the checkout.
func TestGoWorkEnvLeavesARunWithNoWorkspaceAlone(t *testing.T) {
	work := writeTree(t, map[string]string{"go.work": "go 1.22\n\nuse ./api\n", "api/go.mod": "module example.com/api\n"})
	plain := writeTree(t, map[string]string{"go.mod": "module example.com/m\n"})
	for _, tc := range []struct {
		name, gowork, root string
		argv               []string
	}{
		{"no module in the argv", "", work, []string{"govulncheck", "-C"}},
		{"GOWORK=off", "off", work, []string{"govulncheck", "-C", filepath.Join(work, "api")}},
		{"GOWORK naming a file", filepath.Join(work, "go.work"), work, []string{"govulncheck", "-C", filepath.Join(work, "api")}},
		{"no go.work", "auto", plain, []string{"govulncheck", "-C", plain}},
	} {
		t.Setenv("GOWORK", tc.gowork)
		env, cleanup, err := goWorkEnv(tc.root, tc.argv)
		cleanup()
		if err != nil || env != nil {
			t.Errorf("%s: env = %q, err = %v, want neither", tc.name, env, err)
		}
	}
}

// A workspace vendored at its root runs from the checkout as it is, because the go command builds it
// from vendor/ and reads no checksums. Before go 1.22 the go command ignores a workspace's vendor/,
// so that workspace is copied like any other.
func TestGoWorkEnvLeavesAVendoredWorkspaceInPlace(t *testing.T) {
	t.Setenv("GOWORK", "")
	for _, tc := range []struct {
		goLine string
		copied bool
	}{
		{"go 1.22\n\n", false},
		{"go 1.26.2\n\n", false},
		{"go 1.21\n\n", true},
		{"", true},
	} {
		root := writeTree(t, map[string]string{
			"go.work":            tc.goLine + "use ./a\n",
			"a/go.mod":           "module example.com/a\n",
			"vendor/modules.txt": "## workspace\n",
		})
		env, cleanup, err := goWorkEnv(root, []string{"govulncheck", "-C", filepath.Join(root, "a")})
		cleanup()
		if err != nil || (len(env) == 1) != tc.copied {
			t.Errorf("go line %q: env = %q, err = %v, want a copy %v", tc.goLine, env, err, tc.copied)
		}
	}
}

// A go.work that cannot be read or parsed fails the run with the file named, and govulncheck does
// not run.
func TestGoWorkEnvFailsOnAWorkspaceItCannotRead(t *testing.T) {
	t.Setenv("GOWORK", "")
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"a directive go.work does not have", map[string]string{"go.work": "go 1.22\nrequire example.com/x v1.0.0\n"}, "go.work:2: unknown directive: require"},
		{"go.work is a directory", map[string]string{"go.work/x": ""}, "is a directory"},
		{"go.work.sum is a directory", map[string]string{"go.work": "use .\n", "go.work.sum/x": ""}, "is a directory"},
	} {
		root := writeTree(t, tc.files)
		if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/m\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		ran := false
		run := func(context.Context, string, []string, []string) ([]byte, error) { ran = true; return nil, nil }
		_, err := onGoWork(run)(context.Background(), root, []string{"govulncheck", "-C", root})
		if err == nil || !strings.Contains(err.Error(), tc.want) || ran {
			t.Errorf("%s: err = %v, ran = %v, want %q and no run", tc.name, err, ran, tc.want)
		}
	}
}
