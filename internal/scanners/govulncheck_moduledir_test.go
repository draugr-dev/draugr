package scanners

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// goMain is a Go file a module builds, so govulncheck has a package to run over.
const goMain = "package main\n\nfunc main() {}\n"

// Two components in two repositories, with modules declaring different Go versions: a root module
// and a nested one in the first, and a module a go.work uses in the second. Each run of govulncheck
// has its module as the working directory, which is where it runs `go env GOVERSION`, so the go
// command there reads that module's go.mod, and the workspace run keeps GOWORK naming its copy.
func TestGovulncheckRunsInEachModuleSoItsOwnGoVersionDecides(t *testing.T) {
	goProxy(t)
	useGoVulnDB(t, noCopy)
	builtWith(t, "")

	dirs := map[string]string{
		"one": writeTree(t, map[string]string{
			"go.mod":      "module example.com/api\n\ngo 1.22\n",
			"main.go":     goMain,
			"svc/go.mod":  "module example.com/svc\n\ngo 1.24\n",
			"svc/main.go": goMain,
		}),
		"two": writeTree(t, map[string]string{
			"go.work":        "go 1.23\n\nuse ./worker\n",
			"worker/go.mod":  "module example.com/worker\n\ngo 1.23\n",
			"worker/main.go": goMain,
		}),
	}

	type ran struct {
		dir, gomod string
		env        []string
	}
	var mu sync.Mutex
	runs := map[string]ran{}
	origExec := execArgvInDirWithEnv
	t.Cleanup(func() { execArgvInDirWithEnv = origExec })
	execArgvInDirWithEnv = func(ctx context.Context, dir string, argv, env []string) ([]byte, error) {
		mod := argv[slices.Index(argv, "-C")+1]
		// What govulncheck's own `go env` would see, run where govulncheck runs.
		cmd := exec.CommandContext(ctx, "go", "env", "GOMOD")
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), env...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("go env GOMOD in %s: %w: %s", dir, err, out)
		}
		mu.Lock()
		runs[mod] = ran{dir: dir, gomod: strings.TrimSpace(string(out)), env: env}
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
	if _, err := engine.New(reg).Run(context.Background(), model); err != nil {
		t.Fatalf("run: %v", err)
	}

	mods := []string{dirs["one"], filepath.Join(dirs["one"], "svc"), filepath.Join(dirs["two"], "worker")}
	if len(runs) != len(mods) {
		t.Fatalf("govulncheck ran over %d modules, want %d: %+v", len(runs), len(mods), runs)
	}
	for _, mod := range mods {
		r, ok := runs[mod]
		if !ok {
			t.Errorf("no run for %s", mod)
			continue
		}
		if r.dir != mod {
			t.Errorf("the run for %s had %s as its working directory, want the module", mod, r.dir)
		}
		if want := filepath.Join(mod, "go.mod"); r.gomod != want {
			t.Errorf("go env GOMOD for %s = %q, want %q", mod, r.gomod, want)
		}
	}
	if env := runs[mods[0]].env; len(env) != 0 {
		t.Errorf("the root module, under no go.work, ran with %q, want nothing added", env)
	}
	worker := runs[mods[2]]
	if len(worker.env) != 1 || !strings.HasPrefix(worker.env[0], "GOWORK=") || worker.env[0] == "GOWORK=off" {
		t.Errorf("the workspace module ran with %q, want GOWORK naming a copy", worker.env)
	}
}

// The working directory comes from `-C`, and an argv without one keeps the directory it was given.
func TestInModuleDirFallsBackToTheGivenDirectory(t *testing.T) {
	var got []string
	run := inModuleDir(func(_ context.Context, dir string, _, _ []string) ([]byte, error) {
		got = append(got, dir)
		return nil, nil
	})
	for _, argv := range [][]string{
		{"govulncheck", "-C", "/checkout/svc", "./..."},
		{"govulncheck", "-C"},
		{"govulncheck", "./..."},
	} {
		if _, err := run(context.Background(), "/checkout", argv, nil); err != nil {
			t.Fatal(err)
		}
	}
	if want := []string{"/checkout/svc", "/checkout", "/checkout"}; !slices.Equal(got, want) {
		t.Errorf("working directories = %v, want %v", got, want)
	}
}
