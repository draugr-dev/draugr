package scanners

import (
	"context"
	"maps"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/draugr-dev/draugr/internal/toolexec"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// gosecRuns scans two components in two Go repositories with gosec, each run going through the
// runner a scan uses with `env` standing in for gosec, and returns each run's argv and the
// environment it started with, keyed by module directory, with the directories by repository.
func gosecRuns(t *testing.T) (argvs, environments, dirs map[string]string) {
	t.Helper()
	orig := lookRuntime
	t.Cleanup(func() { lookRuntime = orig })
	lookRuntime = func(name string) (string, error) { return "/usr/bin/" + name, nil }
	loadsAnyModule(t)

	dirs = map[string]string{
		"one": writeTree(t, map[string]string{"go.mod": "module example.com/api\n\ngo 1.22\n", "main.go": goMain}),
		"two": writeTree(t, map[string]string{"go.mod": "module example.com/worker\n\ngo 1.22\n", "main.go": goMain}),
	}
	var mu sync.Mutex
	argvs, environments = map[string]string{}, map[string]string{}
	origExec := execArgvInDirWithEnv
	t.Cleanup(func() { execArgvInDirWithEnv = origExec })
	execArgvInDirWithEnv = func(ctx context.Context, dir string, argv, env []string) ([]byte, error) {
		out, err := origExec(ctx, dir, []string{"env"}, env)
		if err != nil {
			return nil, err
		}
		mod := strings.TrimSuffix(argv[len(argv)-1], string(filepath.Separator)+"...")
		mu.Lock()
		argvs[mod] = strings.Join(argv, " ")
		environments[mod] = string(out)
		mu.Unlock()
		return writeAsGosec(argv, nil)
	}

	s := NewGosec().(repoScanner)
	s.cacheVersion = func(context.Context) string { return "gosec@2.30.0" }
	s.checkout = checkoutOf(dirs)
	reg := engine.NewRegistry()
	reg.RegisterController(sastController{scanner: gosecScannerName})
	reg.RegisterScanner(s)
	model := saga.Model{
		Config: saga.Config{Controls: map[string]saga.ControllerSettings{"sast": {"enabled": true}}},
		Components: []saga.Component{
			{Name: "api", Repositories: []saga.Repository{{URL: "one"}}},
			{Name: "worker", Repositories: []saga.Repository{{URL: "two"}}},
		},
	}
	if _, err := engine.New(reg, engine.WithConcurrency(2)).Run(context.Background(), model); err != nil {
		t.Fatalf("run: %v", err)
	}
	return argvs, environments, dirs
}

// gosecLoadsHere is the -concurrency gosec runs with on this machine, and the -p each of its loads
// builds with: gosecLoads or the bound where that is fewer, and the bound divided among them.
func gosecLoadsHere() (loads, perLoad int) {
	n := toolexec.Parallelism()
	loads = min(gosecLoads, n)
	return loads, max(1, n/loads)
}

// Each gosec run, in each of two repositories, loads at most gosecLoads packages at once, and each
// load builds with the bound divided among them, after the caller's own flags. Its compile
// processes together then stay within the bound rather than reaching the bound for each load.
// GOMAXPROCS stays the whole bound, because it sizes gosec's own threads.
func TestEachGosecRunDividesTheBoundAmongItsLoads(t *testing.T) {
	t.Setenv("GOMAXPROCS", "")
	t.Setenv("GOFLAGS", "-tags=aaa")
	t.Setenv("GOWORK", "")
	argvs, environments, dirs := gosecRuns(t)

	n := toolexec.Parallelism()
	loads, perLoad := gosecLoadsHere()
	if loads*perLoad > n {
		t.Fatalf("%d loads at -p=%d is %d compile processes, above the bound %d", loads, perLoad, loads*perLoad, n)
	}
	for _, mod := range []string{dirs["one"], dirs["two"]} {
		env, ok := environments[mod]
		if !ok {
			t.Errorf("gosec did not run over %s; it ran over %v", mod, slices.Sorted(maps.Keys(environments)))
			continue
		}
		if want := " -concurrency " + strconv.Itoa(loads) + " "; !strings.Contains(argvs[mod], want) {
			t.Errorf("the run over %s is %q, without %q", mod, argvs[mod], strings.TrimSpace(want))
		}
		for _, want := range []string{
			"GOMAXPROCS=" + strconv.Itoa(n) + "\n",
			"GOFLAGS=-tags=aaa -p=" + strconv.Itoa(perLoad) + "\n",
		} {
			if !strings.Contains(env, want) {
				t.Errorf("the run over %s lacks %q; its environment:\n%s", mod, want, env)
			}
		}
	}
}

// A caller who chose -p chose each command's parallelism, and gosec's loads build with it; the
// number of loads gosec runs at once is still bounded. The caller's GOMAXPROCS stands too.
func TestGosecKeepsTheCallersBuildParallelism(t *testing.T) {
	t.Setenv("GOMAXPROCS", "3")
	t.Setenv("GOFLAGS", "-mod=mod -p=3")
	t.Setenv("GOWORK", "")
	argvs, environments, dirs := gosecRuns(t)

	loads, _ := gosecLoadsHere()
	for _, mod := range []string{dirs["one"], dirs["two"]} {
		env, ok := environments[mod]
		if !ok {
			t.Errorf("gosec did not run over %s", mod)
			continue
		}
		if want := " -concurrency " + strconv.Itoa(loads) + " "; !strings.Contains(argvs[mod], want) {
			t.Errorf("the run over %s is %q, without %q", mod, argvs[mod], strings.TrimSpace(want))
		}
		for _, want := range []string{"GOMAXPROCS=3\n", "GOFLAGS=-mod=mod -p=3\n"} {
			if !strings.Contains(env, want) {
				t.Errorf("the run over %s lacks the caller's %q; its environment:\n%s", mod, want, env)
			}
		}
	}
}
