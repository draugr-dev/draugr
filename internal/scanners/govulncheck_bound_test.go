package scanners

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/internal/toolexec"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// Two components in two Go repositories, planned to run at once. Each govulncheck run goes through
// the same runner it would in a scan, with `env` standing in for govulncheck, and each one starts
// with GOMAXPROCS at the bound and -p in GOFLAGS after the caller's own tags, which the scanner
// still reads as the build tags. The two runs take turns, so their compile processes together stay
// within the bound rather than reaching twice it.
func TestEachConcurrentGovulncheckRunCarriesTheBound(t *testing.T) {
	useGoVulnDB(t, noCopy)
	builtWith(t, "go1.26.10")
	origLook := lookRuntime
	t.Cleanup(func() { lookRuntime = origLook })
	lookRuntime = func(name string) (string, error) { return "/usr/bin/" + name, nil }
	t.Setenv("GOMAXPROCS", "")
	t.Setenv("GOFLAGS", "-tags=aaa")
	t.Setenv("GOWORK", "")

	dirs := map[string]string{
		"one": writeTree(t, map[string]string{"go.mod": "module example.com/api\n\ngo 1.22\n", "main.go": goMain}),
		"two": writeTree(t, map[string]string{"go.mod": "module example.com/worker\n\ngo 1.22\n", "main.go": goMain}),
	}
	var mu sync.Mutex
	environments := map[string]string{}
	// running is how many runs are in progress, and most the largest it reached.
	running, most := 0, 0
	origExec := execArgvInDirWithEnv
	t.Cleanup(func() { execArgvInDirWithEnv = origExec })
	execArgvInDirWithEnv = func(ctx context.Context, dir string, argv, env []string) ([]byte, error) {
		mu.Lock()
		running++
		most = max(most, running)
		mu.Unlock()
		defer func() {
			mu.Lock()
			running--
			mu.Unlock()
		}()
		mod := argv[slices.Index(argv, "-C")+1]
		out, err := origExec(ctx, dir, []string{"env"}, env)
		if err != nil {
			return nil, err
		}
		// Long enough that two runs started together would be seen in progress together.
		time.Sleep(50 * time.Millisecond)
		mu.Lock()
		environments[mod] = string(out)
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
	if _, err := engine.New(reg, engine.WithConcurrency(2)).Run(context.Background(), model); err != nil {
		t.Fatalf("run: %v", err)
	}
	if most != 1 {
		t.Errorf("%d govulncheck runs were in progress at once, want 1 so the run stays within one bound", most)
	}

	n := strconv.Itoa(toolexec.Parallelism())
	for _, mod := range []string{dirs["one"], dirs["two"]} {
		env, ok := environments[mod]
		if !ok {
			t.Errorf("govulncheck did not run over %s", mod)
			continue
		}
		for _, want := range []string{"GOMAXPROCS=" + n + "\n", "GOFLAGS=-tags=aaa -p=" + n + "\n"} {
			if !strings.Contains(env, want) {
				t.Errorf("the run over %s lacks %q; its environment:\n%s", mod, want, env)
			}
		}
	}
	// The bound is the tool's environment, not Draugr's: the GOFLAGS the scanner reads its build tags
	// from is the caller's, as it was.
	if goflags := os.Getenv("GOFLAGS"); goflags != "-tags=aaa" || !slices.Equal(goflagsTags(goflags), []string{"aaa"}) {
		t.Errorf("after the run GOFLAGS = %q with tags %q, want the caller's -tags=aaa", goflags, goflagsTags(goflags))
	}
}
