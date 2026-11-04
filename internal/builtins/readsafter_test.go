package builtins

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// moduleCache stands in for the Go module cache: one scanner fills it per repository and another
// reports what it found there.
type moduleCache struct {
	mu     sync.Mutex
	filled map[string]bool
}

func (c *moduleCache) fill(repo string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.filled[repo] = true
}

func (c *moduleCache) has(repo string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.filled[repo]
}

// cacheScanner wears a built-in scanner's name and ReadsAfter, and either fills the cache for the
// repository it is handed or reads it.
type cacheScanner struct {
	info  plugin.ScannerInfo
	cache *moduleCache
	fills bool
}

func (s cacheScanner) Info() plugin.ScannerInfo { return s.info }

func (s cacheScanner) Scan(_ context.Context, target plugin.Target, _ plugin.Config) (sarif.Report, error) {
	repo := target.(plugin.RepositoryTarget).URL
	if s.fills {
		// A module download takes a while, which is the window a concurrent reader used to fall in.
		time.Sleep(50 * time.Millisecond)
		s.cache.fill(repo)
		return sarif.Report{Tool: s.info.Name}, nil
	}
	rule := "license/MPL-2.0/github.com/hashicorp/errwrap"
	if !s.cache.has(repo) {
		rule = "license/unread/go.mod"
	}
	return sarif.Report{Tool: s.info.Name, Results: []sarif.Result{{
		RuleID: rule, Level: sarif.LevelNote, Location: sarif.Location{URI: repo + "/go.mod"},
	}}}, nil
}

// The real sca and licenses controllers plan govulncheck and trivy-license on each of a component's
// two Go repositories, and the jobs run concurrently. trivy-license reads the cache after govulncheck
// filled it, on both repositories and on every run, so two scans of one tree report the same licenses.
func TestLicensesAreReadAfterGovulncheckFilledTheModuleCache(t *testing.T) {
	builtin := Registry()
	info := func(name string) plugin.ScannerInfo {
		sc, ok := builtin.Scanner(name)
		if !ok {
			t.Fatalf("%s is not registered", name)
		}
		i := sc.Info()
		// The behavior under test is the ordering; the fakes take no options.
		i.ConfigSchema = nil
		return i
	}
	m := saga.Model{
		Release: saga.Release{Version: "1"},
		Config: saga.Config{
			Controls: map[string]saga.ControllerSettings{
				"sca":      {"enabled": true},
				"licenses": {"enabled": true},
			},
			Reachability: &saga.ReachabilityConfig{Analyzers: []string{"govulncheck"}},
		},
		Components: []saga.Component{{
			Name:         "app",
			Repositories: []saga.Repository{{URL: "repo-a"}, {URL: "repo-b"}},
		}},
	}

	for run := range 2 {
		cache := &moduleCache{filled: map[string]bool{}}
		reg := engine.NewRegistry()
		reg.RegisterController(controllers.NewSCA())
		reg.RegisterController(controllers.NewLicenses())
		reg.RegisterScanner(cacheScanner{info: plugin.ScannerInfo{Name: "trivy-fs"}, cache: &moduleCache{filled: map[string]bool{}}})
		reg.RegisterScanner(cacheScanner{info: info("govulncheck"), cache: cache, fills: true})
		reg.RegisterScanner(cacheScanner{info: info("trivy-license"), cache: cache})

		res, err := engine.New(reg, engine.WithConcurrency(8), engine.WithoutPrewarm()).Run(context.Background(), m)
		if err != nil {
			t.Fatalf("run %d: %v", run, err)
		}
		got := res.Controls["licenses"].Report.Results
		if len(got) != 2 {
			t.Fatalf("run %d: licenses results = %+v, want one per repository", run, got)
		}
		for _, r := range got {
			if r.RuleID != "license/MPL-2.0/github.com/hashicorp/errwrap" {
				t.Errorf("run %d: %s read the module cache before govulncheck filled it", run, r.RuleID)
			}
		}
	}
}
