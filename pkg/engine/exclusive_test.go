package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// controlOf plans one job of a scanner on each repository, under the named control.
type controlOf struct {
	control string
	scanner *stepScanner
	repos   []string
}

// registryOf registers each scanner under its control, enabled, and returns the model that runs them.
func registryOf(controls ...controlOf) (*Registry, saga.Model) {
	reg := NewRegistry()
	enabled := map[string]saga.ControllerSettings{}
	for _, c := range controls {
		reg.RegisterScanner(c.scanner)
		reg.RegisterController(repoListController{name: c.control, scanner: c.scanner.name, repos: c.repos})
		enabled[c.control] = saga.ControllerSettings{"enabled": true}
	}
	return reg, saga.Model{Release: saga.Release{Version: "1"}, Config: saga.Config{Controls: enabled}}
}

// overlapMeter counts the exclusive jobs in progress and keeps the most seen at once.
type overlapMeter struct {
	mu      sync.Mutex
	active  int
	most    int
	entered int
}

// during marks a job in progress for the length of d, or until ctx is done.
func (m *overlapMeter) during(ctx context.Context, d time.Duration) {
	m.mu.Lock()
	m.active++
	m.entered++
	m.most = max(m.most, m.active)
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.active--
		m.mu.Unlock()
	}()
	select {
	case <-time.After(d):
	case <-ctx.Done():
	}
}

func (m *overlapMeter) counts() (most, entered int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.most, m.entered
}

var twoRepos = []string{"repo-a", "repo-b"}

// Two scanners declaring one resource, each planned on two repositories, never run two of their
// jobs at once, at one slot or at four, while an ordinary job does run beside one of them when there
// is a slot for it. The waits are the waiting scanners' to report.
func TestExclusiveJobsNeverRunAtOnce(t *testing.T) {
	for _, jobs := range []int{1, 4} {
		t.Run(fmt.Sprintf("j%d", jobs), func(t *testing.T) {
			log := &eventLog{}
			meter := &overlapMeter{}
			// At -j 4 an ordinary job has a slot of its own, and the lock is no reason to hold it
			// back: vuln on repo-a and the ordinary job each wait until the other has started, so
			// the run finishes only if both are in progress at once.
			plainStarted, vulnStarted := make(chan struct{}), make(chan struct{})
			meet := func(ctx context.Context, mine, theirs chan struct{}) error {
				if jobs == 1 {
					return nil
				}
				close(mine)
				select {
				case <-theirs:
					return nil
				case <-time.After(10 * time.Second):
					return errors.New("no ordinary job ran during an exclusive one")
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			vuln := &stepScanner{name: "vuln", exclusive: plugin.ExclusiveGoPackageLoad, log: log,
				hold: func(ctx context.Context, repo string) error {
					if repo == "repo-a" {
						if err := meet(ctx, vulnStarted, plainStarted); err != nil {
							return err
						}
					}
					meter.during(ctx, 30*time.Millisecond)
					return nil
				}}
			sast := &stepScanner{name: "sast-go", exclusive: plugin.ExclusiveGoPackageLoad, log: log,
				hold: func(ctx context.Context, _ string) error {
					meter.during(ctx, 30*time.Millisecond)
					return nil
				}}
			plain := &stepScanner{name: "plain", log: log, hold: func(ctx context.Context, _ string) error {
				return meet(ctx, plainStarted, vulnStarted)
			}}
			reg, m := registryOf(
				controlOf{"sca", vuln, twoRepos},
				controlOf{"sast", sast, twoRepos},
				controlOf{"secrets", plain, []string{"repo-b"}},
			)

			res, err := runBounded(context.Background(), t, New(reg, WithConcurrency(jobs), WithoutPrewarm()), m)
			if err != nil {
				t.Fatalf("Run: %v (events: %s)", err, log)
			}
			if most, entered := meter.counts(); most != 1 || entered != 4 {
				t.Errorf("exclusive jobs: %d at once, %d run; want 1 at once and all 4 run (events: %s)", most, entered, log)
			}
			if res.Stats.OrderWaits["vuln"]+res.Stats.OrderWaits["sast-go"] <= 0 {
				t.Errorf("OrderWaits = %v, want the exclusive jobs' waits for each other recorded", res.Stats.OrderWaits)
			}
			if _, ok := res.Stats.ToolWaits["vuln"]; ok {
				t.Errorf("ToolWaits = %v, want the lock's wait kept out of it", res.Stats.ToolWaits)
			}
			if _, ok := res.Stats.OrderWaits["plain"]; ok {
				t.Errorf("OrderWaits = %v, want nothing for a scanner that declares no resource", res.Stats.OrderWaits)
			}
		})
	}
}

// A job that fails releases the resource as surely as one that succeeds.
func TestAFailedExclusiveJobReleasesTheLock(t *testing.T) {
	log := &eventLog{}
	vuln := &stepScanner{name: "vuln", exclusive: plugin.ExclusiveGoPackageLoad, log: log, fail: true}
	sast := &stepScanner{name: "sast-go", exclusive: plugin.ExclusiveGoPackageLoad, log: log}
	reg, m := registryOf(controlOf{"sca", vuln, twoRepos}, controlOf{"sast", sast, twoRepos})

	res, err := runBounded(context.Background(), t, New(reg, WithConcurrency(2), WithoutPrewarm()), m)
	if err == nil || !strings.Contains(err.Error(), "module download failed") {
		t.Fatalf("Run error = %v, want the failed job's error", err)
	}
	if got := len(res.Controls["sast"].Report.Results); got != 2 {
		t.Errorf("sast results = %d, want both jobs run after the failed ones released the lock (events: %s)", got, log)
	}
}

// A run canceled while a job waits for the resource does not wait out the job holding it, and the
// waiting job never starts.
func TestACanceledRunReleasesAJobWaitingForTheLock(t *testing.T) {
	log := &eventLog{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	var once sync.Once
	vuln := &stepScanner{name: "vuln", exclusive: plugin.ExclusiveGoPackageLoad, log: log,
		hold: func(ctx context.Context, _ string) error {
			once.Do(func() { close(started) })
			<-ctx.Done()
			// Held past the cancellation, so the job waiting for the lock finds the run canceled
			// before it finds the lock free.
			time.Sleep(200 * time.Millisecond)
			return ctx.Err()
		}}
	reg, m := registryOf(controlOf{"sca", vuln, twoRepos})
	go func() {
		<-started
		cancel()
	}()

	if _, err := runBounded(ctx, t, New(reg, WithConcurrency(2), WithoutPrewarm()), m); err == nil {
		t.Fatal("Run returned no error for a canceled run")
	}
	if a, b := log.at("start vuln repo-a"), log.at("start vuln repo-b"); a >= 0 && b >= 0 {
		t.Errorf("both jobs started, want the one waiting for the lock released by the cancellation: %s", log)
	}
}

// A reader waiting on two exclusive fillers completes at one slot and at four, after both fillers
// on its own repository, and the fillers still never run at once. The reader takes its turn after
// the fillers, so it never holds the slot they need, and they never hold the lock while waiting.
func TestReadsAfterAndExclusiveTogether(t *testing.T) {
	for _, jobs := range []int{1, 4} {
		t.Run(fmt.Sprintf("j%d", jobs), func(t *testing.T) {
			log := &eventLog{}
			meter := &overlapMeter{}
			load := func(ctx context.Context, _ string) error {
				meter.during(ctx, 20*time.Millisecond)
				return nil
			}
			vuln := &stepScanner{name: "vuln", exclusive: plugin.ExclusiveGoPackageLoad, log: log, hold: load}
			sast := &stepScanner{name: "sast-go", exclusive: plugin.ExclusiveGoPackageLoad, log: log, hold: load}
			reader := &stepScanner{name: "reader", after: []string{"vuln", "sast-go"}, log: log}
			plain := &stepScanner{name: "plain", log: log}
			reg, m := registryOf(
				controlOf{"licenses", reader, twoRepos},
				controlOf{"sca", vuln, twoRepos},
				controlOf{"sast", sast, twoRepos},
				controlOf{"secrets", plain, twoRepos},
			)

			res, err := runBounded(context.Background(), t, New(reg, WithConcurrency(jobs), WithoutPrewarm()), m)
			if err != nil {
				t.Fatalf("Run: %v (events: %s)", err, log)
			}
			for _, repo := range twoRepos {
				started := log.at("start reader " + repo)
				for _, filler := range []string{"vuln", "sast-go"} {
					if ended := log.at("end " + filler + " " + repo); started < 0 || ended < 0 || started < ended {
						t.Errorf("%s: the reader started before %s ended: %s", repo, filler, log)
					}
				}
			}
			if most, entered := meter.counts(); most != 1 || entered != 4 {
				t.Errorf("exclusive jobs: %d at once, %d run; want 1 at once and all 4 run", most, entered)
			}
			for _, control := range []string{"licenses", "secrets"} {
				if got := len(res.Controls[control].Report.Results); got != 2 {
					t.Errorf("%s results = %d, want 2", control, got)
				}
			}
		})
	}
}

// A job of a scanner that declares no resource, or one whose scanner is not registered, needs no
// lock and is not held up by one.
func TestExclusiveLocksOnlyForDeclaredResources(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterScanner(&stepScanner{name: "vuln", exclusive: plugin.ExclusiveGoPackageLoad, log: &eventLog{}})
	reg.RegisterScanner(&stepScanner{name: "plain", log: &eventLog{}})
	planned := []PlannedJob{
		{Job: plugin.ScanJob{Scanner: "vuln"}},
		{Job: plugin.ScanJob{Scanner: "vuln"}},
		{Job: plugin.ScanJob{Scanner: "plain"}},
		{Job: plugin.ScanJob{Scanner: "missing"}},
	}
	locks := newExclusiveLocks(reg, planned)
	if len(locks) != 1 || locks[plugin.ExclusiveGoPackageLoad] == nil {
		t.Fatalf("locks = %v, want one for %s", locks, plugin.ExclusiveGoPackageLoad)
	}
	waits := &plugin.WaitRecorder{}
	for _, resource := range []string{"", "undeclared"} {
		release, ok := locks.acquire(context.Background(), waits, "plain", resource)
		if !ok {
			t.Fatalf("acquire(%q) = false, want no lock to wait for", resource)
		}
		release()
	}
	if got := waits.Totals(); got != nil {
		t.Errorf("waits = %v, want none", got)
	}
}

func TestCheckExclusive(t *testing.T) {
	scanner := func(name, resource string) *stepScanner {
		return &stepScanner{name: name, exclusive: resource, log: &eventLog{}}
	}
	t.Run("clean", func(t *testing.T) {
		reg := NewRegistry()
		reg.RegisterScanner(scanner("vuln", plugin.ExclusiveGoPackageLoad))
		reg.RegisterScanner(scanner("plain", ""))
		if err := reg.CheckExclusive(plugin.ExclusiveGoPackageLoad); err != nil {
			t.Errorf("CheckExclusive = %v, want nil", err)
		}
	})
	t.Run("undeclared", func(t *testing.T) {
		reg := NewRegistry()
		reg.RegisterScanner(scanner("vuln", "go-pakage-load"))
		err := reg.CheckExclusive(plugin.ExclusiveGoPackageLoad)
		if err == nil || !strings.Contains(err.Error(), `vuln is exclusive on "go-pakage-load"`) {
			t.Errorf("CheckExclusive = %v, want the undeclared name", err)
		}
	})
}
