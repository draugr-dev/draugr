package engine

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// eventLog records when each job started and ended, in the order it happened.
type eventLog struct {
	mu     sync.Mutex
	events []string
}

func (l *eventLog) add(event string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, event)
}

// at is the position of event in the log, or -1 when it never happened.
func (l *eventLog) at(event string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Index(l.events, event)
}

func (l *eventLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.events, ", ")
}

// stepScanner logs "start <name> <repo>" and "end <name> <repo>" around each job, and runs hold in
// between, so a test decides how long a job takes and what it waits for.
type stepScanner struct {
	name      string
	after     []string
	exclusive string
	runWide   bool
	log       *eventLog
	hold      func(ctx context.Context, repo string) error
	fail      bool
}

func (s *stepScanner) Info() plugin.ScannerInfo {
	return plugin.ScannerInfo{
		Name: s.name, ReadsAfter: s.after, ReadsAfterRun: s.runWide, Exclusive: s.exclusive,
		TargetKinds: []plugin.TargetKind{plugin.TargetRepository},
	}
}

func (s *stepScanner) Scan(ctx context.Context, target plugin.Target, _ plugin.Config) (sarif.Report, error) {
	repo := target.(plugin.RepositoryTarget).URL
	s.log.add("start " + s.name + " " + repo)
	defer s.log.add("end " + s.name + " " + repo)
	if s.hold != nil {
		if err := s.hold(ctx, repo); err != nil {
			return sarif.Report{}, err
		}
	}
	if s.fail {
		return sarif.Report{}, errors.New("module download failed")
	}
	return sarif.Report{Tool: s.name, Results: []sarif.Result{{
		RuleID: "R", Level: sarif.LevelWarning, Location: sarif.Location{URI: repo + "/go.mod"},
	}}}, nil
}

// repoListController plans one job of its scanner on each of its repositories.
type repoListController struct {
	name    string
	scanner string
	repos   []string
}

func (c repoListController) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: c.name, Scope: plugin.ScopeProject}
}

func (c repoListController) Plan(saga.Model, *saga.Component) ([]plugin.ScanJob, error) {
	jobs := make([]plugin.ScanJob, 0, len(c.repos))
	for _, r := range c.repos {
		jobs = append(jobs, plugin.ScanJob{Scanner: c.scanner, Target: plugin.RepositoryTarget{URL: r}})
	}
	return jobs, nil
}

func (c repoListController) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	return plugin.ControlResult{Control: c.name, Report: sarif.Merge(reports...)}, nil
}

// readerAndFiller registers a reader scanner under the licenses control and a filler it reads after
// under sca, each planned on its own repositories. The licenses control sorts first, so the reader's
// jobs come first in the plan and would take the slots first if nothing ordered them.
func readerAndFiller(reader, filler *stepScanner, readerRepos, fillerRepos []string) (*Registry, saga.Model) {
	reg := NewRegistry()
	reg.RegisterScanner(reader)
	reg.RegisterScanner(filler)
	reg.RegisterController(repoListController{name: "licenses", scanner: reader.name, repos: readerRepos})
	reg.RegisterController(repoListController{name: "sca", scanner: filler.name, repos: fillerRepos})
	return reg, saga.Model{
		Release: saga.Release{Version: "1"},
		Config: saga.Config{Controls: map[string]saga.ControllerSettings{
			"licenses": {"enabled": true},
			"sca":      {"enabled": true},
		}},
	}
}

// runBounded runs the engine and fails the test if the run has not returned within a deadline,
// which is what a deadlock looks like from outside.
func runBounded(ctx context.Context, t *testing.T, e *Engine, m saga.Model) (Result, error) {
	t.Helper()
	type outcome struct {
		res Result
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := e.Run(ctx, m)
		done <- outcome{res, err}
	}()
	select {
	case o := <-done:
		return o.res, o.err
	case <-time.After(20 * time.Second):
		t.Fatal("the run did not finish: a job waiting to read is holding up the job it waits for")
		return Result{}, nil
	}
}

// A reader's job on a repository starts after the filler's job on that repository has ended, and
// on no other repository's. Run with one slot, where a reader holding the slot while it waited
// would never finish, and with four, where a reader waiting for another repository's filler would.
func TestAReaderStartsAfterTheFillerOnItsOwnRepository(t *testing.T) {
	for _, jobs := range []int{1, 4} {
		t.Run(fmt.Sprintf("j%d", jobs), func(t *testing.T) {
			log := &eventLog{}
			readerOnAStarted := make(chan struct{})
			var once sync.Once
			reader := &stepScanner{name: "reader", after: []string{"filler"}, log: log,
				hold: func(_ context.Context, repo string) error {
					if repo == "repo-a" {
						once.Do(func() { close(readerOnAStarted) })
					}
					return nil
				}}
			filler := &stepScanner{name: "filler", log: log,
				hold: func(ctx context.Context, repo string) error {
					if repo == "repo-b" && jobs > 1 {
						// repo-a's reader has to start while repo-b's filler is still running. It
						// cannot if it waits for every filler rather than its own repository's.
						select {
						case <-readerOnAStarted:
						case <-time.After(10 * time.Second):
							return errors.New("repo-a's reader waited for repo-b's filler")
						case <-ctx.Done():
							return ctx.Err()
						}
					}
					time.Sleep(50 * time.Millisecond)
					return nil
				}}
			reg, m := readerAndFiller(reader, filler,
				[]string{"repo-a", "repo-b"}, []string{"repo-a", "repo-b"})

			res, err := runBounded(context.Background(), t, New(reg, WithConcurrency(jobs), WithoutPrewarm()), m)
			if err != nil {
				t.Fatalf("Run: %v (events: %s)", err, log)
			}
			for _, repo := range []string{"repo-a", "repo-b"} {
				started, filled := log.at("start reader "+repo), log.at("end filler "+repo)
				if started < 0 || filled < 0 || started < filled {
					t.Errorf("%s: the reader started before the filler ended: %s", repo, log)
				}
			}
			if got := len(res.Controls["licenses"].Report.Results); got != 2 {
				t.Errorf("licenses results = %d, want one per repository", got)
			}
			// With four slots every job starts at once, so each reader finds its filler still
			// running, and the time it waited is the run's to report.
			if jobs > 1 && res.Stats.OrderWaits["reader"] <= 0 {
				t.Errorf("OrderWaits = %v, want the reader's wait recorded under its name", res.Stats.OrderWaits)
			}
		})
	}
}

// A reader on a repository with no filler planned on it starts at once, and a run that plans no
// filler at all records no wait.
func TestAReaderIsNotDelayedWhereNoFillerIsPlanned(t *testing.T) {
	t.Run("filler on another repository", func(t *testing.T) {
		log := &eventLog{}
		readerStarted := make(chan struct{})
		var once sync.Once
		reader := &stepScanner{name: "reader", after: []string{"filler"}, log: log,
			hold: func(context.Context, string) error { once.Do(func() { close(readerStarted) }); return nil }}
		filler := &stepScanner{name: "filler", log: log, hold: func(ctx context.Context, _ string) error {
			select {
			case <-readerStarted:
				return nil
			case <-time.After(10 * time.Second):
				return errors.New("the reader on repo-a waited for the filler on repo-b")
			case <-ctx.Done():
				return ctx.Err()
			}
		}}
		reg, m := readerAndFiller(reader, filler, []string{"repo-a"}, []string{"repo-b"})
		res, err := runBounded(context.Background(), t, New(reg, WithConcurrency(2), WithoutPrewarm()), m)
		if err != nil {
			t.Fatalf("Run: %v (events: %s)", err, log)
		}
		if _, ok := res.Stats.OrderWaits["reader"]; ok {
			t.Errorf("OrderWaits = %v, want no wait for a reader with no filler on its repository", res.Stats.OrderWaits)
		}
	})
	t.Run("no filler planned", func(t *testing.T) {
		log := &eventLog{}
		reader := &stepScanner{name: "reader", after: []string{"filler"}, log: log}
		filler := &stepScanner{name: "filler", log: log}
		reg, m := readerAndFiller(reader, filler, []string{"repo-a", "repo-b"}, nil)
		res, err := runBounded(context.Background(), t, New(reg, WithConcurrency(1), WithoutPrewarm()), m)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if res.Stats.OrderWaits != nil {
			t.Errorf("OrderWaits = %v, want none", res.Stats.OrderWaits)
		}
		if got := len(res.Controls["licenses"].Report.Results); got != 2 {
			t.Errorf("licenses results = %d, want 2", got)
		}
	})
}

// A filler that fails releases its readers: what it left in the cache is the state the reader
// reads, and a reader waiting for a success that never comes would never run.
func TestAFailedFillerStillReleasesTheReader(t *testing.T) {
	log := &eventLog{}
	reader := &stepScanner{name: "reader", after: []string{"filler"}, log: log}
	filler := &stepScanner{name: "filler", log: log, fail: true}
	reg, m := readerAndFiller(reader, filler, []string{"repo-a", "repo-b"}, []string{"repo-a", "repo-b"})

	res, err := runBounded(context.Background(), t, New(reg, WithConcurrency(1), WithoutPrewarm()), m)
	if err == nil || !strings.Contains(err.Error(), "module download failed") {
		t.Fatalf("Run error = %v, want the filler's failure", err)
	}
	for _, repo := range []string{"repo-a", "repo-b"} {
		if started, filled := log.at("start reader "+repo), log.at("end filler "+repo); started < filled {
			t.Errorf("%s: the reader started before the failed filler ended: %s", repo, log)
		}
	}
	if got := len(res.Controls["licenses"].Report.Results); got != 2 {
		t.Errorf("licenses results = %d, want the reader's two despite the filler failing", got)
	}
}

// Declarations that form a cycle would have two jobs each waiting for the other. The run says so
// and runs them unordered rather than never finishing.
func TestACycleIsReportedAndNothingWaits(t *testing.T) {
	log := &eventLog{}
	x := &stepScanner{name: "x", after: []string{"y"}, log: log}
	y := &stepScanner{name: "y", after: []string{"x"}, log: log}
	reg, m := readerAndFiller(x, y, []string{"repo-a"}, []string{"repo-a"})

	res, err := runBounded(context.Background(), t, New(reg, WithConcurrency(1), WithoutPrewarm()), m)
	if err == nil || !strings.Contains(err.Error(), "x → y → x") {
		t.Fatalf("Run error = %v, want the cycle named", err)
	}
	if got := res.Controls["licenses"].Report.Results; len(got) != 1 {
		t.Errorf("licenses results = %v, want x's job to have run", got)
	}
}

// A run canceled while a reader waits does not wait out the filler.
func TestACanceledRunReleasesAWaitingReader(t *testing.T) {
	log := &eventLog{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fillerStarted := make(chan struct{})
	reader := &stepScanner{name: "reader", after: []string{"filler"}, log: log}
	filler := &stepScanner{name: "filler", log: log, hold: func(ctx context.Context, _ string) error {
		close(fillerStarted)
		<-ctx.Done()
		return ctx.Err()
	}}
	reg, m := readerAndFiller(reader, filler, []string{"repo-a"}, []string{"repo-a"})
	go func() {
		<-fillerStarted
		cancel()
	}()
	if _, err := runBounded(ctx, t, New(reg, WithConcurrency(2), WithoutPrewarm()), m); err == nil {
		t.Fatal("Run returned no error for a canceled run")
	}
}

func TestReadsAfterCycle(t *testing.T) {
	cases := []struct {
		name     string
		declared map[string][]string
		want     []string
	}{
		{"none", map[string][]string{"a": {"b"}, "b": nil}, nil},
		{"unknown names are not followed", map[string][]string{"a": {"missing"}}, nil},
		{"itself", map[string][]string{"a": {"a"}}, []string{"a", "a"}},
		{"two", map[string][]string{"a": {"b"}, "b": {"a"}}, []string{"a", "b", "a"}},
		{"three, entered part way", map[string][]string{"a": {"b"}, "b": {"c"}, "c": {"b"}}, []string{"b", "c", "b"}},
		{"a diamond is not a cycle", map[string][]string{"a": {"b", "c"}, "b": {"d"}, "c": {"d"}, "d": nil}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := readsAfterCycle(tc.declared); !slices.Equal(got, tc.want) {
				t.Errorf("readsAfterCycle = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCheckReadsAfter(t *testing.T) {
	scanner := func(name string, after ...string) *stepScanner {
		return &stepScanner{name: name, after: after, log: &eventLog{}}
	}
	t.Run("clean", func(t *testing.T) {
		reg := NewRegistry()
		reg.RegisterScanner(scanner("reader", "filler"))
		reg.RegisterScanner(scanner("filler"))
		if err := reg.CheckReadsAfter(); err != nil {
			t.Errorf("CheckReadsAfter = %v, want nil", err)
		}
	})
	t.Run("unknown", func(t *testing.T) {
		reg := NewRegistry()
		reg.RegisterScanner(scanner("reader", "filler"))
		if err := reg.CheckReadsAfter(); err == nil || !strings.Contains(err.Error(), `reader reads after "filler"`) {
			t.Errorf("CheckReadsAfter = %v, want the unknown name", err)
		}
	})
	t.Run("cycle", func(t *testing.T) {
		reg := NewRegistry()
		reg.RegisterScanner(scanner("x", "y"))
		reg.RegisterScanner(scanner("y", "x"))
		if err := reg.CheckReadsAfter(); err == nil || !strings.Contains(err.Error(), "x → y → x") {
			t.Errorf("CheckReadsAfter = %v, want the cycle", err)
		}
	})
}

// A reader that reads after the run waits for the filler on every repository, its own and the
// others', because the state it reads is one for the whole run. Run with one slot and with four.
func TestAReaderThatReadsAfterTheRunWaitsForEveryRepository(t *testing.T) {
	for _, jobs := range []int{1, 4} {
		t.Run(fmt.Sprintf("j%d", jobs), func(t *testing.T) {
			log := &eventLog{}
			reader := &stepScanner{name: "reader", after: []string{"filler"}, runWide: true, log: log}
			filler := &stepScanner{name: "filler", log: log,
				hold: func(context.Context, string) error { time.Sleep(50 * time.Millisecond); return nil }}
			reg, m := readerAndFiller(reader, filler,
				[]string{"repo-a", "repo-b"}, []string{"repo-a", "repo-b", "repo-c"})

			res, err := runBounded(context.Background(), t, New(reg, WithConcurrency(jobs), WithoutPrewarm()), m)
			if err != nil {
				t.Fatalf("Run: %v (events: %s)", err, log)
			}
			for _, reading := range []string{"repo-a", "repo-b"} {
				started := log.at("start reader " + reading)
				for _, filled := range []string{"repo-a", "repo-b", "repo-c"} {
					if ended := log.at("end filler " + filled); started < 0 || ended < 0 || started < ended {
						t.Errorf("the reader on %s started before the filler on %s ended: %s", reading, filled, log)
					}
				}
			}
			if got := len(res.Controls["licenses"].Report.Results); got != 2 {
				t.Errorf("licenses results = %d, want one per repository", got)
			}
		})
	}
}
