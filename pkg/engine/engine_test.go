package engine

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/draugr-dev/draugr/pkg/cache"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// --- fakes ---

type fakeScanner struct {
	name    string
	version string
	fail    bool
	mu      sync.Mutex
	call    int
}

func (f *fakeScanner) Info() plugin.ScannerInfo {
	return plugin.ScannerInfo{Name: f.name, Version: f.version}
}

func (f *fakeScanner) Scan(_ context.Context, target plugin.Target, _ plugin.Config) (sarif.Report, error) {
	f.mu.Lock()
	f.call++
	f.mu.Unlock()
	if f.fail {
		return sarif.Report{}, errors.New("boom")
	}
	// Vary the finding by target so distinct targets don't dedup away.
	return sarif.Report{Tool: f.name, Results: []sarif.Result{
		{RuleID: "R", Level: sarif.LevelWarning, Location: sarif.Location{URI: target.Identity()}},
	}}, nil
}

func (f *fakeScanner) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.call
}

type fakeController struct {
	name     string
	scope    plugin.Scope
	scanner  string
	planFail bool
}

func (c fakeController) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: c.name, Scope: c.scope}
}

func (c fakeController) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if c.planFail {
		return nil, errors.New("plan failed")
	}
	var target plugin.Target = plugin.RepositoryTarget{URL: "proj"}
	if c.scope == plugin.ScopeComponent {
		if comp == nil {
			return nil, nil
		}
		target = plugin.ImageTarget{Ref: comp.Name}
	}
	return []plugin.ScanJob{{Scanner: c.scanner, Target: target}}, nil
}

func (c fakeController) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	merged := sarif.Merge(reports...)
	return plugin.ControlResult{
		Control: c.name,
		Report:  merged,
		Summary: plugin.Summary{Warnings: merged.Counts().Warning},
	}, nil
}

func model() saga.Model {
	return saga.Model{
		Release: saga.Release{Version: "1"},
		Config: saga.Config{Controllers: map[string]saga.ControllerSettings{
			"images": {"enabled": true},
			"infra":  {"enabled": true},
		}},
		Components: []saga.Component{{Name: "a"}, {Name: "b"}},
	}
}

// --- tests ---

func TestWithPrioritizationStampsFindings(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "images", scope: plugin.ScopeComponent, scanner: "s"})
	reg.RegisterScanner(&fakeScanner{name: "s"})
	m := saga.Model{
		Release:    saga.Release{Version: "1"},
		Config:     saga.Config{Controllers: map[string]saga.ControllerSettings{"images": {"enabled": true}}},
		Components: []saga.Component{{Name: "a", Exposure: saga.ExposurePublic, Criticality: saga.CriticalityCritical}},
	}
	// The prioritizer receives the component's classification and the control name.
	prio := func(control string, e saga.Exposure, c saga.Criticality, _ sarif.Result) Priority {
		if control == "images" && e == saga.ExposurePublic && c == saga.CriticalityCritical {
			return Priority{Band: "P1", Escalation: &sarif.Escalation{
				From: sarif.SeverityHigh, Signal: "kev", Detail: "on KEV", AsOf: "2026-08-01",
			}}
		}
		return Priority{Band: "P4"}
	}
	res, err := New(reg, WithPrioritization(prio)).Run(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	report := res.Controls["images"].Report
	if len(report.Results) != 1 || report.Results[0].Priority != "P1" {
		t.Fatalf("expected finding stamped P1, got %+v", report.Results)
	}
	// The reason travels with the band. A band on its own states a conclusion and withholds
	// the premise it was computed from.
	esc := report.Results[0].Escalation
	if esc == nil || esc.Signal != "kev" || esc.From != sarif.SeverityHigh || esc.AsOf != "2026-08-01" {
		t.Errorf("escalation did not reach the result: %+v", esc)
	}
}

func TestNoPrioritizationLeavesPriorityEmpty(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "images", scope: plugin.ScopeComponent, scanner: "s"})
	reg.RegisterScanner(&fakeScanner{name: "s"})
	res, err := New(reg).Run(context.Background(), model())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res.Controls["images"].Report.Results {
		if r.Priority != "" {
			t.Errorf("priority should be empty without WithPrioritization, got %q", r.Priority)
		}
	}
}

func TestPlanComponentScope(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "images", scope: plugin.ScopeComponent, scanner: "s"})
	reg.RegisterScanner(&fakeScanner{name: "s"})

	jobs, err := New(reg).Plan(model())
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 2 {
		t.Fatalf("want 2 jobs (one per component), got %d", len(jobs))
	}
	for _, j := range jobs {
		if j.Control != "images" {
			t.Errorf("job control = %q", j.Control)
		}
	}
}

func TestPlanProjectScope(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "infra", scope: plugin.ScopeProject, scanner: "s"})
	jobs, err := New(reg).Plan(model())
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 {
		t.Fatalf("project-scope should plan 1 job, got %d", len(jobs))
	}
}

func TestPlanSkipsDisabled(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "dast", scope: plugin.ScopeComponent, scanner: "s"})
	jobs, err := New(reg).Plan(model()) // "dast" not enabled in config
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 0 {
		t.Fatalf("disabled controller should plan 0 jobs, got %d", len(jobs))
	}
}

func TestPlanControllerError(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "images", scope: plugin.ScopeComponent, scanner: "s", planFail: true})
	_, err := New(reg).Plan(model())
	if err == nil {
		t.Fatal("expected plan error")
	}
}

func TestRunAggregates(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "images", scope: plugin.ScopeComponent, scanner: "s"})
	sc := &fakeScanner{name: "s"}
	reg.RegisterScanner(sc)

	res, err := New(reg).Run(context.Background(), model())
	if err != nil {
		t.Fatalf("run error: %v", err)
	}
	cr, ok := res.Controls["images"]
	if !ok {
		t.Fatal("no images control result")
	}
	if cr.Summary.Warnings != 2 {
		t.Fatalf("want 2 warnings aggregated, got %d", cr.Summary.Warnings)
	}
	if sc.calls() != 2 {
		t.Errorf("scanner should be called twice, got %d", sc.calls())
	}
}

func TestRunScannerNotFound(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "images", scope: plugin.ScopeComponent, scanner: "missing"})
	res, err := New(reg).Run(context.Background(), model())
	if err == nil {
		t.Fatal("expected error for missing scanner")
	}
	if len(res.Controls) != 0 {
		t.Errorf("no results expected, got %d", len(res.Controls))
	}
}

func TestRunScanError(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "images", scope: plugin.ScopeComponent, scanner: "s"})
	reg.RegisterScanner(&fakeScanner{name: "s", fail: true})
	_, err := New(reg).Run(context.Background(), model())
	if err == nil {
		t.Fatal("expected scan error")
	}
}

func TestRunContextCanceled(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "images", scope: plugin.ScopeComponent, scanner: "s"})
	reg.RegisterScanner(&fakeScanner{name: "s"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := New(reg).Run(ctx, model())
	if err == nil {
		t.Fatal("expected context error")
	}
	if len(res.Controls) != 0 {
		t.Errorf("canceled run should produce no results, got %d", len(res.Controls))
	}
}

func TestRunWithCache(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "images", scope: plugin.ScopeComponent, scanner: "s"})
	sc := &fakeScanner{name: "s"}
	reg.RegisterScanner(sc)

	e := New(reg, WithCache(cache.NewMemory()))

	// First run: 2 jobs, both scanned and cached.
	res1, err := e.Run(context.Background(), model())
	if err != nil {
		t.Fatal(err)
	}
	if res1.Stats.Scans != 2 || res1.Stats.CacheHits != 0 {
		t.Fatalf("first run stats = %+v, want 2 scans / 0 hits", res1.Stats)
	}
	if sc.calls() != 2 {
		t.Fatalf("scanner calls after run 1 = %d, want 2", sc.calls())
	}

	// Second run: same inputs → all cache hits, no new scans.
	res2, err := e.Run(context.Background(), model())
	if err != nil {
		t.Fatal(err)
	}
	if res2.Stats.CacheHits != 2 || res2.Stats.Scans != 0 {
		t.Fatalf("second run stats = %+v, want 0 scans / 2 hits", res2.Stats)
	}
	if sc.calls() != 2 {
		t.Errorf("scanner should not be called again, total calls = %d", sc.calls())
	}
	// Cached results still aggregate correctly.
	if res2.Controls["images"].Summary.Warnings != 2 {
		t.Errorf("cached aggregation wrong: %+v", res2.Controls["images"].Summary)
	}
}

func TestWithConcurrencySerialStillCompletes(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "images", scope: plugin.ScopeComponent, scanner: "s"})
	sc := &fakeScanner{name: "s"}
	reg.RegisterScanner(sc)

	// concurrency 0 is ignored (default used); 1 forces serial.
	e := New(reg, WithConcurrency(0), WithConcurrency(1))
	if _, err := e.Run(context.Background(), model()); err != nil {
		t.Fatal(err)
	}
	if sc.calls() != 2 {
		t.Errorf("all jobs should run even serially, got %d calls", sc.calls())
	}
}

// A scan that couldn't run has to be attributable, or the report can't name it and the gate
// can't distinguish "clean" from "unchecked".
func TestRunAttributesScanErrorsToTheirControl(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "sca", scope: plugin.ScopeComponent, scanner: "broken"})
	reg.RegisterScanner(&fakeScanner{name: "broken", fail: true})

	res, err := New(reg).Run(context.Background(), saga.Model{
		Release: saga.Release{Name: "app", Version: "1"},
		Components: []saga.Component{
			{Name: "c", Controllers: map[string]saga.ControllerSettings{"sca": {}}},
		},
	})
	if err == nil {
		t.Fatal("want an error from a failed scan")
	}
	msgs, ok := res.ScanErrors["sca"]
	if !ok {
		t.Fatalf("ScanErrors = %v, want an entry for sca", res.ScanErrors)
	}
	if len(msgs) != 1 || !strings.Contains(msgs[0], "boom") {
		t.Errorf("ScanErrors[sca] = %v, want the underlying error", msgs)
	}
	// The control produced no result at all, which is exactly why it has to be reported.
	if _, present := res.Controls["sca"]; present {
		t.Error("a control whose only scan failed should have no result")
	}
}

// A run where everything worked must not claim otherwise.
func TestRunReportsNoScanErrorsOnSuccess(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "sca", scope: plugin.ScopeComponent, scanner: "ok"})
	reg.RegisterScanner(&fakeScanner{name: "ok"})
	res, err := New(reg).Run(context.Background(), saga.Model{
		Release: saga.Release{Name: "app", Version: "1"},
		Components: []saga.Component{
			{Name: "c", Controllers: map[string]saga.ControllerSettings{"sca": {}}},
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.ScanErrors) != 0 {
		t.Errorf("ScanErrors = %v, want none", res.ScanErrors)
	}
}

// The hole this closes: a descriptor that enables no control produced no findings, no failures,
// and a PASS — identical output to a spotless application. The wrong reading is far more likely,
// since a descriptor reaches that state by being unfinished or by being generated from discovery.
func TestRunReportsThatNothingWasChecked(t *testing.T) {
	t.Parallel()

	model := saga.Model{
		Release:    saga.Release{Name: "app", Version: "1.0"},
		Components: []saga.Component{{Name: "web", Repositories: []saga.Repository{{URL: "https://example.test/x.git"}}}},
	}
	res, err := New(NewRegistry()).Run(context.Background(), model)
	if err != nil {
		t.Fatal(err)
	}
	msgs := res.ScanErrors["(planning)"]
	if len(msgs) == 0 {
		t.Fatal("a run that checked nothing must report it, not pass silently")
	}
	// The message has to say what to do; "nothing ran" alone leaves the reader guessing whether
	// it is their descriptor or a broken install.
	joined := strings.Join(msgs, " ")
	for _, want := range []string{"no controls ran", "config.controllers"} {
		if !strings.Contains(joined, want) {
			t.Errorf("message should mention %q, got %q", want, joined)
		}
	}
}

// A descriptor that asks only for an SBOM enables no control and plans no job, but it does
// produce the evidence it was asked for — so it has done what it said, and must not be reported
// as having checked nothing.
func TestRunDoesNotComplainAboutAnSBOMOnlyDescriptor(t *testing.T) {
	t.Parallel()

	model := saga.Model{
		Release:    saga.Release{Name: "app", Version: "1.0"},
		Config:     saga.Config{SBOM: &saga.SBOMConfig{Enabled: true}},
		Components: []saga.Component{{Name: "web", Repositories: []saga.Repository{{URL: "https://example.test/x.git"}}}},
	}
	res, err := New(NewRegistry(), WithSBOM(&fakeSBOM{})).Run(context.Background(), model)
	if err != nil {
		t.Fatal(err)
	}
	if msgs := res.ScanErrors["(planning)"]; len(msgs) > 0 {
		t.Errorf("an SBOM-only descriptor did what it asked; got %v", msgs)
	}
}

// Every report should say what produced it, without each scanner having to remember. A scanner
// written later by someone who never read this file still gets provenance.
func TestEngineStampsProvenanceOnEveryReport(t *testing.T) {
	t.Parallel()

	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "images", scope: plugin.ScopeComponent, scanner: "s"})
	reg.RegisterScanner(&fakeScanner{name: "s", version: "1.2.3"})

	res, err := New(reg).Run(context.Background(), model())
	if err != nil {
		t.Fatal(err)
	}
	got := res.Controls["images"].Report.Provenance
	if len(got) != 1 {
		t.Fatalf("want one account of the scan, got %+v", got)
	}
	if got[0].Tool != "s" || got[0].Version != "1.2.3" {
		t.Errorf("provenance = %+v, want the scanner and its version", got[0])
	}
}

// The scanner with the best version information is the one whose version is not static: Trivy
// reports its vulnerability-DB version through CacheVersion. Caching resolves that anyway, so
// provenance reuses it rather than probing again or reporting nothing.
func TestProvenanceUsesTheResolvedVersionWhenCaching(t *testing.T) {
	t.Parallel()

	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "images", scope: plugin.ScopeComponent, scanner: "s"})
	reg.RegisterScanner(&versionedScanner{name: "s", version: "db@1"})

	res, err := New(reg, WithCache(cache.NewMemory())).Run(context.Background(), model())
	if err != nil {
		t.Fatal(err)
	}
	got := res.Controls["images"].Report.Provenance
	if len(got) != 1 || got[0].Version != "db@1" {
		t.Errorf("provenance = %+v, want the version the cache resolved", got)
	}
}

// A scanner reporting no version has nothing to say, and an entry saying nothing is noise in
// every report that renders it.
func TestNoProvenanceForAScannerWithNoVersion(t *testing.T) {
	t.Parallel()

	var r sarif.Report
	recordProvenance(&r, "quiet", "")
	if len(r.Provenance) != 0 {
		t.Errorf("want no entry, got %+v", r.Provenance)
	}
}

// A scanner that described its own run keeps what it said and gains the version it did not know.
func TestRecordProvenanceAugmentsWhatTheScannerSaid(t *testing.T) {
	t.Parallel()

	r := sarif.Report{Provenance: []sarif.Provenance{{
		Tool:   "kube-bench",
		Fields: []sarif.Field{{Key: "benchmark", Value: "gke-1.9.0"}},
	}}}
	recordProvenance(&r, "kube-bench", "0.15.6")

	if len(r.Provenance) != 1 {
		t.Fatalf("the scanner's own entry should be augmented, not duplicated: %+v", r.Provenance)
	}
	if r.Provenance[0].Version != "0.15.6" {
		t.Errorf("version = %q, want it filled in", r.Provenance[0].Version)
	}
	if len(r.Provenance[0].Fields) != 1 {
		t.Errorf("the scanner's fields must survive: %+v", r.Provenance[0].Fields)
	}
}

// A finding has to say which component it belongs to. A location alone is ambiguous the moment a
// descriptor has two, and it is what makes the priority checkable — the band is computed from
// that component's declared classification.
func TestFindingsCarryTheirComponent(t *testing.T) {
	t.Parallel()

	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "images", scope: plugin.ScopeComponent, scanner: "s"})
	reg.RegisterScanner(&fakeScanner{name: "s"})

	res, err := New(reg).Run(context.Background(), model())
	if err != nil {
		t.Fatal(err)
	}
	results := res.Controls["images"].Report.Results
	if len(results) == 0 {
		t.Fatal("expected findings")
	}
	for _, r := range results {
		if r.Component == "" {
			t.Errorf("finding %q has no component", r.RuleID)
		}
	}
}

// warmingScanner is a fakeScanner that also counts how often it was prewarmed.
type warmingScanner struct {
	fakeScanner
	warms int
}

func (w *warmingScanner) Prewarm(context.Context) error {
	w.warms++
	return nil
}

func TestWithoutPrewarmSkipsWarmingButStillScans(t *testing.T) {
	newReg := func(sc plugin.Scanner) *Registry {
		reg := NewRegistry()
		reg.RegisterController(fakeController{name: "images", scope: plugin.ScopeComponent, scanner: "s"})
		reg.RegisterScanner(sc)
		return reg
	}

	offline := &warmingScanner{fakeScanner: fakeScanner{name: "s"}}
	res, err := New(newReg(offline), WithoutPrewarm()).Run(context.Background(), model())
	if err != nil {
		t.Fatal(err)
	}
	if offline.warms != 0 {
		t.Errorf("prewarmed %d times while offline", offline.warms)
	}
	// The scan itself must still happen against whatever is on disk. Skipping the warm-up is
	// not skipping the run — an earlier version of this cleared the wrong slice and did both.
	if offline.calls() == 0 {
		t.Error("no scans ran; the run was skipped rather than the warm-up")
	}
	if len(res.Controls) == 0 {
		t.Error("no control results")
	}

	online := &warmingScanner{fakeScanner: fakeScanner{name: "s"}}
	if _, err := New(newReg(online)).Run(context.Background(), model()); err != nil {
		t.Fatal(err)
	}
	if online.warms != 1 {
		t.Errorf("prewarmed %d times without the option, want 1", online.warms)
	}
}

func TestWithCacheableTargetVetoesAJob(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "images", scope: plugin.ScopeComponent, scanner: "s"})
	sc := &fakeScanner{name: "s"}
	reg.RegisterScanner(sc)

	// Reject everything: the scan still runs, and nothing is stored — a vetoed target behaves
	// exactly as though caching were off.
	c := cache.NewMemory()
	if _, err := New(reg, WithCache(c), WithCacheableTarget(func(plugin.Target) bool { return false })).
		Run(context.Background(), model()); err != nil {
		t.Fatal(err)
	}
	before := sc.calls()
	if before == 0 {
		t.Fatal("no scans ran")
	}
	// A second run must scan again, because the first stored nothing.
	if _, err := New(reg, WithCache(c), WithCacheableTarget(func(plugin.Target) bool { return false })).
		Run(context.Background(), model()); err != nil {
		t.Fatal(err)
	}
	if sc.calls() == before {
		t.Error("the second run was served from a cache the veto should have kept empty")
	}

	// Accepting everything caches as usual, so the veto is what made the difference above.
	sc2 := &fakeScanner{name: "s"}
	reg2 := NewRegistry()
	reg2.RegisterController(fakeController{name: "images", scope: plugin.ScopeComponent, scanner: "s"})
	reg2.RegisterScanner(sc2)
	shared := cache.NewMemory()
	for range 2 {
		if _, err := New(reg2, WithCache(shared)).Run(context.Background(), model()); err != nil {
			t.Fatal(err)
		}
	}
	if n := sc2.calls(); n != 2 {
		t.Errorf("with caching on, expected 2 scans across two runs (one per target), got %d", n)
	}
}

func TestWithWorkingTreeRefusesToCacheWhatItScans(t *testing.T) {
	// Two runs at the same revision read different bytes, so a cache keyed on the revision would
	// answer the second with the first's findings.
	e := New(NewRegistry(), WithWorkingTree())
	if e.cacheable == nil {
		t.Fatal("no cache veto was registered")
	}
	if e.cacheable(plugin.RepositoryTarget{URL: ".", Revision: "abc", WorkingTree: true}) {
		t.Error("a working-tree scan was cacheable")
	}
	// Everything else is still cacheable, including a committed scan of the same repository.
	if !e.cacheable(plugin.RepositoryTarget{URL: ".", Revision: "abc"}) {
		t.Error("the veto swallowed the committed scan too")
	}
	if !e.cacheable(plugin.ImageTarget{Ref: "acme/api@sha256:abc"}) {
		t.Error("the veto swallowed an image")
	}
}

func TestWithWorkingTreeComposesWithAnExistingVeto(t *testing.T) {
	// --cache-require-digest already registers one. The second must not silently replace it.
	e := New(NewRegistry(),
		WithCacheableTarget(func(plugin.Target) bool { return false }),
		WithWorkingTree())
	if e.cacheable(plugin.ImageTarget{Ref: "acme/api:latest"}) {
		t.Error("the earlier veto was discarded")
	}
}

// A scanner may declare several effects, and reporting one at a time turns accepting them into a
// sequence of scans, each ending in a refusal naming an effect the previous run never mentioned.
// The decision is whether to let the scanner do all of it, so it has to be asked once.
func TestConsentNamesEveryUnacceptedEffect(t *testing.T) {
	t.Parallel()
	info := plugin.ScannerInfo{
		Name: "kube-bench-job",
		Effects: []plugin.Effect{
			{Kind: plugin.EffectMutate, Detail: "creates a short-lived Job"},
			{Kind: plugin.EffectPrivilege, Detail: "runs privileged with host mounts"},
		},
	}

	err := consentFor(info, nil)
	if err == nil {
		t.Fatal("want a refusal")
	}
	for _, want := range []string{"mutate", "privilege", "creates a short-lived Job",
		"runs privileged with host mounts", "--allow-effects mutate,privilege"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal should mention %q:\n%v", want, err)
		}
	}

	// Accepting one leaves the other, named on its own rather than as a list of one.
	err = consentFor(info, map[plugin.EffectKind]bool{plugin.EffectMutate: true})
	if err == nil {
		t.Fatal("want a refusal for the remaining effect")
	}
	if strings.Contains(err.Error(), "mutate") {
		t.Errorf("an accepted effect should not be listed again:\n%v", err)
	}
	if !strings.Contains(err.Error(), "an effect that has not been accepted") {
		t.Errorf("a single effect should read as one:\n%v", err)
	}

	if err := consentFor(info, map[plugin.EffectKind]bool{
		plugin.EffectMutate: true, plugin.EffectPrivilege: true,
	}); err != nil {
		t.Errorf("everything accepted should pass: %v", err)
	}
}

// A run that says nothing while it works is indistinguishable from one that has hung, and the jobs
// worth waiting on are exactly the slow ones. The snapshots have to describe the run truthfully at
// every point: never more complete than planned, and never claiming more in flight than the pool
// can hold.
func TestProgressDescribesTheRunAsItGoes(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var events []ProgressEvent
	reg := NewRegistry()
	// Two controls over two components: four jobs, more than the pool, so the snapshots have to
	// describe a queue rather than everything at once.
	reg.RegisterController(fakeController{name: "images", scope: plugin.ScopeComponent, scanner: "s"})
	reg.RegisterController(fakeController{name: "infra", scope: plugin.ScopeComponent, scanner: "s"})
	reg.RegisterScanner(&fakeScanner{name: "s"})

	eng := New(reg, WithConcurrency(2), WithProgress(func(ev ProgressEvent) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, ev)
	}))

	if _, err := eng.Run(context.Background(), model()); err != nil {
		t.Fatalf("run: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(events) == 0 {
		t.Fatal("a run reported nothing about itself")
	}
	total := events[0].Total
	if total == 0 {
		t.Fatal("the first snapshot should already know how many jobs were planned")
	}
	for i, ev := range events {
		if ev.Total != total {
			t.Errorf("event %d: total changed from %d to %d mid-run", i, total, ev.Total)
		}
		if ev.Complete > ev.Total {
			t.Errorf("event %d: %d complete of %d planned", i, ev.Complete, ev.Total)
		}
		if len(ev.Running) > 2 {
			t.Errorf("event %d: %d jobs in flight on a pool of 2", i, len(ev.Running))
		}
		if ev.Complete+len(ev.Running) > ev.Total {
			t.Errorf("event %d: %d done plus %d running exceeds %d planned",
				i, ev.Complete, len(ev.Running), ev.Total)
		}
	}
	// The run is over, so the last word has to be that everything finished and nothing is left.
	last := events[len(events)-1]
	if last.Complete != last.Total || len(last.Running) != 0 {
		t.Errorf("the final snapshot should be %d/%d with nothing running, got %d/%d running %v",
			total, total, last.Complete, last.Total, last.Running)
	}
}
