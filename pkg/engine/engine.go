// Package engine orchestrates a run: it expands a Saga into scan jobs
// (controllers × components), executes them with bounded parallelism, and aggregates
// each control's results. Content-hash caching and the full describe→publish pipeline
// build on this.
package engine

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/draugr-dev/draugr/pkg/cache"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// Engine plans and runs scans against a registry of controllers and scanners.
type Engine struct {
	reg         *Registry
	concurrency int
	cache       cache.Cache
	prioritize  Prioritizer
}

// Prioritizer computes a finding's priority band from its control and its component's risk
// classification. Injected via WithPrioritization so the engine stays decoupled from the
// prioritization matrices and per-control severity floors; nil disables priority stamping.
type Prioritizer func(control string, exposure saga.Exposure, criticality saga.Criticality, res sarif.Result) string

// Option configures an Engine.
type Option func(*Engine)

// WithConcurrency sets the maximum number of scan jobs running at once. Values < 1 are
// ignored (the default is used).
func WithConcurrency(n int) Option {
	return func(e *Engine) {
		if n >= 1 {
			e.concurrency = n
		}
	}
}

// WithCache enables result caching: a cache hit for a job's key reuses the stored report
// instead of re-scanning. A nil cache disables caching (the default).
func WithCache(c cache.Cache) Option {
	return func(e *Engine) { e.cache = c }
}

// WithPrioritization stamps each finding with a priority band computed by p. Priority is
// applied per run (never cached), since it depends on the component's current classification.
func WithPrioritization(p Prioritizer) Option {
	return func(e *Engine) { e.prioritize = p }
}

// New creates an Engine over the given registry. By default it runs up to NumCPU jobs
// concurrently.
func New(reg *Registry, opts ...Option) *Engine {
	e := &Engine{reg: reg, concurrency: defaultConcurrency()}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

func defaultConcurrency() int {
	if n := runtime.NumCPU(); n > 0 {
		return n
	}
	return 1
}

// PlannedJob is a scan job tagged with the control that produced it and the risk
// classification of the component it targets (empty for project-scoped controls).
type PlannedJob struct {
	Control     string
	Job         plugin.ScanJob
	Exposure    saga.Exposure
	Criticality saga.Criticality
}

// Plan expands the model into scan jobs. Only registered controllers that are enabled
// (project-level for project-scoped controllers, per-component for component-scoped ones)
// are planned. Controllers are visited in name order for determinism.
func (e *Engine) Plan(model saga.Model) ([]PlannedJob, error) {
	var planned []PlannedJob
	var errs []error

	for _, name := range sortedControllerNames(e.reg.controllers) {
		ctrl := e.reg.controllers[name]
		switch ctrl.Info().Scope {
		case plugin.ScopeProject:
			if !model.Config.ControllerEnabled(name) {
				continue
			}
			jobs, err := ctrl.Plan(model, nil)
			if err != nil {
				errs = append(errs, fmt.Errorf("plan %s: %w", name, err))
				continue
			}
			planned = appendJobs(planned, name, "", "", jobs)
		case plugin.ScopeComponent:
			for i := range model.Components {
				comp := &model.Components[i]
				if !comp.ControllerEnabled(name, model.Config) {
					continue
				}
				jobs, err := ctrl.Plan(model, comp)
				if err != nil {
					errs = append(errs, fmt.Errorf("plan %s/%s: %w", name, comp.Name, err))
					continue
				}
				planned = appendJobs(planned, name, comp.Exposure, comp.Criticality, jobs)
			}
		}
	}
	return planned, errors.Join(errs...)
}

// Result is the outcome of a run: one aggregated ControlResult per control, plus run
// statistics.
type Result struct {
	Controls map[string]plugin.ControlResult
	Stats    Stats
}

// Stats summarizes execution, including cache effectiveness.
type Stats struct {
	Jobs      int
	Scans     int
	CacheHits int
	// Deduped counts jobs that reused an identical scan already running/completed in this run
	// (in-run singleflight), rather than scanning or hitting the persistent cache.
	Deduped int
}

// scanOutcome is the raw result of obtaining a job's report (via cache or a fresh scan),
// shared across identical jobs by the in-run singleflight before per-job priority stamping.
type scanOutcome struct {
	report sarif.Report
	cached bool
}

// effectiveKey returns the job's cache key, computing one from the scan inputs when the
// controller did not set it. The version component reflects the scanner's tool/data version:
// a CacheVersioner (e.g. Trivy, folding in its vuln-DB version) takes precedence over the
// static ScannerInfo.Version, so an updated database invalidates cached results.
func effectiveKey(ctx context.Context, job plugin.ScanJob, scanner plugin.Scanner) string {
	if job.CacheKey != "" {
		return string(job.CacheKey)
	}
	version := scanner.Info().Version
	if cv, ok := scanner.(plugin.CacheVersioner); ok {
		if v := cv.CacheVersion(ctx); v != "" {
			version = v
		}
	}
	return string(plugin.ComputeCacheKey(job.Scanner, version, job.Target, job.Config))
}

// Run plans and executes scans with bounded concurrency, then aggregates per control.
// Scan errors do not abort the run; they are collected and returned (joined) alongside
// whatever results succeeded. Honors ctx cancellation.
func (e *Engine) Run(ctx context.Context, model saga.Model) (Result, error) {
	planned, planErr := e.Plan(model)

	ctx, runSpan := tracer.Start(ctx, "engine.run",
		trace.WithAttributes(attribute.Int("jobs", len(planned))))
	defer runSpan.End()

	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		byCtl    = make(map[string][]sarif.Report)
		errs     []error
		stats    = Stats{Jobs: len(planned)}
		sem      = make(chan struct{}, e.concurrency)
		sf       = &sfGroup{}
		canceled bool
	)
	if planErr != nil {
		// Runs before any worker goroutine starts; the concurrent appends below are
		// mutex-guarded, so this is not a data race.
		errs = append(errs, planErr) // nosem: trailofbits.go.racy-append-to-slice.racy-append-to-slice
	}

	// Warm shared scanner state (e.g. Trivy's vuln DB) once per distinct scanner, before the
	// concurrent fan-out — so parallel scans don't each cold-start it. Best-effort.
	warmed := make(map[string]bool)
	for _, pj := range planned {
		if ctx.Err() != nil {
			break
		}
		name := pj.Job.Scanner
		if warmed[name] {
			continue
		}
		warmed[name] = true
		if sc, ok := e.reg.Scanner(name); ok {
			if pw, ok := sc.(plugin.Prewarmer); ok {
				if err := pw.Prewarm(ctx); err != nil {
					runSpan.AddEvent("prewarm failed", trace.WithAttributes(
						attribute.String("scanner", name), attribute.String("error", err.Error())))
				}
			}
		}
	}

	for _, pj := range planned {
		if ctx.Err() != nil {
			canceled = true
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(pj PlannedJob) {
			defer wg.Done()
			defer func() { <-sem }()

			jobCtx, span := tracer.Start(ctx, "engine.scan", trace.WithAttributes(
				attribute.String("control", pj.Control),
				attribute.String("scanner", pj.Job.Scanner),
			))
			defer span.End()

			scanner, ok := e.reg.Scanner(pj.Job.Scanner)
			if !ok {
				err := fmt.Errorf("no scanner %q for control %q", pj.Job.Scanner, pj.Control)
				span.RecordError(err)
				span.SetStatus(codes.Error, "scanner not found")
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
				return
			}
			span.SetAttributes(attribute.String("target.kind", string(pj.Job.Target.Kind())))

			// Collapse identical concurrent jobs (same scanner+target+config) to a single scan.
			// The version-less identity is cheap (no DB-version probe) and constant within a run.
			ident := string(plugin.ComputeCacheKey(pj.Job.Scanner, "", pj.Job.Target, pj.Job.Config))
			out, shared, scanErr := sf.do(ident, func() (any, error) {
				// The cache key (and any tool/DB version probe) is built only when caching is on.
				var key string
				if e.cache != nil {
					key = effectiveKey(jobCtx, pj.Job, scanner)
					if rep, hit := e.cache.Get(key); hit {
						cacheHitCounter.Add(jobCtx, 1, metric.WithAttributes(attribute.String("control", pj.Control)))
						return scanOutcome{report: rep, cached: true}, nil
					}
				}
				start := time.Now()
				rep, err := scanner.Scan(jobCtx, pj.Job.Target, pj.Job.Config)
				scanDuration.Record(jobCtx, time.Since(start).Seconds(),
					metric.WithAttributes(attribute.String("scanner", pj.Job.Scanner)))
				if err != nil {
					return scanOutcome{}, err
				}
				if e.cache != nil {
					_ = e.cache.Put(key, rep) // cache the raw findings; priority is stamped per run
				}
				scanCounter.Add(jobCtx, 1, metric.WithAttributes(attribute.String("scanner", pj.Job.Scanner)))
				return scanOutcome{report: rep}, nil
			})
			if scanErr != nil {
				span.RecordError(scanErr)
				span.SetStatus(codes.Error, "scan failed")
				if !shared { // record the underlying error once, not once per collapsed job
					mu.Lock()
					errs = append(errs, fmt.Errorf("scan %s/%s: %w", pj.Control, pj.Job.Scanner, scanErr))
					mu.Unlock()
				}
				return
			}
			res := out.(scanOutcome)
			span.SetAttributes(attribute.Bool("cache.hit", res.cached), attribute.Bool("dedup", shared))
			recordFindings(jobCtx, pj.Control, res.report)
			report := e.stampPriority(res.report, pj)
			mu.Lock()
			byCtl[pj.Control] = append(byCtl[pj.Control], report)
			switch {
			case shared:
				stats.Deduped++
			case res.cached:
				stats.CacheHits++
			default:
				stats.Scans++
			}
			mu.Unlock()
		}(pj)
	}
	wg.Wait()
	if canceled {
		errs = append(errs, ctx.Err())
	}

	res := Result{Controls: make(map[string]plugin.ControlResult), Stats: stats}
	for _, control := range sortedReportKeys(byCtl) {
		ctrl, ok := e.reg.Controller(control)
		if !ok {
			continue
		}
		cr, err := ctrl.Aggregate(byCtl[control])
		if err != nil {
			errs = append(errs, fmt.Errorf("aggregate %s: %w", control, err))
			continue
		}
		res.Controls[control] = cr
	}
	return res, errors.Join(errs...)
}

func appendJobs(dst []PlannedJob, control string, exposure saga.Exposure, criticality saga.Criticality, jobs []plugin.ScanJob) []PlannedJob {
	for _, j := range jobs {
		dst = append(dst, PlannedJob{Control: control, Job: j, Exposure: exposure, Criticality: criticality})
	}
	return dst
}

// stampPriority returns a copy of report with each finding's Priority set from the injected
// Prioritizer. It copies the results slice so a cached report is never mutated (priority is
// per-run, since classification can differ between jobs sharing a cache key).
func (e *Engine) stampPriority(report sarif.Report, pj PlannedJob) sarif.Report {
	if e.prioritize == nil || len(report.Results) == 0 {
		return report
	}
	out := report
	out.Results = make([]sarif.Result, len(report.Results))
	copy(out.Results, report.Results)
	for i := range out.Results {
		out.Results[i].Priority = e.prioritize(pj.Control, pj.Exposure, pj.Criticality, out.Results[i])
	}
	return out
}

func sortedControllerNames(m map[string]plugin.Controller) []string {
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

func sortedReportKeys(m map[string][]sarif.Report) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
