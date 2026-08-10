// Package engine orchestrates a run: it expands a Saga into scan jobs
// (controllers × components), executes them with bounded parallelism, and aggregates
// each control's results. Content-hash caching and the full describe→publish pipeline
// build on this.
package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"sort"
	"strings"
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
	"github.com/draugr-dev/draugr/pkg/sbom"
)

// Engine plans and runs scans against a registry of controllers and scanners.
type Engine struct {
	reg         *Registry
	concurrency int
	cache       cache.Cache
	// cacheable, when set, vetoes caching for targets it rejects.
	cacheable func(plugin.Target) bool
	// workingTree scans repositories as they are on disk rather than at their committed revision.
	workingTree bool
	// resolveRemote names a local checkout by its remote — see WithRemoteResolver.
	resolveRemote RemoteResolver
	prioritize    Prioritizer
	// skipPrewarm suppresses the pre-run warm-up of shared scanner state (Trivy's database,
	// Nuclei's templates), which is the only part of a scan that reaches the network on its own.
	skipPrewarm bool
	sbomGen     sbom.Generator
	// allowEffects are scanner effects accepted for this invocation, layered over the Saga's.
	allowEffects []string
	// scope narrows the run to named components and controls; the zero value scans everything.
	scope Scope
}

// Prioritizer computes a finding's priority band from its control and its component's risk
// classification. Injected via WithPrioritization so the engine stays decoupled from the
// prioritization matrices and per-control severity floors; nil disables priority stamping.
type Prioritizer func(control string, exposure saga.Exposure, criticality saga.Criticality, res sarif.Result) Priority

// Priority is what a Prioritizer decided, and why where there is a why.
//
// A struct rather than a bare band because the band alone states a conclusion and withholds its
// premise — and because the next thing worth explaining about a ranking will not be the last.
type Priority struct {
	// Band is the action band, P1–P4. Empty leaves the finding unstamped.
	Band string
	// Escalation is set when exploitability data raised the severity the band was computed
	// from. Nil when the scanner's own rating stood.
	Escalation *sarif.Escalation
	// Floor explains a band that the component's classification alone does not account for,
	// because the control declared that exposure does not bound its findings. Empty when the
	// matrices' own answer stood.
	Floor string
}

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

// WithCacheableTarget restricts caching to targets the predicate accepts.
//
// Draugr's cache is content-addressed, which holds only while a target's identity is its content.
// A container image named by a mutable tag breaks that: the name is stable while the bytes behind
// it are not. This is the hook for a caller that would rather re-scan than be wrong about one.
//
// Nil accepts everything, which is the default.
func WithCacheableTarget(fn func(plugin.Target) bool) Option {
	return func(e *Engine) { e.cacheable = fn }
}

// WithWorkingTree scans repositories as they are on disk, uncommitted work included, instead of
// at their committed revision.
//
// Also refuses to cache what it scans. A working tree's content changes between two runs at the
// same revision, so a content-addressed cache keyed on the revision would serve the previous
// edit's findings — which is the exact opposite of what somebody iterating on a fix needs.
func WithWorkingTree() Option {
	return func(e *Engine) {
		e.workingTree = true
		prev := e.cacheable
		e.cacheable = func(t plugin.Target) bool {
			if r, ok := t.(plugin.RepositoryTarget); ok && r.WorkingTree {
				return false
			}
			return prev == nil || prev(t)
		}
	}
}

// WithPrioritization stamps each finding with a priority band computed by p. Priority is
// applied per run (never cached), since it depends on the component's current classification.
func WithPrioritization(p Prioritizer) Option {
	return func(e *Engine) { e.prioritize = p }
}

// WithoutPrewarm skips the pre-run warm-up of shared scanner state.
//
// For a run that must make no network calls. The scan still happens against whatever each tool
// already has on disk, and a tool with nothing on disk reports that itself — which is a more
// specific message than the engine could produce on its behalf.
func WithoutPrewarm() Option {
	return func(e *Engine) { e.skipPrewarm = true }
}

// RemoteResolver reports the repository a local checkout was cloned from, or "" when the path is
// not a local checkout, has no remote, or should not be resolved.
//
// Injected because resolving one means running git, which lives in internal/ — the same
// arrangement as the SBOM generator. It also makes "do not resolve" expressible by simply not
// supplying one, which is what a vendored copy or an air-gapped mirror wants: there the path is
// the more truthful answer, because the remote is absent or names something the tree no longer
// matches.
type RemoteResolver func(path string) string

// WithScope narrows the run to named components and controls. The zero Scope scans everything.
func WithScope(sc Scope) Option {
	return func(e *Engine) { e.scope = sc }
}

// WithRemoteResolver names local checkouts by the repository they came from.
func WithRemoteResolver(r RemoteResolver) Option {
	return func(e *Engine) { e.resolveRemote = r }
}

// WithSBOM supplies the generator used when a Saga enables config.sbom. Injected rather than
// imported so pkg/engine stays free of a concrete tool, exactly as it does for scanners. Nil
// (the default) means a Saga asking for SBOMs gets an error rather than silence.
func WithSBOM(g sbom.Generator) Option {
	return func(e *Engine) { e.sbomGen = g }
}

// WithAllowedEffects accepts scanner effects for this invocation, on top of whatever the Saga
// accepts. Backs the --allow-effects flag.
func WithAllowedEffects(kinds []string) Option {
	return func(e *Engine) { e.allowEffects = kinds }
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
	Control string
	Job     plugin.ScanJob
	// Component names the part of the application being scanned, empty for a project-scoped
	// control. Carried alongside the classification rather than derived from it: exposure and
	// criticality say what a component is worth, and a reader also has to know which one it was.
	Component   string
	Exposure    saga.Exposure
	Criticality saga.Criticality
}

// Plan expands the model into scan jobs. Only registered controllers that are enabled
// (project-level for project-scoped controllers, per-component for component-scoped ones)
// are planned. Controllers are visited in name order for determinism.
func (e *Engine) Plan(model saga.Model) ([]PlannedJob, error) {
	var planned []PlannedJob
	var errs []error
	allowed := allowedEffects(model.Config.AllowEffects, e.allowEffects)

	for _, name := range sortedControllerNames(e.reg.controllers) {
		ctrl := e.reg.controllers[name]
		switch ctrl.Info().Scope {
		case plugin.ScopeProject:
			if !e.scope.includesControl(name) || !model.Config.ControllerEnabled(name) {
				continue
			}
			jobs, err := ctrl.Plan(model, nil)
			if err != nil {
				errs = append(errs, fmt.Errorf("plan %s: %w", name, err))
				continue
			}
			jobs, verrs := e.validateConfigs(name, jobs, allowed)
			errs = append(errs, verrs...)
			planned = appendJobs(planned, name, "", "", "", e.resolveRemotes(e.markWorkingTree(jobs)))
		case plugin.ScopeComponent:
			if !e.scope.includesControl(name) {
				continue
			}
			for i := range model.Components {
				comp := &model.Components[i]
				if !e.scope.IncludesComponent(comp.Name) || !comp.ControllerEnabled(name, model.Config) {
					continue
				}
				jobs, err := ctrl.Plan(model, comp)
				if err != nil {
					errs = append(errs, fmt.Errorf("plan %s/%s: %w", name, comp.Name, err))
					continue
				}
				jobs, verrs := e.validateConfigs(name+"/"+comp.Name, jobs, allowed)
				errs = append(errs, verrs...)
				planned = appendJobs(planned, name, comp.Name, comp.Exposure, comp.Criticality,
					e.resolveRemotes(e.markWorkingTree(jobs)))
			}
		}
	}
	slog.Debug("planned scan jobs", "jobs", len(planned), "controls", len(e.reg.controllers))
	for _, pj := range planned {
		slog.Debug("planned job",
			"control", pj.Control, "scanner", pj.Job.Scanner,
			"target", fmt.Sprintf("%v", pj.Job.Target), "target_kind", pj.Job.Target.Kind())
	}
	return planned, errors.Join(errs...)
}

// validateConfigs drops any job whose Config fails its scanner's declared ConfigSchema, so a
// mistyped or ill-typed Saga option is rejected before scanning rather than silently ignored.
// It returns the surviving jobs and one error per rejected job. Jobs for an unregistered scanner
// pass through (the run reports the missing scanner); scanners without a schema are not checked.
func (e *Engine) validateConfigs(label string, jobs []plugin.ScanJob, allowed map[plugin.EffectKind]bool) ([]plugin.ScanJob, []error) {
	var kept []plugin.ScanJob
	var errs []error
	for _, job := range jobs {
		if scanner, ok := e.reg.Scanner(job.Scanner); ok {
			info := scanner.Info()
			if schema := info.ConfigSchema; len(schema) > 0 {
				if err := plugin.ValidateConfig(schema, job.Config); err != nil {
					errs = append(errs, fmt.Errorf("%s/%s: %w", label, job.Scanner, err))
					continue
				}
			}
			if err := consentFor(info, allowed); err != nil {
				errs = append(errs, fmt.Errorf("%s/%s: %w", label, job.Scanner, err))
				continue
			}
		}
		kept = append(kept, job)
	}
	return kept, errs
}

// consentFor refuses a scanner whose declared effects have not been accepted.
//
// Checked while planning, so a run that is not permitted to do what it would do stops before it
// checks out a repository or reaches a cluster — and the message says what the scanner would
// have done rather than only that it was blocked, because a refusal nobody can act on is its own
// kind of dead end.
func consentFor(info plugin.ScannerInfo, allowed map[plugin.EffectKind]bool) error {
	// Every unaccepted effect, not the first. A scanner may declare several — the kube-bench Job
	// both creates something and runs it privileged — and reporting one at a time makes accepting
	// them a sequence of scans, each ending in a refusal naming an effect the previous run did not
	// mention. The decision is whether to let this scanner do all of it, so it has to be asked once.
	var kinds []string
	var described []string
	for _, effect := range info.Effects {
		if !effect.Kind.RequiresConsent() || allowed[effect.Kind] {
			continue
		}
		kinds = append(kinds, string(effect.Kind))
		described = append(described, fmt.Sprintf("%s (%s)", effect.Kind, effect.Detail))
	}
	if len(kinds) == 0 {
		return nil
	}
	return fmt.Errorf(
		"this scanner has %s that %s not been accepted: %s. Add %s to config.allowEffects in "+
			"your Saga, or pass --allow-effects %s",
		plural2(len(kinds), "an effect", "effects"),
		plural2(len(kinds), "has", "have"),
		strings.Join(described, "; "),
		plural2(len(kinds), "it", "them"),
		strings.Join(kinds, ","))
}

// plural2 picks a word for a count.
func plural2(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// dedupeEffects collapses the same effect reported by several jobs, in a stable order.
func dedupeEffects(all []plugin.Effect) []plugin.Effect {
	if len(all) == 0 {
		return nil
	}
	seen := make(map[plugin.Effect]bool, len(all))
	out := make([]plugin.Effect, 0, len(all))
	for _, e := range all {
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Detail < out[j].Detail
	})
	return out
}

// allowedEffects merges what the descriptor accepts with what this invocation was told to allow.
func allowedEffects(fromSaga, fromFlag []string) map[plugin.EffectKind]bool {
	allowed := make(map[plugin.EffectKind]bool, len(fromSaga)+len(fromFlag))
	for _, list := range [][]string{fromSaga, fromFlag} {
		for _, k := range list {
			if k = strings.ToLower(strings.TrimSpace(k)); k != "" {
				allowed[plugin.EffectKind(k)] = true
			}
		}
	}
	return allowed
}

// Result is the outcome of a run: one aggregated ControlResult per control, plus run
// statistics.
type Result struct {
	Controls map[string]plugin.ControlResult
	Stats    Stats
	// Scope is what the run was narrowed to, empty when it was not narrowed at all.
	//
	// Carried on the result rather than left with the caller because every artifact a result
	// becomes has to be able to say so. A scoped report.json shaped exactly like an unscoped one
	// is a partial answer that anything downstream will read as a complete one.
	Scope Scope
	// Suppressed counts findings a config.exclude rule matched. They are still present in the
	// reports, marked with their justification — this is how many stopped counting.
	Suppressed int
	// LapsedExclusions are exclusions past their expiry date, which no longer suppress anything.
	// Reported so a finding that used to be accepted does not simply reappear with nothing to
	// say why.
	LapsedExclusions []saga.ExcludeRule
	// UnmatchedExclusions are rules that matched no finding in this run. Reported because an
	// exclusion doing nothing is indistinguishable from one that is working: it is usually a
	// typo, a rule id that moved, or a finding someone already fixed and forgot to stop excusing.
	UnmatchedExclusions []saga.ExcludeRule
	// Effects records what this run did to its targets beyond reading them, deduplicated. Only
	// scans that actually executed count: a cache hit means the traffic was not sent this time,
	// and a record of effects has to describe what happened rather than what was configured.
	Effects []plugin.Effect
	// Scanners names every scanner this run used, deduplicated and sorted.
	//
	// Recorded because a report has to be able to say which tools produced its findings — the
	// SARIF driver name is the tool's own and does not identify the scanner Draugr selected, so
	// nothing downstream could work it out. Cache hits count: the key includes the tool version,
	// so a hit describes the same build as the run that stored it.
	Scanners []string
	// SBOMs are the Software Bills of Materials produced when the Saga enables config.sbom.
	// Evidence rather than judgement: they carry no findings and never affect the verdict.
	SBOMs []sbom.Document
	// ScanErrors records, per control, what stopped it completing — a missing scanner binary, a
	// tool that exited badly, a plan that couldn't be built. A control listed here checked less
	// than it was asked to, so its absence of findings is not evidence of absence, and callers
	// that treat an empty report as "clean" would be wrong.
	ScanErrors map[string][]string
}

// Stats summarizes execution, including cache effectiveness.
type Stats struct {
	Jobs      int
	Scans     int
	CacheHits int
	// Deduped counts jobs that reused an identical scan already running/completed in this run
	// (in-run singleflight), rather than scanning or hitting the persistent cache.
	Deduped int
	// Concurrency is the maximum number of scan jobs run in parallel for this run (the
	// effective value after applying WithConcurrency or the NumCPU default).
	Concurrency int
	// Duration is wall-clock for the whole run, and ByControl is how long each control's jobs
	// took summed across them. Reported because "why is this slow" is a question a job count
	// cannot answer: with concurrency the parts do not add up to the whole, and the control
	// worth attention is the slowest one rather than the one with the most jobs.
	Duration  time.Duration
	ByControl map[string]time.Duration
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
	return string(plugin.ComputeCacheKey(job.Scanner, scannerVersion(ctx, scanner), job.Target, job.Config))
}

// scannerVersion resolves the version of what actually ran: a CacheVersioner's answer (Trivy
// folding in its vulnerability-DB version) over the static ScannerInfo.Version.
//
// Only called where a cache key is being built. The probe can cost a subprocess, and a run
// without caching has no reason to pay it — which is why the provenance a report carries uses
// the static version rather than calling this.
func scannerVersion(ctx context.Context, scanner plugin.Scanner) string {
	if cv, ok := scanner.(plugin.CacheVersioner); ok {
		if v := cv.CacheVersion(ctx); v != "" {
			return v
		}
	}
	return scanner.Info().Version
}

// recordProvenance stamps the scanner and its version onto what the scan returned.
//
// Done here rather than in each scanner so a scanner cannot forget: every report says what
// produced it, including scanners written later by someone who never read this comment. A
// scanner that already added an entry for itself keeps its fields and gains the version.
func recordProvenance(report *sarif.Report, tool, version string) {
	for i := range report.Provenance {
		if report.Provenance[i].Tool == tool {
			if report.Provenance[i].Version == "" {
				report.Provenance[i].Version = version
			}
			return
		}
	}
	if version == "" {
		return // nothing to say about a scanner that reports no version
	}
	report.Provenance = append(report.Provenance, sarif.Provenance{Tool: tool, Version: version})
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
		ctlErrs  = make(map[string][]string)
		errs     []error
		stats    = Stats{Jobs: len(planned), Concurrency: e.concurrency, ByControl: map[string]time.Duration{}}
		effects  []plugin.Effect
		runStart = time.Now()
		sem      = make(chan struct{}, e.concurrency)
		sf       = &sfGroup{}
		canceled bool
	)
	if planErr != nil {
		// Runs before any worker goroutine starts; the concurrent appends below are
		// mutex-guarded, so this is not a data race.
		errs = append(errs, planErr) // nosem: trailofbits.go.racy-append-to-slice.racy-append-to-slice
		// Planning failures aren't attributable to one control, but they still mean the run is
		// incomplete, so they need somewhere to be reported from.
		ctlErrs[planningPseudoControl] = append(ctlErrs[planningPseudoControl], planErr.Error()) // nosem: trailofbits.go.racy-append-to-slice.racy-append-to-slice
	}

	// A run with nothing to do is not a clean run.
	//
	// With no control enabled, or none whose surface the components carry, the engine has
	// nothing to execute and every downstream stage behaves exactly as it would for a spotless
	// application: no findings, no failures, PASS. The two are indistinguishable in the output,
	// and the wrong one is far more likely — a descriptor written by hand and never finished, or
	// generated by discovery, which describes a surface without enabling anything to check it.
	//
	// Reported the same way a control that could not run is, because it is the same failure one
	// level up: the gate answered without having looked.
	//
	// A descriptor that only asks for an SBOM is exempt: it enables no control and plans no job,
	// but it does produce the evidence it was asked for, so the run did what the descriptor said.
	if len(planned) == 0 && planErr == nil && !sbomRequested(model) {
		// Runs before any worker goroutine starts; see above.
		ctlErrs[planningPseudoControl] = append(ctlErrs[planningPseudoControl], //nolint:gocritic // same pre-goroutine window as the planErr append
			"no controls ran: no enabled control matches a surface these components declare. "+
				"Enable one under config.controllers, or run `draugr scan <dir>` for the defaults")
	}

	// Warm shared scanner state (e.g. Trivy's vuln DB) once per distinct scanner, before the
	// concurrent fan-out — so parallel scans don't each cold-start it. Best-effort.
	warmed := make(map[string]bool)
	toWarm := planned
	if e.skipPrewarm {
		// Said once, up front, rather than left for each scanner to hint at later. Whatever is
		// on disk is what the run gets; a scanner with nothing on disk says so in its own terms,
		// which is more specific than anything this loop could say for it.
		//
		// A separate slice, because `planned` is the scan itself: emptying it would skip the run
		// rather than the warm-up.
		slog.InfoContext(ctx, "offline: not refreshing scanner data, using what is on disk")
		toWarm = nil
	}
	for _, pj := range toWarm {
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
					// A span event is for someone already reading traces because they suspect
					// this. Anyone else gets whatever the scanner says later about a symptom of
					// it, which is how a template set that never downloaded surfaced as a
					// complaint about the descriptor.
					slog.WarnContext(ctx, "scanner prewarm failed",
						"scanner", name, "error", err.Error())
					runSpan.AddEvent("prewarm failed", trace.WithAttributes(
						attribute.String("scanner", name), attribute.String("error", err.Error())))
				}
			}
		}
	}

	gates := newRateGates()
	for _, pj := range planned {
		if ctx.Err() != nil {
			canceled = true
			break
		}
		wg.Add(1)
		go func(pj PlannedJob) {
			defer wg.Done()

			// A scanner's rate limit is waited out *before* a concurrency slot is taken, and
			// that ordering is the whole design. A hosted API allowing four calls a minute means
			// fifteen seconds of waiting per call; spent holding a worker, four such jobs would
			// idle half a default pool and every other control would queue behind a scanner it
			// has nothing to do with. One scanner's constraint must not become the run's.
			//
			// The cost is a goroutine per planned job rather than per worker. Goroutines blocked
			// on a timer are cheap, and the semaphore below still bounds what actually runs.
			if sc, ok := e.reg.Scanner(pj.Job.Scanner); ok {
				if err := gates.wait(ctx, sc, pj.Job.Scanner, pj.Job.Config); err != nil {
					return // the run was cancelled while waiting
				}
			}

			sem <- struct{}{}
			defer func() { <-sem }()

			jobStart := time.Now()
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
				ctlErrs[pj.Control] = append(ctlErrs[pj.Control], err.Error())
				mu.Unlock()
				return
			}
			span.SetAttributes(attribute.String("target.kind", string(pj.Job.Target.Kind())))

			// Collapse identical concurrent jobs (same scanner+target+config) to a single scan.
			// The version-less identity is cheap (no DB-version probe) and constant within a run.
			ident := string(plugin.ComputeCacheKey(pj.Job.Scanner, "", pj.Job.Target, pj.Job.Config))
			out, shared, scanErr := sf.do(ident, func() (any, error) {
				// The cache key (and any tool/DB version probe) is built only when caching is on.
				// version is what provenance reports. Caching resolves the live one anyway —
				// Trivy's includes its vulnerability-DB version — so reuse it rather than
				// probing twice, and fall back to the static one when nothing resolved it.
				var key string
				version := scanner.Info().Version
				// A vetoed target is scanned as though caching were off: no lookup, no store.
				// Checked once here so the two cannot disagree about whether this job caches.
				caches := e.cache != nil && (e.cacheable == nil || e.cacheable(pj.Job.Target))
				if caches {
					if v := scannerVersion(jobCtx, scanner); v != "" {
						version = v
					}
					key = string(plugin.ComputeCacheKey(pj.Job.Scanner, version, pj.Job.Target, pj.Job.Config))
					if pj.Job.CacheKey != "" {
						key = string(pj.Job.CacheKey)
					}
					if rep, hit := e.cache.Get(key); hit {
						slog.DebugContext(jobCtx, "cache hit",
							"control", pj.Control, "scanner", pj.Job.Scanner, "key", key)
						cacheHitCounter.Add(jobCtx, 1, metric.WithAttributes(attribute.String("control", pj.Control)))
						return scanOutcome{report: rep, cached: true}, nil
					}
				}
				slog.DebugContext(jobCtx, "scanning",
					"control", pj.Control, "scanner", pj.Job.Scanner,
					"target_kind", pj.Job.Target.Kind())
				start := time.Now()
				rep, err := scanner.Scan(jobCtx, pj.Job.Target, pj.Job.Config)
				scanDuration.Record(jobCtx, time.Since(start).Seconds(),
					metric.WithAttributes(attribute.String("scanner", pj.Job.Scanner)))
				if err != nil {
					return scanOutcome{}, err
				}
				// Before caching, so a cache hit carries the same account a fresh scan does.
				recordProvenance(&rep, pj.Job.Scanner, version)
				if caches {
					_ = e.cache.Put(key, rep) // cache the raw findings; priority is stamped per run
				}
				slog.DebugContext(jobCtx, "scan complete",
					"control", pj.Control, "scanner", pj.Job.Scanner,
					"findings", len(rep.Results),
					"duration", time.Since(start).Round(time.Millisecond).String())
				scanCounter.Add(jobCtx, 1, metric.WithAttributes(attribute.String("scanner", pj.Job.Scanner)))
				return scanOutcome{report: rep}, nil
			})
			if scanErr != nil {
				span.RecordError(scanErr)
				span.SetStatus(codes.Error, "scan failed")
				if !shared { // record the underlying error once, not once per collapsed job
					mu.Lock()
					errs = append(errs, fmt.Errorf("scan %s/%s: %w", pj.Control, pj.Job.Scanner, scanErr))
					// No scanner prefix: the scanner already names itself when it wraps the
					// failure ("run nuclei: …"), and adding it again reads as a stutter in
					// the one line a reader scans to find out what broke.
					ctlErrs[pj.Control] = append(ctlErrs[pj.Control], scanErr.Error())
					mu.Unlock()
				}
				return
			}
			res := out.(scanOutcome)
			span.SetAttributes(attribute.Bool("cache.hit", res.cached), attribute.Bool("dedup", shared))
			jobTook := time.Since(jobStart)
			recordFindings(jobCtx, pj.Control, res.report)
			report := e.stampJobFields(res.report, pj)
			mu.Lock()
			stats.ByControl[pj.Control] += jobTook
			if !res.cached {
				effects = append(effects, scanner.Info().Effects...)
			}
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

	// Evidence, after the controls: an SBOM describes what a component contains rather than
	// judging it, so it never reaches the verdict. A failure is still recorded, because
	// "you asked for an inventory and did not get one" must not pass quietly.
	docs, sbomErrs := e.generateSBOMs(ctx, model)
	if len(sbomErrs) > 0 {
		ctlErrs[sbomPseudoControl] = append(ctlErrs[sbomPseudoControl], sbomErrs...)
	}

	stats.Duration = time.Since(runStart)
	res := Result{
		Controls: make(map[string]plugin.ControlResult),
		Stats:    stats,
		Scope:    e.scope,
		Effects:  dedupeEffects(effects),
		Scanners: distinctScanners(planned),
		SBOMs:    docs,
	}
	if len(ctlErrs) > 0 {
		res.ScanErrors = ctlErrs
	}
	for _, control := range sortedReportKeys(byCtl) {
		ctrl, ok := e.reg.Controller(control)
		if !ok {
			continue
		}
		slog.Debug("aggregating control", "control", control, "reports", len(byCtl[control]))
		slog.Debug("aggregating control", "control", control, "reports", len(byCtl[control]))
		cr, err := ctrl.Aggregate(byCtl[control])
		if err != nil {
			errs = append(errs, fmt.Errorf("aggregate %s: %w", control, err))
			ctlErrs[control] = append(ctlErrs[control], "aggregate: "+err.Error())
			continue
		}
		res.Controls[control] = cr
	}

	// Exclusions apply after aggregation, to what every consumer will see. Doing it here rather
	// than per scanner means one syntax covers every tool, including ones added later — and it
	// is what makes suppress-rather-than-delete possible at all: a finding a scanner never
	// produced cannot be marked.
	res.Suppressed, res.LapsedExclusions, res.UnmatchedExclusions =
		applyExclusions(res.Controls, model.Config.Exclude, time.Now())
	return res, errors.Join(errs...)
}

// resolveRemotes names each local checkout by the repository it came from.
//
// Here rather than in each controller for the reason markWorkingTree is: every controller builds
// its own RepositoryTarget, so doing it at the source would be a change in each one and a
// silently missing resolution in whichever is written next.
//
// It changes the target's identity, and therefore its cache key — deliberately. A laptop scanning
// `.` and a pipeline scanning the remote are the same repository at the same revision, and until
// now they were two unrelated sources that could not share a cache entry or be diffed against
// each other.
func (e *Engine) resolveRemotes(jobs []plugin.ScanJob) []plugin.ScanJob {
	if e.resolveRemote == nil {
		return jobs
	}
	resolved := map[string]string{}
	for i, j := range jobs {
		r, ok := j.Target.(plugin.RepositoryTarget)
		if !ok || r.URL == "" {
			continue
		}
		url, seen := resolved[r.URL]
		if !seen {
			// The resolver answers "" for anything that is not a local checkout with a remote,
			// so the engine needs no notion of what a path or a remote looks like.
			url = e.resolveRemote(r.URL)
			resolved[r.URL] = url
		}
		if url == "" {
			continue // no remote: the path is the only name this repository has
		}
		r.Remote = url
		jobs[i].Target = r
		// The controller computed the cache key from the target it planned, so it has to be
		// recomputed against the one that will actually be scanned.
		if jobs[i].CacheKey != "" {
			jobs[i].CacheKey = plugin.ComputeCacheKey(j.Scanner, "", r, j.Config)
		}
	}
	return jobs
}

// markWorkingTree flags every repository target so the scanner reads the checkout on disk.
//
// Applied here rather than where each controller builds its targets: every controller constructs
// its own RepositoryTarget, so setting the flag at the source would be a change in each one and a
// silently missing flag in whichever is written next. Every planned job funnels through here.
//
// The cache key changes with the flag (RepositoryTarget.Identity), so a working-tree scan and a
// committed one cannot be confused for each other.
func (e *Engine) markWorkingTree(jobs []plugin.ScanJob) []plugin.ScanJob {
	if !e.workingTree {
		return jobs
	}
	for i, j := range jobs {
		r, ok := j.Target.(plugin.RepositoryTarget)
		if !ok {
			continue
		}
		r.WorkingTree = true
		jobs[i].Target = r
		// The cache key is computed by the controller from the target it planned, so it has to be
		// recomputed against the one that will actually be scanned.
		if jobs[i].CacheKey != "" {
			jobs[i].CacheKey += "+worktree"
		}
	}
	return jobs
}

func appendJobs(dst []PlannedJob, control, component string, exposure saga.Exposure, criticality saga.Criticality, jobs []plugin.ScanJob) []PlannedJob {
	for _, j := range jobs {
		dst = append(dst, PlannedJob{
			Control: control, Job: j, Component: component,
			Exposure: exposure, Criticality: criticality,
		})
	}
	return dst
}

// stampJobFields returns a copy of report with the per-run facts about the job that produced it:
// which component it belongs to, and the priority band its classification earns.
//
// Both are per-run rather than cached, and for the same reason — two jobs can share a cache key
// while belonging to different components with different classifications, so the cached findings
// must never be mutated. The slice is copied for that.
func (e *Engine) stampJobFields(report sarif.Report, pj PlannedJob) sarif.Report {
	if len(report.Results) == 0 {
		return report
	}
	out := report
	out.Results = make([]sarif.Result, len(report.Results))
	copy(out.Results, report.Results)
	for i := range out.Results {
		out.Results[i].Component = pj.Component
		if e.prioritize != nil {
			p := e.prioritize(pj.Control, pj.Exposure, pj.Criticality, out.Results[i])
			out.Results[i].Priority = p.Band
			out.Results[i].Escalation = p.Escalation
			out.Results[i].PriorityFloor = p.Floor
		}
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

// sbomRequested reports whether the descriptor asks for SBOM evidence.
func sbomRequested(model saga.Model) bool {
	return model.Config.SBOM != nil && model.Config.SBOM.Enabled
}

// planningPseudoControl is where a planning failure is reported, since it belongs to the run
// rather than to any one control.
const planningPseudoControl = "(planning)"

// Waivable reports whether a failure under this control name is one --allow-scan-errors can
// accept.
//
// The flag means "a scanner could not run and I accept a partial result" — the reader has other
// controls that did run and is choosing to proceed on those. A planning failure is not a
// scanner: it is the run saying there was nothing to do at all, so there is no partial result to
// accept. Treating the two alike turns the flag into "pass anyway", and a PASS that means "we
// did not look" is the worst thing this tool can print.
//
// (sbom) stays waivable on purpose. A missing SBOM is missing evidence, not a missing check —
// the controls still ran and their verdict still means something.
func Waivable(control string) bool { return control != planningPseudoControl }

// applyExclusions marks findings matched by a Saga exclusion and returns how many. The finding
// stays in the report carrying its justification, so an exclusion is auditable rather than a
// hole; Counts skips suppressed results, so the summary and the verdict simply stop seeing it.
//
// Summaries are recomputed afterwards because a controller built them from the unsuppressed
// report during Aggregate.
func applyExclusions(controls map[string]plugin.ControlResult, rules []saga.ExcludeRule, now time.Time) (suppressed int, lapsed, unmatched []saga.ExcludeRule) {
	if len(rules) == 0 {
		return 0, nil, nil
	}
	// An expired exclusion stops suppressing, and is reported as having lapsed. Dropping it
	// silently would produce a finding that used to be accepted with nothing to say why it came
	// back; keeping it would let "until the upstream fix lands" mean forever, which is how a
	// suppression mechanism decays into a way of never seeing something again.
	active := make([]saga.ExcludeRule, 0, len(rules))
	for _, r := range rules {
		if r.ExpiredOn(now) {
			lapsed = append(lapsed, r)
			continue
		}
		active = append(active, r)
	}
	rules = active

	// An exclusion that matches nothing is doing nothing, and looks identical to one that is
	// working. That is worth saying on its own — a rule kept after the finding it excused was
	// fixed is stale, and a rule that never matched is usually a typo or an id that moved.
	matched := make([]bool, len(rules))

	total := 0
	for name, cr := range controls {
		n := 0
		for i := range cr.Report.Results {
			res := &cr.Report.Results[i]
			if res.Suppressed() {
				continue // already suppressed upstream; leave the original reason intact
			}
			for ri, rule := range rules {
				if rule.Matches(res.Location.URI, res.RuleID) {
					matched[ri] = true
					res.Suppression = &sarif.Suppression{
						Kind: "external", Justification: rule.Reason,
						AcceptedBy: rule.AcceptedBy, Expires: rule.Expires,
						Source: rule.Source,
					}
					if rule.VEX != nil {
						res.Suppression.VEXStatus = rule.VEX.Status
						res.Suppression.VEXJustification = rule.VEX.Justification
					}
					n++
					break
				}
			}
		}
		if n > 0 {
			counts := cr.Report.Counts()
			cr.Summary = plugin.Summary{Errors: counts.Error, Warnings: counts.Warning, Notes: counts.Note}
			controls[name] = cr
			total += n
		}
	}
	for i, ok := range matched {
		if !ok {
			unmatched = append(unmatched, rules[i])
		}
	}
	return total, lapsed, unmatched
}

// sbomPseudoControl is where SBOM generation failures are reported. SBOMs are evidence, not a
// control, but a failure still has to land somewhere a caller will look — and it makes the run
// incomplete for the same reason a missing scanner does: you asked for something, and silence
// would let you believe you got it.
const sbomPseudoControl = "(sbom)"

// generateSBOMs takes one inventory per distinct repository and image in the model.
//
// Deduplicated by target identity: several controls scan the same repository, and an SBOM of it
// is the same document however many controls touched it. Ordered by component then target so a
// run is reproducible and two runs diff cleanly.
func (e *Engine) generateSBOMs(ctx context.Context, model saga.Model) ([]sbom.Document, []string) {
	cfg := model.Config.SBOM
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}
	if e.sbomGen == nil {
		return nil, []string{"sbom generation is enabled but no generator is configured"}
	}

	ctx, span := tracer.Start(ctx, "engine.sbom")
	defer span.End()

	var docs []sbom.Document
	var errs []string
	seen := make(map[string]bool)

	for i := range model.Components {
		comp := &model.Components[i]
		var targets []plugin.Target
		for _, r := range comp.Repositories {
			targets = append(targets, plugin.RepositoryTarget{
				URL: r.URL, Revision: r.Revision, WorkingTree: e.workingTree,
			})
		}
		for _, img := range comp.Images {
			targets = append(targets, plugin.ImageTarget{Ref: img.Image, Digest: img.Digest})
		}
		for _, t := range targets {
			if ctx.Err() != nil {
				errs = append(errs, ctx.Err().Error())
				return docs, errs
			}
			if seen[t.Identity()] {
				continue
			}
			seen[t.Identity()] = true
			doc, err := e.sbomGen.Generate(ctx, comp.Name, t, cfg.Format)
			if err != nil {
				errs = append(errs, err.Error())
				continue
			}
			docs = append(docs, doc)
		}
	}

	scope := cfg.Scope
	if scope == "" {
		scope = saga.SBOMScopeComponent
	}
	if scope.Project() {
		docs, errs = appendProjectSBOM(e.sbomGen, model.Release, cfg.Format, scope, docs, errs)
	}
	slog.DebugContext(ctx, "generated SBOMs", "documents", len(docs), "errors", len(errs))
	return docs, errs
}

// appendProjectSBOM assembles the per-target documents into one covering the release, and — for
// scope: project — drops the parts it was built from.
//
// A generator that cannot assemble produces an error rather than the per-target documents it can
// manage. The descriptor asked for a document covering the product; quietly delivering seven
// documents covering repositories would be a green run that answered a different question.
func appendProjectSBOM(gen sbom.Generator, release saga.Release, format saga.SBOMFormat,
	scope saga.SBOMScope, docs []sbom.Document, errs []string,
) ([]sbom.Document, []string) {
	asm, ok := gen.(sbom.Assembler)
	if !ok {
		return docs, append(errs, "config.sbom.scope asks for a project document, "+
			"but the configured SBOM generator cannot assemble one")
	}
	project, err := asm.Assemble(release, format, docs)
	if err != nil {
		return docs, append(errs, err.Error())
	}
	if scope == saga.SBOMScopeProject {
		// The parts were generated because assembling needs them; the descriptor asked only for
		// the whole. scope: both is how you keep the evidence alongside the summary.
		return []sbom.Document{project}, errs
	}
	return append(docs, project), errs
}

// distinctScanners names the scanners a run used, sorted.
//
// From the planned jobs rather than from the findings: a scanner that ran and found nothing still
// produced this report's silence, and a reader asking which tools it was deserves the same answer
// either way.
func distinctScanners(planned []PlannedJob) []string {
	seen := map[string]bool{}
	var out []string
	for _, pj := range planned {
		if pj.Job.Scanner == "" || seen[pj.Job.Scanner] {
			continue
		}
		seen[pj.Job.Scanner] = true
		out = append(out, pj.Job.Scanner)
	}
	sort.Strings(out)
	return out
}
