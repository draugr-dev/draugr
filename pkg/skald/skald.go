// Package skald renders scan results and verdicts into evidence: a JSON summary and
// merged SARIF. A skald is the poet who records deeds — here, the record of a scan.
package skald

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/pkg/ci"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/prioritization"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// jsonReport is the JSON evidence document.
type jsonReport struct {
	// Project is what a platform files this run under. First, because it is the identity of the
	// thing the rest of the document is about.
	Project string      `json:"project,omitempty"`
	Release releaseInfo `json:"release"`
	Verdict string      `json:"verdict"`
	// Scope is what the run was narrowed to, absent when it was not narrowed at all.
	//
	// First, beside the verdict, because it qualifies it. A consumer reading this document has
	// to be able to tell a verdict about the release from a verdict about part of it, and the
	// rest of the document looks the same either way.
	Scope    *scopeInfo      `json:"scope,omitempty"`
	Controls []controlReport `json:"controls"`
	// NotMeasured names a scanner that was planned and then not run because it could not answer
	// the question its target asked. Distinct from an error: nothing went wrong, and the run is
	// not incomplete — but a scanner that quietly did not run is indistinguishable, in the rest
	// of this document, from one that ran and found nothing.
	NotMeasured []notMeasuredReport `json:"notMeasured,omitempty"`
	Priorities  *priorityCounts     `json:"priorities,omitempty"`
	// Exploitability names the datasets that enriched this run's severities, so a report can
	// be checked against the data it was computed from. Absent when no enrichment ran.
	Exploitability []FeedProvenance `json:"exploitability,omitempty"`
	// Reachability summarizes what reachability analysis concluded, so a consumer can see the
	// analysis ran and how much of it landed. Absent when none ran.
	Reachability *reachabilityInfo `json:"reachability,omitempty"`
	// Repositories is which repository was read and at which commit — what makes the report
	// reproducible, and the answer to "does this describe my change or last week's".
	Repositories []sarif.RepositoryRef `json:"repositories,omitempty"`
	// Descriptor is the Saga that turned a repository into this set of checks.
	//
	// Without it the report says what was found and never what was asked for, so "why did this
	// run cover sca and not images" has no answer from the artifact — and an exclusion that
	// suppressed a finding came from a file nobody can name.
	Descriptor *DescriptorRef `json:"descriptor,omitempty"`
	// CI is the job this scan ran in. Absent outside CI, and absent rather than guessed on a
	// platform Draugr does not recognize.
	CI       *ci.Context     `json:"ci,omitempty"`
	Findings []findingReport `json:"findings,omitempty"`
	Stats    statsInfo       `json:"stats"`
}

// sortedControls names the controls in a scan-error map, in a stable order.
func sortedControls(errs map[string][]string) []string {
	out := make([]string, 0, len(errs))
	for name := range errs {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// scopeInfo mirrors engine.Scope in the report document.
type scopeInfo struct {
	Components        []string `json:"components,omitempty"`
	Controls          []string `json:"controls,omitempty"`
	SkippedComponents []string `json:"skippedComponents,omitempty"`
}

// priorityCounts tallies findings by priority band (present when prioritization ran).
type priorityCounts struct {
	P1 int `json:"p1"`
	P2 int `json:"p2"`
	P3 int `json:"p3"`
	P4 int `json:"p4"`
}

// findingReport is one ranked finding, emitted when a minimum priority filter is set.
type findingReport struct {
	Priority string  `json:"priority,omitempty"`
	Level    string  `json:"level"`
	Score    float64 `json:"score,omitempty"`
	Control  string  `json:"control"`
	Tool     string  `json:"tool,omitempty"`
	RuleID   string  `json:"ruleId,omitempty"`
	Message  string  `json:"message,omitempty"`
	Location string  `json:"location,omitempty"`
	// Escalation says why this finding's severity was raised, when exploitability data raised
	// it. A consumer acting on the priority can then say what the priority rests on.
	Escalation *sarif.Escalation `json:"escalation,omitempty"`
	// Reachability says whether this project's code can reach the vulnerable code, and carries
	// the call path when it can. Same reason as Escalation, in the other direction: a consumer
	// acting on a band that reachability lowered can say what lowered it.
	Reachability *sarif.Reachability `json:"reachability,omitempty"`
}

// Provenance is what produced a run, as opposed to what it found.
//
// Grouped rather than added as two more parameters: these travel together, they are both absent
// together in the common local case, and the renderer's signature is already long enough that a
// caller passing them in the wrong order would compile.
type Provenance struct {
	Descriptor *DescriptorRef
	CI         *ci.Context
}

// DescriptorRef identifies the descriptor a run was produced from.
//
// Both halves are needed and neither substitutes for the other: Digest says whether two runs were
// asked the same question, and Sources says which files that question was assembled from.
type DescriptorRef struct {
	// Digest is over the merged, environment-substituted descriptor, serialized canonically.
	//
	// No file on disk has this content. A digest over the root file alone would call two runs
	// identical when a fragment between them changed, and different when a comment moved.
	Digest string `json:"digest,omitempty"`
	// Sources are the files it was assembled from, root first.
	Sources []DescriptorSource `json:"sources,omitempty"`
	// Effective is the merged, environment-substituted descriptor as YAML — the same bytes Digest
	// is taken over.
	//
	// Sent because a digest is worth nothing to somebody who cannot reproduce it, and because the
	// question a reader actually has is "what did this run apply", which no list of filenames
	// answers. It holds less than the report beside it: the findings, their locations and every
	// suppression's reason and accepter are already in that, and a descriptor never carries a
	// credential — the schema has no field for one, only for the name of a variable.
	//
	// A few kilobytes against a report that is already larger.
	Effective string `json:"effective,omitempty"`
}

// DescriptorSource is one file a descriptor was assembled from.
type DescriptorSource struct {
	// Path is the file as the descriptor that named it wrote it.
	Path string `json:"path,omitempty"`
	// URL, Revision and Resolved locate a fragment fetched from another repository. Revision is
	// what was asked for and Resolved is the commit that turned out to be — a branch moves, so
	// only the second makes the run reproducible.
	URL      string `json:"url,omitempty"`
	Revision string `json:"revision,omitempty"`
	Resolved string `json:"resolved,omitempty"`
	// Digest is over the file as committed, before ${{ VAR }} substitution: it answers "is this
	// the same file somebody reviewed", which is a question about the text, not the run.
	Digest string `json:"digest,omitempty"`
	// Root marks the descriptor the resolution started from.
	Root bool `json:"root,omitempty"`
}

// DescriptorFrom renders a resolution as the report's descriptor block, or nil when there was
// none — a scan driven entirely from flags has no descriptor to record, and an empty block would
// claim otherwise.
func DescriptorFrom(res *saga.Resolved) *DescriptorRef {
	if res == nil || len(res.Sources) == 0 {
		return nil
	}
	out := &DescriptorRef{
		Digest:    res.Digest(),
		Effective: res.Effective(),
		Sources:   make([]DescriptorSource, 0, len(res.Sources)),
	}
	for _, s := range res.Sources {
		out.Sources = append(out.Sources, DescriptorSource{
			Path: s.Path, URL: s.URL, Revision: s.Revision, Resolved: s.Resolved,
			Digest: s.Digest, Root: s.Root,
		})
	}
	return out
}

// FeedProvenance is one exploitability dataset as a run saw it: where it came from, when, and
// whether it was already older than the run allowed for.
type FeedProvenance struct {
	Name      string     `json:"name"`
	URL       string     `json:"url,omitempty"`
	FetchedAt *time.Time `json:"fetchedAt,omitempty"`
	SHA256    string     `json:"sha256,omitempty"`
	Stale     bool       `json:"stale,omitempty"`
}

type releaseInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type controlReport struct {
	Name            string `json:"name"`
	Verdict         string `json:"verdict"`
	Highest         string `json:"highest"`
	HighestPriority string `json:"highestPriority,omitempty"`
	Threshold       string `json:"threshold"`
	Errors          int    `json:"errors"`
	Warnings        int    `json:"warnings"`
	Notes           int    `json:"notes"`
	Total           int    `json:"total"`
	// ScanErrors are what stopped this control finishing, in the scanner's own words.
	//
	// Present is the whole signal; there is no separate flag saying so. A run that failed because
	// a scanner never started and one that failed on what it found are the same `fail` above, and
	// they call for different things — the first is a broken pipeline, the second is work. When
	// this is set the counts describe what the scanners that did run found, which is not the same
	// as what is there.
	ScanErrors []string `json:"scanErrors,omitempty"`
}

// notMeasuredReport is a job that was planned and then not run.
type notMeasuredReport struct {
	Control   string `json:"control"`
	Scanner   string `json:"scanner"`
	Component string `json:"component,omitempty"`
	Reason    string `json:"reason"`
}

type statsInfo struct {
	Jobs      int `json:"jobs"`
	Scans     int `json:"scans"`
	CacheHits int `json:"cacheHits"`
	// UnpinnedCacheHits names images whose findings were reused from a cache entry keyed on a
	// tag rather than a digest, so they may describe an earlier image. Omitted when empty, and
	// present here because a machine reading this report needs the same caveat a person gets.
	UnpinnedCacheHits []string `json:"unpinnedCacheHits,omitempty"`
	Deduped           int      `json:"deduped"`
	Concurrency       int      `json:"concurrency"`

	// DurationMs is wall-clock for the run, ByControlMs is each control's job time summed
	// across its jobs, and ToolWaitsMs is time spent queueing for a tool's own cache instead of
	// scanning. Milliseconds, named in the key: a bare number of unstated units is a figure a
	// consumer has to guess at, and the guess is silent when it is wrong.
	//
	// Here rather than on each control row because "why did this take so long" is one question,
	// and answering it from three places means correlating them first. The console and the HTML
	// report have shown these since the engine started recording them; this document is what CI
	// keeps, which makes it the copy anyone still has when they come to ask.
	//
	// Wall-clock and the per-control sum are different numbers and neither substitutes: jobs run
	// concurrently, so the parts add up to more than the whole. The sum is what identifies the
	// control worth looking at; the wall-clock is what the person waited.
	//
	// Omitted rather than zero when the engine did not record them. Zero milliseconds is a claim
	// that a run took no time, which is never true — unlike `cacheHits: 0`, where zero is a
	// measurement and belongs in the document.
	DurationMs  int64            `json:"durationMs,omitempty"`
	ByControlMs map[string]int64 `json:"byControlMs,omitempty"`
	ToolWaitsMs map[string]int64 `json:"toolWaitsMs,omitempty"`
}

// millis converts a duration for the report, rounding rather than truncating.
//
// Rounding because truncation reports anything under a millisecond as 0, and a 0 inside a map
// whose presence means "measured" reads as "took no time" rather than "too fast to matter".
func millis(d time.Duration) int64 {
	if d <= 0 {
		return 0
	}
	return int64(d.Round(time.Millisecond) / time.Millisecond)
}

// millisBy converts a per-key duration map, dropping nothing: a control that ran is a control
// with a time, and omitting the fast ones would make the map read as a partial list.
func millisBy(in map[string]time.Duration) map[string]int64 {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]int64, len(in))
	for k, d := range in {
		out[k] = millis(d)
	}
	return out
}

// RenderJSON writes a JSON evidence summary combining the run result and the verdict.
// Controls are emitted in name order for stable output. When minPriority is non-empty (e.g.
// "P2"), a ranked `findings` list of findings at or above that band is included; priority
// counts are always included when the run was prioritized.
func RenderJSON(w io.Writer, release saga.Release, run engine.Result, verdict norn.Result, minPriority string) error {
	return RenderJSONWith(w, release, run, verdict, minPriority, sarif.MarshalOptions{})
}

// RenderJSONWith is RenderJSON with marshaling options; Compact drops the indentation.
func RenderJSONWith(w io.Writer, release saga.Release, run engine.Result, verdict norn.Result, minPriority string, opts sarif.MarshalOptions) error {
	return RenderJSONWithFeeds(w, release, run, verdict, minPriority, nil, opts)
}

// RenderJSONWithFeeds is RenderJSONWith plus the exploitability datasets the run used.
//
// Deprecated: use RenderJSONFor, which carries the project. This one emits a document with no
// project in it, which a platform files under nothing.
func RenderJSONWithFeeds(w io.Writer, release saga.Release, run engine.Result, verdict norn.Result, minPriority string, feeds []FeedProvenance, opts sarif.MarshalOptions) error {
	return RenderJSONFor(w, "", release, run, verdict, minPriority, feeds, opts, Provenance{})
}

// RenderJSONFor is RenderJSONWithFeeds with the project the run belongs to.
//
// A separate function rather than another parameter on the three above: release.name is being
// removed, and those signatures go with it. Changing them twice — once to add the project and
// again to drop the release name — is two breaks for one decision.
func RenderJSONFor(w io.Writer, project string, release saga.Release, run engine.Result, verdict norn.Result, minPriority string, feeds []FeedProvenance, opts sarif.MarshalOptions, prov Provenance) error {
	doc := jsonReport{
		Descriptor: prov.Descriptor,
		CI:         prov.CI,
		Project:    project,
		Release:    releaseInfo{Name: release.Name, Version: release.Version},
		Verdict:    string(verdict.Verdict),
		Scope:      scopeOf(run),
		Stats: statsInfo{
			Jobs:              run.Stats.Jobs,
			Scans:             run.Stats.Scans,
			CacheHits:         run.Stats.CacheHits,
			UnpinnedCacheHits: run.Stats.UnpinnedCacheHits,
			Deduped:           run.Stats.Deduped,
			Concurrency:       run.Stats.Concurrency,
			DurationMs:        millis(run.Stats.Duration),
			ByControlMs:       millisBy(run.Stats.ByControl),
			ToolWaitsMs:       millisBy(run.Stats.ToolWaits),
		},
	}
	seen := make(map[string]bool, len(verdict.Controls))
	for _, oc := range verdict.Controls {
		seen[oc.Control] = true
		doc.Controls = append(doc.Controls, controlReport{
			Name:            oc.Control,
			Verdict:         string(oc.Verdict),
			Highest:         string(oc.Highest),
			HighestPriority: oc.HighestPriority,
			Threshold:       string(oc.Threshold),
			Errors:          oc.Counts.Error,
			Warnings:        oc.Counts.Warning,
			Notes:           oc.Counts.Note,
			Total:           oc.Counts.Total(),
			ScanErrors:      run.ScanErrors[oc.Control],
		})
	}
	// A control that produced nothing at all has no outcome to attach to, so listing only the
	// outcomes drops it entirely — and a consumer counting controls sees a shorter list rather
	// than a failure. That is the whole complaint this document exists to answer, so it is
	// listed with the counts it truly has: none.
	for _, name := range sortedControls(run.ScanErrors) {
		if seen[name] {
			continue
		}
		doc.Controls = append(doc.Controls, controlReport{
			Name:       name,
			Verdict:    string(norn.Fail),
			Highest:    string(sarif.LevelNone),
			ScanErrors: run.ScanErrors[name],
		})
	}
	sort.Slice(doc.Controls, func(i, j int) bool { return doc.Controls[i].Name < doc.Controls[j].Name })

	for _, sk := range run.Skipped {
		doc.NotMeasured = append(doc.NotMeasured, notMeasuredReport{
			Control: sk.Control, Scanner: sk.Scanner, Component: sk.Component, Reason: sk.Reason,
		})
	}

	doc.Priorities, doc.Findings = summarizePriorities(run, minPriority)
	doc.Exploitability = feeds
	doc.Reachability = reachabilityOf(run)

	reports := make([]sarif.Report, 0, len(run.Controls))
	for _, cr := range run.Controls {
		reports = append(reports, cr.Report)
	}
	doc.Repositories = sarif.RepositoriesIn(reports)
	sort.Slice(doc.Repositories, func(i, j int) bool {
		if doc.Repositories[i].URL != doc.Repositories[j].URL {
			return doc.Repositories[i].URL < doc.Repositories[j].URL
		}
		return doc.Repositories[i].Revision < doc.Repositories[j].Revision
	})

	enc := json.NewEncoder(w)
	if !opts.Compact {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(doc)
}

// summarizePriorities tallies findings by priority band and, when minPriority is set, builds
// a ranked list of findings at or above it. Returns nil counts when the run was not
// prioritized (no finding carries a priority).
func summarizePriorities(run engine.Result, minPriority string) (*priorityCounts, []findingReport) {
	var counts priorityCounts
	var findings []findingReport
	prioritized := false
	minRank := prioritization.Priority(minPriority).Rank()

	for _, name := range sortedControlNames(run) {
		for _, res := range run.Controls[name].Report.Results {
			if res.Priority == "" {
				continue
			}
			prioritized = true
			switch prioritization.Priority(res.Priority) {
			case prioritization.P1:
				counts.P1++
			case prioritization.P2:
				counts.P2++
			case prioritization.P3:
				counts.P3++
			case prioritization.P4:
				counts.P4++
			}
			if minRank > 0 && prioritization.Priority(res.Priority).Rank() >= minRank {
				findings = append(findings, toFinding(name, res))
			}
		}
	}
	if !prioritized {
		return nil, nil
	}
	sortFindings(findings)
	return &counts, findings
}

func toFinding(control string, res sarif.Result) findingReport {
	loc := res.Location.URI
	if loc != "" && res.Location.StartLine > 0 {
		loc = fmt.Sprintf("%s:%d", loc, res.Location.StartLine)
	}
	return findingReport{
		Priority:     res.Priority,
		Level:        string(res.Level),
		Score:        res.Score,
		Control:      control,
		Tool:         res.Tool,
		RuleID:       res.RuleID,
		Message:      res.Message,
		Location:     loc,
		Escalation:   res.Escalation,
		Reachability: res.Reachability,
	}
}

// sortFindings orders most-urgent first: by priority, then numeric score, then SARIF level,
// then rule id for stability.
func sortFindings(fs []findingReport) {
	sort.Slice(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if ra, rb := prioritization.Priority(a.Priority).Rank(), prioritization.Priority(b.Priority).Rank(); ra != rb {
			return ra > rb
		}
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		if la, lb := sarif.Level(a.Level).Rank(), sarif.Level(b.Level).Rank(); la != lb {
			return la > lb
		}
		return a.RuleID < b.RuleID
	})
}

func sortedControlNames(run engine.Result) []string {
	names := make([]string, 0, len(run.Controls))
	for name := range run.Controls {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// MergedSARIF combines all controls' reports into one SARIF report.
func MergedSARIF(run engine.Result) sarif.Report {
	names := sortedControlNames(run)
	reports := make([]sarif.Report, 0, len(names))
	for _, name := range names {
		rep := run.Controls[name].Report
		// Stamped here because this is the last place the control is known. A run holds reports
		// keyed by control and the merged document holds none, so a finding that does not carry
		// its own control arrives downstream unable to say which check made it.
		stamped := make([]sarif.Result, len(rep.Results))
		copy(stamped, rep.Results)
		for i := range stamped {
			if stamped[i].Control == "" {
				stamped[i].Control = name
			}
		}
		rep.Results = stamped
		reports = append(reports, rep)
	}
	merged := sarif.Merge(reports...)
	// A scoped run stamps what it covered. SARIF carries the results and nothing about what was
	// not looked at, so without this a scan of one component and a scan of twelve are
	// indistinguishable to any consumer that reloads the file — and the one that matters,
	// `draugr diff`, would read every unscanned finding as fixed.
	if prov, ok := ScopeProvenance(run.Scope); ok {
		merged.Provenance = append(merged.Provenance, prov)
	}
	return merged
}

// ScopeProvenanceTool is the provenance entry a scoped run stamps on its SARIF.
const ScopeProvenanceTool = "draugr/scope"

// ScopeProvenance renders a scope as a SARIF provenance entry, and reports whether there was one
// to render.
//
// Provenance is the right carrier and already says so: it is what a run states about itself
// rather than about what it found, and it survives a round trip through the file.
func ScopeProvenance(scope engine.Scope) (sarif.Provenance, bool) {
	if scope.Empty() {
		return sarif.Provenance{}, false
	}
	p := sarif.Provenance{Tool: ScopeProvenanceTool}
	if len(scope.Components) > 0 {
		p.Fields = append(p.Fields, sarif.Field{Key: "components", Value: strings.Join(scope.Components, ",")})
	}
	if len(scope.Controls) > 0 {
		p.Fields = append(p.Fields, sarif.Field{Key: "controls", Value: strings.Join(scope.Controls, ",")})
	}
	return p, true
}

// MinPriorityProvenanceTool is the provenance entry a priority-narrowed report stamps on its
// SARIF.
const MinPriorityProvenanceTool = "draugr/min-priority"

// MinPriorityProvenance renders a declared priority band as a SARIF provenance entry, and reports
// whether there was one to render.
//
// The same carrier and the same reason as a scope: a run states what it left out, not only what it
// found. And the same hazard if it does not — a narrowed file and a complete one are
// indistinguishable to anything that reloads them, so `draugr diff` would read every finding below
// the band as fixed.
func MinPriorityProvenance(band string) (sarif.Provenance, bool) {
	if band == "" {
		return sarif.Provenance{}, false
	}
	return sarif.Provenance{
		Tool:   MinPriorityProvenanceTool,
		Fields: []sarif.Field{{Key: "band", Value: band}},
	}, true
}

// MinPriorityOfReport reports the band a loaded report was narrowed to, and whether it was
// narrowed at all. The inverse of MinPriorityProvenance, for a consumer reading a file somebody
// else wrote.
func MinPriorityOfReport(rep sarif.Report) (string, bool) {
	for _, p := range rep.Provenance {
		if p.Tool != MinPriorityProvenanceTool {
			continue
		}
		for _, f := range p.Fields {
			if f.Key == "band" {
				return f.Value, true
			}
		}
	}
	return "", false
}

// ScopeOfReport describes what a loaded report was scoped to, and reports whether it was scoped
// at all. The inverse of ScopeProvenance, for a consumer reading a file somebody else wrote.
func ScopeOfReport(rep sarif.Report) (string, bool) {
	for _, p := range rep.Provenance {
		if p.Tool != ScopeProvenanceTool {
			continue
		}
		parts := make([]string, 0, len(p.Fields))
		for _, f := range p.Fields {
			parts = append(parts, f.Key+"="+f.Value)
		}
		return strings.Join(parts, " "), true
	}
	return "", false
}

// WriteSARIF writes the merged run results as SARIF 2.1.0 JSON.
func WriteSARIF(w io.Writer, run engine.Result) error {
	return WriteSARIFWith(w, run, sarif.MarshalOptions{})
}

// WriteSARIFWith is WriteSARIF with marshaling options.
func WriteSARIFWith(w io.Writer, run engine.Result, opts sarif.MarshalOptions) error {
	return WriteSARIFNarrowed(w, run, "", opts)
}

// WriteSARIFNarrowed writes a SARIF report that says which priority band it was narrowed to.
//
// The caller has already dropped the findings below the band; what this adds is the statement
// that it did. A file that is a subset and does not say so is the failure this whole provenance
// mechanism exists to prevent — most sharply for `draugr diff`, which would otherwise report
// every omitted finding as fixed.
func WriteSARIFNarrowed(w io.Writer, run engine.Result, band string, opts sarif.MarshalOptions) error {
	merged := MergedSARIF(run)
	if prov, ok := MinPriorityProvenance(band); ok {
		merged.Provenance = append(merged.Provenance, prov)
	}
	data, err := merged.MarshalSARIFWith(opts)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// scopeOf renders a run's scope, or nil when the run was not scoped.
//
// nil rather than an empty object, so an unscoped report is byte-identical to what it has always
// been and the field's presence is what carries the meaning.
func scopeOf(run engine.Result) *scopeInfo {
	if run.Scope.Empty() {
		return nil
	}
	return &scopeInfo{
		Components:        run.Scope.Components,
		Controls:          run.Scope.Controls,
		SkippedComponents: run.Scope.SkippedComponents,
	}
}

// reachabilityInfo mirrors engine.ReachabilitySummary in the report document.
//
// Totals plus a breakdown per analyzer. Both are needed: a consumer gating on "how much of this
// run is undetermined" wants the total, and one asking "which tool said so, and how" needs the
// analyzer, because more than one can run and they do not reach their answers the same way.
type reachabilityInfo struct {
	Analyzers []analyzerReachabilityInfo `json:"analyzers"`
	// Reachable, Unreachable and Unknown are the totals across every analyzer. Unknown is
	// reported rather than folded into a total, because it says how much of the answer is
	// missing, and an unreachable count alone cannot express that.
	Reachable   int `json:"reachable"`
	Unreachable int `json:"unreachable"`
	Unknown     int `json:"unknown"`
}

// analyzerReachabilityInfo is one analyzer's contribution.
type analyzerReachabilityInfo struct {
	Analyzer    string `json:"analyzer"`
	Reachable   int    `json:"reachable"`
	Unreachable int    `json:"unreachable"`
	Unknown     int    `json:"unknown"`
	// Contributed counts findings only this analyzer reported, kept rather than folded away.
	Contributed int `json:"contributed,omitempty"`
}

// reachabilityOf renders the run's reachability summary, or nil when no analyzer ran.
func reachabilityOf(run engine.Result) *reachabilityInfo {
	r := run.Reachability
	if !r.Ran() {
		return nil
	}
	out := &reachabilityInfo{
		Reachable:   r.Reachable,
		Unreachable: r.Unreachable,
		Unknown:     r.Unknown,
	}
	for _, a := range r.Analyzers {
		out.Analyzers = append(out.Analyzers, analyzerReachabilityInfo{
			Analyzer:    a.Analyzer,
			Reachable:   a.Reachable,
			Unreachable: a.Unreachable,
			Unknown:     a.Unknown,
			Contributed: a.Contributed,
		})
	}
	return out
}
