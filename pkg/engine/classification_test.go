package engine

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A finding carries the classification that produced its band.
//
// Two components, because one proves the stamping runs and two prove it does not collapse: the
// whole point of the field is that the same flaw is a different band in a different place, and a
// single component cannot tell a per-job value from a per-run one.
func TestStampedFindingsCarryTheirComponentsClassification(t *testing.T) {
	e := &Engine{}
	jobs := []PlannedJob{
		{Component: "checkout", Exposure: saga.ExposurePublic, Criticality: saga.CriticalityCritical},
		{Component: "batch", Exposure: saga.ExposureRestricted, Criticality: saga.CriticalitySupporting},
	}
	want := map[string][2]string{
		"checkout": {"public", "critical"},
		"batch":    {"restricted", "supporting"},
	}

	for _, pj := range jobs {
		got := e.stampJobFields(sarif.Report{Results: []sarif.Result{{RuleID: "CVE-2020-1"}}}, pj)
		if len(got.Results) != 1 {
			t.Fatalf("%s: %d results", pj.Component, len(got.Results))
		}
		r := got.Results[0]
		if [2]string{r.Exposure, r.Criticality} != want[pj.Component] {
			t.Errorf("%s carried %q/%q, want %v — a band explained with another component's inputs",
				pj.Component, r.Exposure, r.Criticality, want[pj.Component])
		}
	}
}

// A component that declares neither leaves both empty rather than inventing the default it is
// read as. The reading belongs to whoever computes the band; recording "public" here would state
// a declaration nobody made, and a reader could not tell it from one somebody did.
func TestAnUndeclaredComponentCarriesNoClassification(t *testing.T) {
	e := &Engine{}
	got := e.stampJobFields(sarif.Report{Results: []sarif.Result{{RuleID: "CVE-2020-1"}}},
		PlannedJob{Component: "unclassified"})
	if r := got.Results[0]; r.Exposure != "" || r.Criticality != "" {
		t.Errorf("carried %q/%q, want both empty", r.Exposure, r.Criticality)
	}
}

// Stamping must not write through to the cached report. A cached scan is replayed for every
// component that shares the target, so a mutated result would hand the second component the
// first one's classification — and the finding would explain its band with numbers from
// somewhere else entirely.
func TestStampingLeavesTheCachedReportAlone(t *testing.T) {
	e := &Engine{}
	cached := sarif.Report{Results: []sarif.Result{{RuleID: "CVE-2020-1"}}}
	e.stampJobFields(cached, PlannedJob{
		Component: "checkout", Exposure: saga.ExposurePublic, Criticality: saga.CriticalityCritical,
	})
	if r := cached.Results[0]; r.Exposure != "" || r.Criticality != "" || r.Component != "" {
		t.Errorf("the cached report was mutated: %+v", r)
	}
}

// Who publishes what was scanned is stamped from the job's target, not written by whichever
// scanner produced the finding.
//
// Two components sharing one repository and disagreeing about it, because that is the case the
// per-job stamp exists for: the scan is cached and replayed, and a value written into the cached
// report would hand the second component the first one's answer. It is also the realistic shape —
// a vendor's repository is upstream to the team that consumes it and self to nobody.
func TestWhoPublishesTheTargetIsStampedPerJob(t *testing.T) {
	e := &Engine{}
	cached := sarif.Report{Results: []sarif.Result{{RuleID: "GPL-3.0-only"}}}

	consumer := e.stampJobFields(cached, PlannedJob{
		Component: "analytics",
		Job:       plugin.ScanJob{Target: plugin.RepositoryTarget{URL: "https://example.com/x.git", Upstream: true}},
	})
	if !consumer.Results[0].BuiltUpstream {
		t.Error("a repository declared upstream produced a finding the reader is told to go and fix")
	}

	maintainer := e.stampJobFields(cached, PlannedJob{
		Component: "platform",
		Job:       plugin.ScanJob{Target: plugin.RepositoryTarget{URL: "https://example.com/x.git"}},
	})
	if maintainer.Results[0].BuiltUpstream {
		t.Error("a repository nobody declared upstream came back as somebody else's")
	}
	if cached.Results[0].BuiltUpstream {
		t.Error("the cached report was mutated, so the next component inherits this answer")
	}
}

// A target that cannot answer leaves whatever the scanner already concluded.
//
// kube-bench decides per control which half of a managed cluster the provider runs, which is more
// than the descriptor knows. A stamp that wrote `false` over that would take a true answer and
// replace it with the absence of a declaration.
func TestStampingNeverClearsWhatAScannerAlreadyKnew(t *testing.T) {
	e := &Engine{}
	got := e.stampJobFields(
		sarif.Report{Results: []sarif.Result{{RuleID: "1.2.20", BuiltUpstream: true}}},
		PlannedJob{Component: "platform", Job: plugin.ScanJob{Target: plugin.HostTarget{URL: "https://example.com"}}})
	if !got.Results[0].BuiltUpstream {
		t.Error("a scanner's own answer was overwritten by a target that does not declare one")
	}
}
