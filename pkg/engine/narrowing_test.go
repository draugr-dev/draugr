package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// stubNarrowScanner declares a capability and never scans; dropUnnarrowable only reads Info.
type stubNarrowScanner struct{ info plugin.ScannerInfo }

func (s stubNarrowScanner) Info() plugin.ScannerInfo { return s.info }
func (stubNarrowScanner) Scan(context.Context, plugin.Target, plugin.Config) (sarif.Report, error) {
	return sarif.Report{}, nil
}

// narrowingRegistry holds one scanner that always describes a whole cluster and one that does not,
// which is the only arrangement where dropping the wrong one is visible.
func narrowingRegistry(t *testing.T) *Registry {
	t.Helper()
	reg := NewRegistry()
	reg.RegisterScanner(stubNarrowScanner{info: plugin.ScannerInfo{
		Name: "whole-cluster-only", Controls: []string{"infrastructure"},
		TargetKinds: []plugin.TargetKind{plugin.TargetInfra}, ClusterWide: true,
	}})
	reg.RegisterScanner(stubNarrowScanner{info: plugin.ScannerInfo{
		Name: "api-reader", Controls: []string{"infrastructure"},
		TargetKinds: []plugin.TargetKind{plugin.TargetInfra},
	}})
	return reg
}

func infraJob(scanner, component string, namespaces ...string) PlannedJob {
	return PlannedJob{
		Control:   "infrastructure",
		Component: component,
		Job: plugin.ScanJob{
			Scanner: scanner,
			Target:  plugin.InfraTarget{Platform: "kubernetes", Ref: "prod", Namespaces: namespaces},
		},
	}
}

// A scanner that can only describe a whole cluster does not run against a component that claimed
// part of one. Refusing the descriptor instead makes a reader hand-write an exception stating
// something Draugr already knows, and running it anyway files the whole cluster's findings against
// a component that owns three of its namespaces.
//
// Two components, because one proves nothing: the same cluster declared twice — once narrowed,
// once whole — is the shape this appears in, and a filter that answered per descriptor rather than
// per job would take the scanner away from the component entitled to it.
func TestDropUnnarrowableKeepsTheComponentThatClaimedTheWholeCluster(t *testing.T) {
	reg := narrowingRegistry(t)
	planned := []PlannedJob{
		infraJob("api-reader", "team-a", "team-a"),
		infraJob("whole-cluster-only", "team-a", "team-a"),
		infraJob("api-reader", "prod"),
		infraJob("whole-cluster-only", "prod"),
	}
	kept, skipped := dropUnnarrowable(reg, planned)

	var keptDesc []string
	for _, pj := range kept {
		keptDesc = append(keptDesc, pj.Component+"/"+pj.Job.Scanner)
	}
	want := "team-a/api-reader prod/api-reader prod/whole-cluster-only"
	if got := strings.Join(keptDesc, " "); got != want {
		t.Errorf("kept %q, want %q", got, want)
	}
	if len(skipped) != 1 {
		t.Fatalf("expected one skip, got %d: %+v", len(skipped), skipped)
	}
	if skipped[0].Component != "team-a" || skipped[0].Scanner != "whole-cluster-only" {
		t.Errorf("wrong job skipped: %+v", skipped[0])
	}
	// The note has to say what was asked for, or a reader cannot tell whether it mattered.
	if !strings.Contains(skipped[0].Reason, "namespace team-a") {
		t.Errorf("the reason should name the scope that was asked for: %q", skipped[0].Reason)
	}
}

// A target that narrowed nothing is served by every scanner, and a scanner that can narrow is
// never dropped. Both directions, because dropping too much is the failure that looks like a pass.
func TestDropUnnarrowableLeavesEverythingElseAlone(t *testing.T) {
	reg := narrowingRegistry(t)
	planned := []PlannedJob{
		infraJob("whole-cluster-only", "prod"),
		infraJob("api-reader", "team-a", "team-a"),
		{Control: "sca", Component: "app", Job: plugin.ScanJob{
			Scanner: "api-reader", Target: plugin.RepositoryTarget{URL: "."}}},
	}
	kept, skipped := dropUnnarrowable(reg, planned)
	if len(kept) != len(planned) || len(skipped) != 0 {
		t.Errorf("kept %d of %d and skipped %d; nothing here can be narrowed wrongly",
			len(kept), len(planned), len(skipped))
	}
}

// An unregistered scanner cannot be asked what it can do, and guessing would drop a job on no
// evidence. It is kept, and the scan reports the missing scanner in its own terms.
func TestDropUnnarrowableKeepsAJobItCannotAskAbout(t *testing.T) {
	kept, skipped := dropUnnarrowable(NewRegistry(), []PlannedJob{infraJob("gone", "team-a", "team-a")})
	if len(kept) != 1 || len(skipped) != 0 {
		t.Errorf("kept %d, skipped %d: an unknown scanner is not evidence of anything", len(kept), len(skipped))
	}
}

func TestNamespaceListReadsAsAScope(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		want string
	}{
		{[]string{"a"}, "namespace a"},
		{[]string{"a", "b"}, "namespaces a and b"},
		{[]string{"a", "b", "c"}, "3 namespaces"},
	} {
		if got := namespaceList(tc.in); got != tc.want {
			t.Errorf("namespaceList(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
