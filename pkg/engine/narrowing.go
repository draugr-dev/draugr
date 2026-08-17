package engine

import (
	"fmt"
	"sort"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

// SkippedJob is a job that was planned and then not run, because the scanner cannot answer the
// question the target asks.
//
// Recorded rather than dropped. A scanner that quietly does not run is the same thing as one that
// found nothing, and the report has no way to tell them apart — which is the failure this whole
// codebase is built to avoid. The alternative that was tried first, refusing the descriptor, is
// worse: it makes a reader hand-write an exception to state something Draugr already knows.
type SkippedJob struct {
	Control   string
	Scanner   string
	Component string
	// Reason is a sentence a reader can act on, or decide not to.
	Reason string
}

// dropUnnarrowable removes jobs whose scanner always describes a whole cluster from targets that
// asked for part of one, and says which it removed.
//
// A component narrows its infrastructure surface with `namespaces` because it owns part of a
// shared cluster. Some scanners cannot honor that — kube-bench's checks are kubectl pipelines
// with `--all-namespaces` written into them, and the Job-based ones read a node's own filesystem,
// which has no namespace. Running them anyway would file the whole cluster's findings against a
// component that claims three of its namespaces: a report that looks scoped, whose rule ids look
// scoped, and whose findings are somebody else's.
//
// So the job is not planned, exactly as a controller does not plan for an infrastructure kind it
// has no benchmark for. Declaring a cluster twice — once narrowed, once whole — is a descriptor
// that means something, and the scanner that can only do one of those should do that one.
func dropUnnarrowable(reg *Registry, planned []PlannedJob) ([]PlannedJob, []SkippedJob) {
	var kept []PlannedJob
	var skipped []SkippedJob
	for _, pj := range planned {
		infra, ok := pj.Job.Target.(plugin.InfraTarget)
		if !ok || len(infra.Namespaces) == 0 {
			kept = append(kept, pj)
			continue
		}
		sc, ok := reg.Scanner(pj.Job.Scanner)
		if !ok || !sc.Info().ClusterWide {
			kept = append(kept, pj)
			continue
		}
		skipped = append(skipped, SkippedJob{
			Control:   pj.Control,
			Scanner:   pj.Job.Scanner,
			Component: pj.Component,
			Reason: fmt.Sprintf("audits the whole cluster and cannot be narrowed to %s",
				namespaceList(infra.Namespaces)),
		})
	}
	sort.Slice(skipped, func(i, j int) bool {
		if skipped[i].Component != skipped[j].Component {
			return skipped[i].Component < skipped[j].Component
		}
		return skipped[i].Scanner < skipped[j].Scanner
	})
	return kept, skipped
}

// namespaceList renders the namespaces a component claimed, so the note says what was asked for
// rather than that something was.
func namespaceList(namespaces []string) string {
	switch len(namespaces) {
	case 1:
		return "namespace " + namespaces[0]
	case 2:
		return "namespaces " + namespaces[0] + " and " + namespaces[1]
	default:
		return fmt.Sprintf("%d namespaces", len(namespaces))
	}
}
