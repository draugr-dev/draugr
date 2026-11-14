package scanners

import (
	"context"
	"log/slog"
	"sync"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// refusedRead is a read the cluster refused the scan's credential, and the checks it left undecided.
type refusedRead struct {
	verb, resource string
}

// Reason is what the report says about the checks the read left undecided.
func (r refusedRead) Reason() string { return "denied " + r.verb + " " + r.resource }

// refusals collects the reads a scan was refused, by the check each left undecided.
type refusals struct {
	mu      sync.Mutex
	byCheck map[string]refusedRead
}

type refusalsKey struct{}

// withRefusals is ctx carrying a collector for the reads the policies are refused.
func withRefusals(ctx context.Context) (context.Context, *refusals) {
	r := &refusals{byCheck: map[string]refusedRead{}}
	return context.WithValue(ctx, refusalsKey{}, r), r
}

// readFailed records that a read the checks need failed. Every failure is in the debug log, which
// otherwise said nothing about it; a refusal of the credential is also kept for the report, so the
// checks it left undecided read as denied rather than as left for a person.
func readFailed(ctx context.Context, checks []string, verb, resource string, err error) {
	slog.DebugContext(ctx, "kubernetes read failed", "verb", verb, "resource", resource, "checks", checks, "error", err)
	if !apierrors.IsForbidden(err) {
		return
	}
	r, ok := ctx.Value(refusalsKey{}).(*refusals)
	if !ok {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, id := range checks {
		if _, seen := r.byCheck[id]; !seen {
			r.byCheck[id] = refusedRead{verb: verb, resource: resource}
		}
	}
}

// accessCheckIDs are the access checks a run asks, the cluster-scoped ones only over the whole cluster.
func accessCheckIDs(scoped bool) []string {
	var out []string
	for _, c := range accessChecks {
		if !scoped || !c.clusterScoped {
			out = append(out, c.id)
		}
	}
	return out
}
