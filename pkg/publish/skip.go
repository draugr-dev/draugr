package publish

import (
	"context"
	"log/slog"

	"github.com/draugr-dev/draugr/pkg/report"
)

// skipPublisher is a no-op Publisher: a configured publisher that has nothing to do in the
// current environment (e.g. a github publisher run outside CI). It reports why and delivers
// nothing.
type skipPublisher struct{ kind, reason string }

func (p skipPublisher) Kind() string { return p.kind }
func (p skipPublisher) Publish(ctx context.Context, _ []report.Artifact) error {
	reportSkip(ctx, p.kind, p.reason)
	return nil
}

// skips collects the publishers one delivery passed over, so the publishers that stand aside for
// one reason are reported in one record rather than one record each.
//
// A descriptor commonly declares several publishers that need the same environment, a code-scanning
// upload and three issue entries all needing GitHub Actions, and outside it every one of them
// stands aside for the same reason. A record per publisher repeats one fact once per entry.
//
// The record names each kind with how many of its entries stood aside, so every skip is still
// counted and the sum is the number of publishers that delivered nothing.
type skips struct {
	// reasons is in the order each reason was first reported, which is descriptor order, so the
	// records come out in the same order on every run.
	reasons  []string
	byReason map[string]*kindCounts
}

// kindCounts is how many entries of each kind stood aside for one reason, in first-seen order.
type kindCounts struct {
	kinds  []string
	counts map[string]int
}

type skipsKey struct{}

// collectSkips returns a context whose skips are gathered rather than logged one by one, and the
// collector to log them from once delivery is done.
func collectSkips(ctx context.Context) (context.Context, *skips) {
	s := &skips{byReason: map[string]*kindCounts{}}
	return context.WithValue(ctx, skipsKey{}, s), s
}

// reportSkip records that a publisher of kind delivered nothing, and why. Under a collector the
// record waits for the others sharing its reason; without one, as for a publisher a caller drives
// directly, it is logged at once in the same shape.
func reportSkip(ctx context.Context, kind, reason string) {
	if s, ok := ctx.Value(skipsKey{}).(*skips); ok {
		s.add(kind, reason)
		return
	}
	logSkip(reason, &kindCounts{kinds: []string{kind}, counts: map[string]int{kind: 1}})
}

func (s *skips) add(kind, reason string) {
	kc, ok := s.byReason[reason]
	if !ok {
		kc = &kindCounts{counts: map[string]int{}}
		s.byReason[reason] = kc
		s.reasons = append(s.reasons, reason)
	}
	if kc.counts[kind] == 0 {
		kc.kinds = append(kc.kinds, kind)
	}
	kc.counts[kind]++
}

// log writes one record per reason.
func (s *skips) log() {
	for _, reason := range s.reasons {
		logSkip(reason, s.byReason[reason])
	}
}

// logSkip writes the record for one reason. The kinds are a group of kind to count, so a console
// reads `kinds.github=1 kinds.github-issue=3` and --log-format json carries an object a machine
// can sum.
func logSkip(reason string, kc *kindCounts) {
	kinds := make([]any, 0, len(kc.kinds))
	for _, k := range kc.kinds {
		kinds = append(kinds, slog.Int(k, kc.counts[k]))
	}
	slog.Info("publishers skipped", slog.Group("kinds", kinds...), "reason", reason)
}
