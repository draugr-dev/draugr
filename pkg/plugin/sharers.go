package plugin

import "context"

type sharersKey struct{}

// WithSharers returns a context saying that n jobs of the running job's scanner, this one
// included, share the machine with it.
func WithSharers(ctx context.Context, n int) context.Context {
	return context.WithValue(ctx, sharersKey{}, n)
}

// Sharers is how many jobs of the running job's scanner the run has running or yet to start,
// counting this one, and never more than the jobs the run runs at once: 1 for a job its scanner
// runs alone, and 1 outside a run.
//
// For a tool that sizes its own parallelism to every CPU it can see. Several of its runs at once
// each take the whole machine and divide it between them unawares, and a tool whose analysis has
// wall-clock limits then finishes less in each. Such a scanner gives each run its share instead,
// and a run with no other left keeps the tool's own default.
func Sharers(ctx context.Context) int {
	if n, ok := ctx.Value(sharersKey{}).(int); ok && n > 1 {
		return n
	}
	return 1
}
