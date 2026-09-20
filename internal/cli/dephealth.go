package cli

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/draugr-dev/draugr/internal/depsdev"
	"github.com/draugr-dev/draugr/pkg/dephealth"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// dependencyHealth builds the third enrichment, and returns nothing when the descriptor did not ask
// for it.
//
// Off unless asked, unlike the other two, because this one sends the list of packages a scan found
// to a third party. The other enrichments read a local cache that somebody chose to fill; this
// reaches the network during the run, and a team should agree to that in a pull request rather than
// find it in a proxy log.
//
// The source comes back empty and is filled during the scan. The prioritizer needs it before the
// scanners have run and the packages are only known after they have, so the engine resolves it
// between aggregation and ranking.
func dependencyHealth(cfg *saga.DependencyHealthConfig, warn io.Writer) (*dephealth.Source, []engine.Option) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}
	src := dephealth.New(nil, "")
	client := depsdev.New()

	resolve := func(ctx context.Context, purls []string) error {
		got, err := client.Lookup(ctx, purls)
		// Whatever was answered is still worth ranking on, so the partial result is loaded either
		// way and the failure is reported rather than raised. This signal never gates, and a run
		// that failed because somebody else's service was down would be a gate on their uptime.
		src.Load(got, time.Now().UTC().Format(time.DateOnly))
		if err != nil {
			_, _ = fmt.Fprintf(warn, "dependency health: %v; findings are ranked without it\n", err)
		}
		return nil
	}
	return src, []engine.Option{engine.WithDependencyHealth(resolve, src)}
}
