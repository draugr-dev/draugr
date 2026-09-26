// Package enrich builds the signals a scan ranks its findings with: exploitability, the age a cached
// feed may reach, and dependency health.
//
// `draugr scan` and the MCP scan both call Load, so a setting the descriptor carries applies from
// either side. Each entry point assembling its own list is how one of them comes to rank without a
// signal the descriptor asked for, with nothing in the result saying so.
package enrich

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/draugr-dev/draugr/internal/depsdev"
	"github.com/draugr-dev/draugr/internal/exploitdata"
	"github.com/draugr-dev/draugr/internal/scanners"
	"github.com/draugr-dev/draugr/internal/scanpolicy"
	"github.com/draugr-dev/draugr/pkg/dephealth"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// DepsDevEndpoint overrides where dependency health sends its lookups. Empty means deps.dev; a
// test in another package points it at its own server, as depsdev.Client.Endpoint does for one in
// that package.
var DepsDevEndpoint string

// Enrichment is what a scan ranks with: the engine options that apply it, and the feeds it read.
type Enrichment struct {
	Options []engine.Option
	Feeds   []report.FeedProvenance
}

// Load reads the exploitability feeds settings names and prepares dependency health when cfg
// enables it, and sets the age limit every cached feed is held to, including the ones scanners
// read for themselves.
//
// Diagnostics from dependency health go to warn, because that signal never fails a scan.
func Load(ctx context.Context, settings exploitdata.Settings, cfg *saga.DependencyHealthConfig, warn io.Writer) (Enrichment, error) {
	// The same limit governs every cached feed, including the Go vulnerability database
	// govulncheck reads, which a scanner cannot see in the descriptor for itself.
	scanners.SetFeedMaxAge(settings.MaxAge)
	expl, feeds, err := exploitdata.Load(ctx, settings)
	if err != nil {
		return Enrichment{}, err
	}
	// Empty until the scan has found packages to ask about; see dependencyHealth.
	health, healthOpts := dependencyHealth(cfg, warn)
	opts := []engine.Option{
		engine.WithPrioritization(scanpolicy.PrioritizerWith(expl, health)),
		// Beside the prioritizer, because they describe the same decision from two sides: what
		// it did, and what it had to work from. A run that enriched without saying what it
		// consulted produces evidence nobody can check the ranking against.
		engine.WithConsulted(append(expl.Consulted(), health.Consulted()...)),
	}
	return Enrichment{Options: append(opts, healthOpts...), Feeds: feeds}, nil
}

// DependencyHealthDetail says what dependency health sends and to whom, for a consent prompt, or ""
// when cfg does not enable it.
func DependencyHealthDetail(cfg *saga.DependencyHealthConfig) string {
	if cfg == nil || !cfg.Enabled {
		return ""
	}
	return "sends package URLs to " + depsdev.Host
}

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
	client.Endpoint = DepsDevEndpoint
	return src, []engine.Option{engine.WithDependencyHealth(resolver(client, src, warn), src)}
}

// resolver fills src from client once the engine knows which packages the run found.
func resolver(client *depsdev.Client, src *dephealth.Source, warn io.Writer) engine.DependencyHealthResolver {
	return func(ctx context.Context, purls []string) error {
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
}
