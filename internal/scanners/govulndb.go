package scanners

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/draugr-dev/draugr/internal/feeds"
	"github.com/draugr-dev/draugr/internal/netpolicy"
)

// feedMaxAge is how old a cached feed may be, set by the scan from config.exploitability.maxAge.
// Process-wide like the offline switch, because a scanner sees its own options and not the
// descriptor's.
var (
	feedMaxAgeMu sync.Mutex
	feedMaxAge   = feeds.DefaultMaxAge
)

// SetFeedMaxAge sets how old a cached feed may be before a scan refuses to read it. Zero or less
// means never too old, for a runner deliberately pinned to a known copy.
func SetFeedMaxAge(d time.Duration) {
	feedMaxAgeMu.Lock()
	defer feedMaxAgeMu.Unlock()
	feedMaxAge = d
	govulnDB = &govulnDBResolver{} // a new limit is a new answer
}

// FeedMaxAge is the limit SetFeedMaxAge last set.
func FeedMaxAge() time.Duration {
	feedMaxAgeMu.Lock()
	defer feedMaxAgeMu.Unlock()
	return feedMaxAge
}

// govulnDBChoice is which database govulncheck reads in this run, and why.
type govulnDBChoice struct {
	// url is passed to -db; empty means govulncheck's own default, vuln.go.dev.
	url     string
	local   feeds.LocalGoVulnDB
	refused string // why a local copy that exists was not used, when the run went to vuln.go.dev
	err     error  // set when govulncheck cannot run at all: offline, with no usable copy
}

// describe is the value the report shows for the database a run read.
func (c govulnDBChoice) describe() string {
	switch {
	case c.url != "":
		return "local copy, fetched " + c.local.Record.FetchedAt.UTC().Format("2006-01-02")
	case c.refused != "":
		return "vuln.go.dev (" + c.refused + ")"
	default:
		return "vuln.go.dev"
	}
}

type govulnDBResolver struct {
	once   sync.Once
	choice govulnDBChoice
	warned sync.Once
	// refreshErr is why this run's refresh of a stale or unusable local copy failed, named
	// beside the reason the copy was passed over.
	refreshErr error
}

// govulnDB is resolved once per run: every module and every component reads the same database,
// and the report says one thing about it.
var govulnDB = &govulnDBResolver{}

// findLocalGoVulnDB locates the cached copy; a variable so tests can point it at a fixture.
var findLocalGoVulnDB = func(now time.Time, maxAge time.Duration) (feeds.LocalGoVulnDB, error) {
	dir, err := feeds.Dir()
	if err != nil {
		return feeds.LocalGoVulnDB{}, err
	}
	return feeds.FindGoVulnDB(dir, now, maxAge)
}

// resolveGovulnDB decides which database govulncheck reads.
//
// A usable local copy is read, whether or not the runner is offline: it is what the operator put
// there, and it keeps the run reproducible. A copy that fails its checks is never read, because
// govulncheck reports "No vulnerabilities found" against an empty or stale database. Online, the
// run falls back to vuln.go.dev and says why; offline, there is nothing to fall back to, and the
// control reports that it could not run.
func resolveGovulnDB() govulnDBChoice { return currentGovulnDB().resolve() }

// currentGovulnDB is this run's resolver.
func currentGovulnDB() *govulnDBResolver {
	feedMaxAgeMu.Lock()
	defer feedMaxAgeMu.Unlock()
	return govulnDB
}

func (r *govulnDBResolver) resolve() govulnDBChoice {
	r.once.Do(func() {
		local, err := findLocalGoVulnDB(time.Now(), FeedMaxAge())
		switch {
		case err == nil:
			r.choice = govulnDBChoice{url: "file://" + local.Path, local: local}
		case netpolicy.Offline():
			r.choice = govulnDBChoice{err: fmt.Errorf("cannot run offline: %w; run `draugr feeds update govulndb`", err)}
		case errors.Is(err, feeds.ErrNoLocalGoVulnDB):
			r.choice = govulnDBChoice{}
		default:
			refused := err.Error()
			if r.refreshErr != nil {
				refused += "; refreshing it failed: " + r.refreshErr.Error()
			}
			r.choice = govulnDBChoice{refused: refused}
		}
	})
	return r.choice
}

// fetchGoVulnDB fetches the Go vulnerability database into the feed cache, as `draugr feeds update
// govulndb` does; a variable so no test reaches vuln.go.dev.
var fetchGoVulnDB = func(ctx context.Context) error {
	dir, err := feeds.Dir()
	if err != nil {
		return err
	}
	_, err = feeds.Fetch(ctx, dir, feeds.GoVulnDB, nil)
	return err
}

// refreshGovulnDB is govulncheck's data refresh, run once before the jobs start like Trivy's and
// Grype's. A local copy that is too old, or fails its checks, is fetched again, so the run reads
// it on this machine rather than sending the module paths the code depends on to vuln.go.dev.
//
// Only a copy somebody fetched is refreshed. A machine that never ran `draugr feeds update
// govulndb` has chosen vuln.go.dev, and the refresh does not download the database for it. When
// the fetch fails, the stale copy stays unread, the run falls back to vuln.go.dev, and the
// warning that says so names the failure.
func refreshGovulnDB(ctx context.Context) error {
	if netpolicy.Offline() {
		return nil
	}
	_, err := findLocalGoVulnDB(time.Now(), FeedMaxAge())
	if err == nil || errors.Is(err, feeds.ErrNoLocalGoVulnDB) {
		return nil
	}
	fetchErr := fetchGoVulnDB(ctx)
	feedMaxAgeMu.Lock()
	govulnDB = &govulnDBResolver{refreshErr: fetchErr} // the copy on disk has changed, or failed to
	feedMaxAgeMu.Unlock()
	if fetchErr != nil {
		return fmt.Errorf("refresh the local Go vulnerability database: %w", fetchErr)
	}
	return nil
}

// govulncheckPreflight refuses the scan before anything runs when there is no database to read,
// and warns once per run when a local copy was passed over for vuln.go.dev.
func govulncheckPreflight(ctx context.Context) error {
	r := currentGovulnDB()
	choice := r.resolve()
	if choice.refused != "" {
		r.warned.Do(func() {
			slog.WarnContext(ctx, "govulncheck is querying vuln.go.dev instead of the local Go vulnerability database",
				"reason", choice.refused)
		})
	}
	return choice.err
}
