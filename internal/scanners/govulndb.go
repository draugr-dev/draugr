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

func currentFeedMaxAge() time.Duration {
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
		local, err := findLocalGoVulnDB(time.Now(), currentFeedMaxAge())
		switch {
		case err == nil:
			r.choice = govulnDBChoice{url: "file://" + local.Path, local: local}
		case netpolicy.Offline():
			r.choice = govulnDBChoice{err: fmt.Errorf("cannot run offline: %w; run `draugr feeds update govulndb`", err)}
		case errors.Is(err, feeds.ErrNoLocalGoVulnDB):
			r.choice = govulnDBChoice{}
		default:
			r.choice = govulnDBChoice{refused: err.Error()}
		}
	})
	return r.choice
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
