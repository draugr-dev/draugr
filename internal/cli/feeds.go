package cli

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/internal/feeds"
	"github.com/draugr-dev/draugr/internal/netpolicy"

	"github.com/draugr-dev/draugr/internal/english"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// fetchFeed is feeds.Fetch, indirected so tests can exercise the command without a network.
var fetchFeed = feeds.Fetch

func newFeedsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "feeds",
		Short: "Manage the datasets a scan reads from ~/.draugr/feeds",
		Long: "Fetch and inspect the cached datasets a scan reads without the network:\n\n" +
			"  kev       CISA's catalog of vulnerabilities exploited in the wild\n" +
			"  epss      FIRST's scores for the likelihood of exploitation\n" +
			"  govulndb  the Go vulnerability database, read by govulncheck\n\n" +
			"A scan reads the cache and never fetches on its own. Update it with this command.",
	}
	cmd.AddCommand(newFeedsUpdateCommand())
	cmd.AddCommand(newFeedsStatusCommand())
	return cmd
}

func newFeedsUpdateCommand() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "update [kev|epss|govulndb]",
		Short: "Fetch the datasets into ~/.draugr/feeds",
		Long: "Download CISA's KEV catalog, FIRST's EPSS scores and the Go vulnerability database\n" +
			"into ~/.draugr/feeds, where a scan reads them without touching the network. With no\n" +
			"arguments, fetches all three.\n\n" +
			"In CI, run it as its own step so a feed outage surfaces there rather than during a scan.\n" +
			"A fetch that fails keeps the cached copy and says how old it is; with nothing cached\n" +
			"there is no answer to keep, and it fails.",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := feeds.Dir()
			if err != nil {
				return err
			}
			names, err := feedNames(args)
			if err != nil {
				return err
			}
			return updateFeeds(cmd, dir, names, force)
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "fetch even if the cached copy is current")
	return cmd
}

// updateFeeds fetches each named feed, reporting as it goes.
//
// A fetch that fails with nothing cached is returned rather than collected: every feed is optional
// to use and none substitutes for another, so the first failure is the
// whole answer. Continuing would report a partial success that the next scan cannot distinguish
// from a full one.
//
// A fetch that fails with a copy already on disk is different, and does not fail. This step exists
// so a scan cannot rank everything as though nothing were exploited; a cached catalog does not
// do that. It ranks on data of a known age, the report says how old, and blocking a pipeline on
// somebody else's outage buys nothing when the answer is already here.
func updateFeeds(cmd *cobra.Command, dir string, names []feeds.Name, force bool) error {
	out := cmd.OutOrStdout()
	cached := feeds.Load(dir)
	now := time.Now()

	if netpolicy.Offline() {
		// Every name would be fetched, so name them all rather than stopping at the first.
		urls := make([]string, 0, len(names))
		for _, n := range names {
			urls = append(urls, feeds.URL(n))
		}
		return netpolicy.Refuse("draugr feeds update", strings.Join(urls, "\n                        "))
	}

	for _, n := range names {
		if rec, ok := cached[n]; ok && !force && !rec.Stale(now, feeds.DefaultMaxAge) {
			_, _ = fmt.Fprintf(out, "%-8s current (%s old) · --force to fetch anyway\n", n, feeds.HumanAge(rec.Age(now)))
			continue
		}
		_, _ = fmt.Fprintf(out, "%-8s fetching %s…\n", n, feeds.URL(n))
		rec, err := fetchFeed(cmd.Context(), dir, n, nil)
		if err != nil {
			// A copy on disk is worth more than a failed run. The reason this step exists is to stop a scan
			// ranking everything as though nothing were exploited. And a cached catalog does not do that:
			// it ranks on data of a stated age, which the report then carries. Refusing here would block a
			// pipeline on somebody else's outage while the answer sat on disk.
			prev, cachedOK := cached[n]
			if !cachedOK {
				return err
			}
			_, _ = fmt.Fprintf(out, "%-8s kept the cached copy (%s old): %v\n", n, feeds.HumanAge(prev.Age(now)), err)
			// Warned as well as printed, because the line above is one of several on a step
			// nobody reads when it succeeds, and this is the run where the ranking is older than
			// the operator thinks.
			slog.WarnContext(cmd.Context(), "feed not refreshed, scanning on the cached copy",
				"feed", string(n), "age", feeds.HumanAge(prev.Age(now)), "error", err.Error())
			continue
		}
		_, _ = fmt.Fprintf(out, "%-8s %s (%s)\n", n, feeds.Path(dir, n), feeds.HumanBytes(rec.Bytes))
	}
	return nil
}

func newFeedsStatusCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show what is cached, how old it is, and where it came from",
		Long: "List the cached datasets with their age, size, source and digest.\n\n" +
			"EPSS is republished daily. A stale KEV or EPSS copy still scans and ranks findings on\n" +
			"old data. A stale govulndb copy is not read. govulncheck queries vuln.go.dev instead,\n" +
			"and with --offline the control reports an error.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir, err := feeds.Dir()
			if err != nil {
				return err
			}
			feedsStatus(cmd.OutOrStdout(), dir, time.Now())
			return nil
		},
	}
	return cmd
}

// feedsStatus writes the cache report. It never fails: an empty cache is a legitimate state and
// the answer to "what have I got" is "nothing yet", not an error.
func feedsStatus(out io.Writer, dir string, now time.Time) {
	cached := feeds.Load(dir)

	_, _ = fmt.Fprintf(out, "%-10s %-22s %-14s %-10s %s\n", "FEED", "FETCHED", "AGE", "SIZE", "DIGEST")
	var missing, stale []feeds.Name
	for _, n := range feeds.Names() {
		rec, ok := cached[n]
		if !ok {
			missing = append(missing, n)
			_, _ = fmt.Fprintf(out, "%-10s %-22s %-14s %-10s %s\n", n, "-", "-", "-", "-")
			continue
		}
		age := feeds.HumanAge(rec.Age(now))
		if rec.Stale(now, feeds.DefaultMaxAge) {
			stale = append(stale, n)
			age += " (stale)"
		}
		_, _ = fmt.Fprintf(out, "%-10s %-22s %-14s %-10s %s\n",
			n, rec.FetchedAt.Format("2006-01-02 15:04Z"), age, feeds.HumanBytes(rec.Bytes), short(rec.SHA256))
	}

	// Named like every other block, with the path beside the title rather than as it. The first
	// block here is headed in the product's own shape and this one was a lowercase label, so one
	// screen carried both.
	col := tui.For(out)
	_, _ = fmt.Fprintf(out, "\n%s  %s\n", col.Paint(tui.StyleMuted, "SOURCES"),
		col.Paint(tui.StyleMuted, "(cached in "+dir+")"))
	for _, n := range feeds.Names() {
		_, _ = fmt.Fprintf(out, "  %-10s %s · %s\n", n, feeds.Describe(n), feeds.URL(n))
	}

	switch {
	case len(missing) == len(feeds.Names()):
		_, _ = fmt.Fprintf(out, "\nNothing cached. Run `draugr feeds update` to fetch all of them.\n")
	case len(missing) > 0:
		_, _ = fmt.Fprintf(out, "\n%s %s not cached. Run `draugr feeds update %s`.\n",
			joinNames(missing), english.Choose(len(missing), "is", "are"), argNames(missing))
	}
	// A stale exploitability feed is still read; a stale Go vulnerability database is not, so the
	// two get different consequences rather than one sentence that is wrong for one of them.
	var staleRanked []feeds.Name
	staleGo := false
	for _, n := range stale {
		if n == feeds.GoVulnDB {
			staleGo = true
			continue
		}
		staleRanked = append(staleRanked, n)
	}
	if len(staleRanked) > 0 {
		_, _ = fmt.Fprintf(out, "\n%s older than %s. A scan uses it and marks the report stale. "+
			"Refresh with `draugr feeds update`.\n", joinNames(staleRanked), feeds.HumanAge(feeds.DefaultMaxAge))
	}
	if staleGo {
		_, _ = fmt.Fprintf(out, "\ngovulndb older than %s. A scan does not read it. govulncheck queries vuln.go.dev instead, "+
			"and with --offline the control reports an error. Refresh with `draugr feeds update govulndb`.\n",
			feeds.HumanAge(feeds.DefaultMaxAge))
	}
}

// short renders a digest at the length people actually compare, with the algorithm named so it
// is obvious what it is a digest of.
func short(sum string) string {
	if len(sum) <= 12 {
		return sum
	}
	return "sha256:" + sum[:12]
}

// argNames renders feed names as command arguments.
func argNames(names []feeds.Name) string {
	s := make([]string, len(names))
	for i, n := range names {
		s[i] = string(n)
	}
	return strings.Join(s, " ")
}

// joinNames renders feed names for a sentence.
func joinNames(names []feeds.Name) string {
	s := make([]string, len(names))
	for i, n := range names {
		s[i] = string(n)
	}
	return strings.Join(s, " and ")
}

// feedNames resolves command arguments to feeds, defaulting to all of them.
func feedNames(args []string) ([]feeds.Name, error) {
	if len(args) == 0 {
		return feeds.Names(), nil
	}
	var out []feeds.Name
	for _, a := range args {
		n := feeds.Name(strings.ToLower(a))
		if feeds.URL(n) == "" {
			return nil, fmt.Errorf("unknown feed %q; known feeds are %s", a, argNames(feeds.Names()))
		}
		out = append(out, n)
	}
	return out, nil
}
