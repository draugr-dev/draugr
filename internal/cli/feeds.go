package cli

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/internal/feeds"
)

// fetchFeed is feeds.Fetch, indirected so tests can exercise the command without a network.
var fetchFeed = feeds.Fetch

func newFeedsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "feeds",
		Short: "Manage the exploitability feeds Draugr can enrich findings with",
		Long: "Fetch and inspect the KEV and EPSS datasets that raise a finding's severity by\n" +
			"real-world exploitability. Fetching is explicit: a scan reads the cache and never\n" +
			"reaches the network on its own, so a gated run stays reproducible and works offline.",
	}
	cmd.AddCommand(newFeedsUpdateCommand())
	cmd.AddCommand(newFeedsStatusCommand())
	return cmd
}

func newFeedsUpdateCommand() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "update [kev|epss]",
		Short: "Fetch the exploitability feeds into ~/.draugr/feeds",
		Long: "Download CISA's KEV catalog and FIRST's EPSS scores into ~/.draugr/feeds, where a\n" +
			"scan can read them without touching the network. With no arguments, fetches both.\n\n" +
			"In CI, run this as its own step: a feed outage then fails where it happened, rather\n" +
			"than as a scan that quietly ranked everything as though nothing were exploited.",
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
// A failure is returned rather than collected: there are two feeds, both are optional to use
// and neither substitutes for the other, so the first failure is the whole answer. Continuing
// would report a partial success that the next scan cannot distinguish from a full one.
func updateFeeds(cmd *cobra.Command, dir string, names []feeds.Name, force bool) error {
	out := cmd.OutOrStdout()
	cached := feeds.Load(dir)
	now := time.Now()

	for _, n := range names {
		if rec, ok := cached[n]; ok && !force && !rec.Stale(now, feeds.DefaultMaxAge) {
			_, _ = fmt.Fprintf(out, "%-5s current (%s old) — --force to fetch anyway\n", n, humanAge(rec.Age(now)))
			continue
		}
		_, _ = fmt.Fprintf(out, "%-5s fetching %s…\n", n, feeds.URL(n))
		rec, err := fetchFeed(cmd.Context(), dir, n, nil)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(out, "%-5s %s (%s)\n", n, feeds.Path(dir, n), humanBytes(rec.Bytes))
	}
	return nil
}

func newFeedsStatusCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show what is cached, how old it is, and where it came from",
		Long: "List the cached exploitability feeds with their age, size, source and digest.\n\n" +
			"Age is the point: EPSS is republished daily, so a stale copy does not fail — it\n" +
			"quietly ranks a finding lower than today's data would.",
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

	_, _ = fmt.Fprintf(out, "%-6s %-22s %-14s %-10s %s\n", "FEED", "FETCHED", "AGE", "SIZE", "DIGEST")
	var missing, stale []feeds.Name
	for _, n := range feeds.Names() {
		rec, ok := cached[n]
		if !ok {
			missing = append(missing, n)
			_, _ = fmt.Fprintf(out, "%-6s %-22s %-14s %-10s %s\n", n, "—", "—", "—", "—")
			continue
		}
		age := humanAge(rec.Age(now))
		if rec.Stale(now, feeds.DefaultMaxAge) {
			stale = append(stale, n)
			age += " (stale)"
		}
		_, _ = fmt.Fprintf(out, "%-6s %-22s %-14s %-10s %s\n",
			n, rec.FetchedAt.Format("2006-01-02 15:04Z"), age, humanBytes(rec.Bytes), short(rec.SHA256))
	}

	_, _ = fmt.Fprintf(out, "\ncache: %s\n", dir)
	for _, n := range feeds.Names() {
		_, _ = fmt.Fprintf(out, "  %-5s %s — %s\n", n, feeds.Describe(n), feeds.URL(n))
	}

	switch {
	case len(missing) == len(feeds.Names()):
		_, _ = fmt.Fprintf(out, "\nNothing cached. Run `draugr feeds update` to fetch both.\n")
	case len(missing) > 0:
		_, _ = fmt.Fprintf(out, "\n%s is not cached. Run `draugr feeds update %s`.\n",
			joinNames(missing), joinNames(missing))
	}
	if len(stale) > 0 {
		_, _ = fmt.Fprintf(out, "\n%s older than %s. A scan will use it and say so; "+
			"`draugr feeds update` refreshes it.\n", joinNames(stale), humanAge(feeds.DefaultMaxAge))
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
			return nil, fmt.Errorf("unknown feed %q; known feeds are kev, epss", a)
		}
		out = append(out, n)
	}
	return out, nil
}

// humanAge renders a duration the way someone reads a staleness report: the largest unit that
// still says something useful, and never more precision than the answer deserves.
func humanAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	// Rounded rather than truncated: a feed fetched 119 minutes ago is two hours old to
	// everyone except integer division.
	case d < time.Hour:
		return plural(int(d.Round(time.Minute).Minutes()), "minute")
	case d < 48*time.Hour:
		return plural(int(d.Round(time.Hour).Hours()), "hour")
	default:
		return plural(int(d.Round(time.Hour).Hours())/24, "day")
	}
}

// humanBytes renders a size in the largest unit that keeps it under four digits.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGT"[exp])
}
