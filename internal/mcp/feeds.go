package mcp

import (
	"context"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/draugr-dev/draugr/internal/feeds"
)

// --- feeds_status ---

// feedsDir locates the feed cache; a variable so tests never read the real ~/.draugr.
var feedsDir = feeds.Dir

// FeedStatus is one cached dataset a scan reads without the network.
type FeedStatus struct {
	Name        string `json:"name" jsonschema:"the feed, as named to draugr feeds update"`
	Description string `json:"description"`
	Cached      bool   `json:"cached"`
	FetchedAt   string `json:"fetchedAt,omitempty" jsonschema:"when Draugr fetched the cached copy, RFC 3339 in UTC"`
	Age         string `json:"age,omitempty" jsonschema:"how long ago the cached copy was fetched, rounded for reading"`
	AgeSeconds  int64  `json:"ageSeconds,omitempty"`
	Stale       bool   `json:"stale" jsonschema:"true when the cached copy is older than maxAge"`
	Source      string `json:"source" jsonschema:"the URL the feed is fetched from"`
	Bytes       int64  `json:"bytes,omitempty" jsonschema:"size of the cached copy on disk, decompressed"`
	Size        string `json:"size,omitempty" jsonschema:"size of the cached copy, rounded for reading"`
	SHA256      string `json:"sha256,omitempty" jsonschema:"digest of the cached copy, recorded when it was fetched"`
	// IfStale is stated for every feed, cached or not, because the consequence differs by feed:
	// an exploitability feed past its age is still read, and the Go database is not.
	IfStale string `json:"ifStale" jsonschema:"what a scan does with this feed once its copy is stale"`
}

// FeedsStatusOutput is the answer to "what is this machine's scan reading, and how old is it?".
type FeedsStatusOutput struct {
	Dir     string       `json:"dir" jsonschema:"the feed cache directory"`
	MaxAge  string       `json:"maxAge" jsonschema:"the age past which a feed is reported stale, and a scan's limit when config.exploitability.maxAge is unset"`
	Feeds   []FeedStatus `json:"feeds"`
	Missing []string     `json:"missing,omitempty" jsonschema:"feeds with no cached copy"`
	Stale   []string     `json:"stale,omitempty" jsonschema:"feeds whose cached copy is older than maxAge"`
	// Next is the command a person would run. Draugr will not run it for you.
	Next string `json:"next,omitempty" jsonschema:"the command that fetches every missing or stale feed; empty when each feed is cached and current"`
	Note string `json:"note"`
}

// ifStale says what a stale copy of each feed does to a scan, in the words `draugr feeds status`
// uses for the same thing.
var ifStale = map[feeds.Name]string{
	feeds.KEV:  "A scan still reads a stale copy and ranks findings on old data; the report marks the feed stale.",
	feeds.EPSS: "EPSS is republished daily. A scan still reads a stale copy and ranks findings on old data; the report marks the feed stale.",
	feeds.GoVulnDB: "A scan does not read a stale copy, and govulncheck queries vuln.go.dev instead; " +
		"with --offline, the control reports an error.",
}

// FeedsStatusTool reports what the feed cache holds, the same answer as `draugr feeds status`.
//
// It stops short of `draugr feeds update`, for the reason check_tools stops short of installing: a
// fetch reaches the network and writes to the user's home directory, and their client already has
// a permission model for running commands. The tool names the command and leaves the running to
// the person who approves such things.
func FeedsStatusTool(_ context.Context, _ *mcp.CallToolRequest, _ EmptyInput) (*mcp.CallToolResult, FeedsStatusOutput, error) {
	dir, err := feedsDir()
	if err != nil {
		return nil, FeedsStatusOutput{}, err
	}
	return nil, FeedsStatus(dir, time.Now()), nil
}

// FeedsStatus reports the cache in dir as of now. It never fails: an empty cache is a legitimate
// state, and every feed is then missing rather than the call being an error.
func FeedsStatus(dir string, now time.Time) FeedsStatusOutput {
	cached := feeds.Load(dir)
	out := FeedsStatusOutput{Dir: dir, MaxAge: feeds.HumanAge(feeds.DefaultMaxAge)}
	var refresh []string
	for _, n := range feeds.Names() {
		s := FeedStatus{
			Name: string(n), Description: feeds.Describe(n), Source: feeds.URL(n), IfStale: ifStale[n],
		}
		rec, ok := cached[n]
		if !ok {
			out.Missing = append(out.Missing, s.Name)
			refresh = append(refresh, s.Name)
			out.Feeds = append(out.Feeds, s)
			continue
		}
		age := rec.Age(now)
		s.Cached = true
		s.FetchedAt = rec.FetchedAt.UTC().Format(time.RFC3339)
		s.Age = feeds.HumanAge(age)
		s.AgeSeconds = int64(age / time.Second)
		s.Bytes = rec.Bytes
		s.Size = feeds.HumanBytes(rec.Bytes)
		s.SHA256 = rec.SHA256
		if rec.Stale(now, feeds.DefaultMaxAge) {
			s.Stale = true
			out.Stale = append(out.Stale, s.Name)
			refresh = append(refresh, s.Name)
		}
		out.Feeds = append(out.Feeds, s)
	}

	switch {
	case len(refresh) == 0:
		out.Note = "Every feed is cached and current."
		return out
	case len(refresh) == len(feeds.Names()):
		// With no arguments the command fetches every feed, which is the shorter way to say it.
		out.Next = "draugr feeds update"
	default:
		out.Next = "draugr feeds update " + strings.Join(refresh, " ")
	}
	out.Note = "A scan reads this cache and never refreshes it. The command in next reaches the " +
		"network and writes to " + dir + "; give it to the user to run."
	return out
}
