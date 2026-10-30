package git

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/pkg/saga"
)

// historyTimeout bounds the git calls for one file's history. Blame on a single file of a large
// repository answers in well under a second; past this, the history is reported as unavailable
// rather than holding up the scan it annotates.
const historyTimeout = 10 * time.Second

// Why a line's history is not reported. Each is a reason a reader can act on, and none of them is
// a guess at who wrote the line.
const (
	HistoryNoGit           = "git is not installed"
	HistoryNoRepository    = "the file is in no git repository"
	HistoryFileUncommitted = "the file is not committed"
	HistoryLineUncommitted = "the line is not committed"
	// HistoryShallow is a line git attributes to a shallow clone's boundary commit. The boundary
	// stands in for all the history the clone does not hold, so its author may not have written the
	// line at all.
	HistoryShallow = "the line is older than the shallow clone's history; fetch full history"
)

// RecordExclusionHistory sets each exclusion's History from git blame on the line it starts at,
// one git invocation per file.
//
// Read-only. Nothing here fetches: a shallow clone stays shallow and its boundary is reported as
// such, and a partial clone is not allowed to fetch the objects blame would ask for. A rule with no
// file or line, which is one built in code rather than read from a descriptor, gets no history.
func RecordExclusionHistory(ctx context.Context, rules []saga.ExcludeRule) {
	byFile := map[string][]int{}
	var files []string
	for i, r := range rules {
		if r.File == "" || r.Line <= 0 {
			continue
		}
		if _, ok := byFile[r.File]; !ok {
			files = append(files, r.File)
		}
		byFile[r.File] = append(byFile[r.File], i)
	}
	for _, file := range files {
		lines := make([]int, 0, len(byFile[file]))
		for _, i := range byFile[file] {
			lines = append(lines, rules[i].Line)
		}
		histories := LineHistories(ctx, file, lines)
		for _, i := range byFile[file] {
			h := histories[rules[i].Line]
			rules[i].History = &h
		}
	}
}

// LineHistories reports what git's history says about each of lines in file, keyed by line.
//
// A line's commit is reported only when the history is reliable: the file is committed, the line
// is unchanged since that commit, and the commit is not the boundary of a shallow clone. Every
// other line carries the reason instead.
func LineHistories(ctx context.Context, file string, lines []int) map[int]saga.LineHistory {
	ctx, cancel := context.WithTimeout(ctx, historyTimeout)
	defer cancel()

	out := make(map[int]saga.LineHistory, len(lines))
	all := func(h saga.LineHistory) map[int]saga.LineHistory {
		for _, l := range lines {
			out[l] = h
		}
		return out
	}
	if _, err := exec.LookPath("git"); err != nil {
		return all(saga.LineHistory{Unavailable: HistoryNoGit})
	}
	abs, err := filepath.Abs(file)
	if err != nil {
		abs = file
	}
	dir, base := filepath.Split(abs)

	where, err := historyGit(ctx, dir, "rev-parse", "--show-prefix", "--git-path", "shallow")
	if err != nil {
		if strings.Contains(err.Error(), "not a git repository") {
			return all(saga.LineHistory{Unavailable: HistoryNoRepository})
		}
		return all(saga.LineHistory{Unavailable: historyFailure(ctx, "git rev-parse", err)})
	}
	parts := strings.Split(strings.TrimRight(string(where), "\n"), "\n")
	if len(parts) < 2 {
		return all(saga.LineHistory{Unavailable: "git rev-parse gave no repository path"})
	}
	path := filepath.ToSlash(parts[0] + base)
	shallow := shallowCommits(dir, parts[1])

	args := []string{"blame", "--line-porcelain", "--ignore-revs-file", ""}
	for _, l := range uniqueSorted(lines) {
		args = append(args, "-L", fmt.Sprintf("%d,%d", l, l))
	}
	args = append(args, "--", base)
	blame, err := historyGit(ctx, dir, args...)
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "no such path") || strings.Contains(msg, "no such ref") {
			return all(saga.LineHistory{Path: path, Unavailable: HistoryFileUncommitted})
		}
		return all(saga.LineHistory{Path: path, Unavailable: historyFailure(ctx, "git blame", err)})
	}
	for line, b := range parseBlame(blame) {
		h := saga.LineHistory{Path: path}
		switch {
		case strings.Trim(b.commit, "0") == "":
			// The commit git blame names for a line that differs from the last commit.
			h.Unavailable = HistoryLineUncommitted
		case shallow[b.commit]:
			h.Unavailable = HistoryShallow
		default:
			h.Commit, h.Author, h.Date = b.commit, b.author, b.date
		}
		out[line] = h
	}
	for _, l := range lines {
		if _, ok := out[l]; !ok {
			out[l] = saga.LineHistory{Path: path, Unavailable: "git blame did not report the line"}
		}
	}
	return out
}

// historyGit runs one read-only git command in dir.
//
// The environment shuts out what could make a lookup reach the network or read anything other
// than the repository's own history: a partial clone may not fetch the objects blame asks for,
// replace refs are ignored, and git's messages are in English so the reasons above can be told
// apart.
func historyGit(ctx context.Context, dir string, args ...string) ([]byte, error) {
	full := append([]string{"-C", dir, "-c", "protocol.allow=never"}, args...)
	cmd := exec.CommandContext(ctx, "git", full...) // #nosec G204 -- fixed subcommands; the paths come from the descriptor being scanned
	cmd.Env = append(os.Environ(),
		"LC_ALL=C", "GIT_NO_LAZY_FETCH=1", "GIT_NO_REPLACE_OBJECTS=1", "GIT_TERMINAL_PROMPT=0")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return nil, fmt.Errorf("%w: %s", err, msg)
		}
		return nil, err
	}
	return out, nil
}

// historyFailure words a git call that failed for a reason none of the named ones covers.
func historyFailure(ctx context.Context, what string, err error) string {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Sprintf("%s did not answer within %s", what, historyTimeout)
	}
	msg := err.Error()
	if i := strings.Index(msg, ": "); i >= 0 {
		msg = msg[i+2:]
	}
	if i := strings.IndexByte(msg, '\n'); i >= 0 {
		msg = msg[:i]
	}
	return what + " failed: " + strings.TrimPrefix(msg, "fatal: ")
}

// shallowCommits reads the commits a shallow clone is cut at, which git keeps one per line in the
// file `git rev-parse --git-path shallow` names. A repository with full history has no such file.
func shallowCommits(dir, gitPath string) map[string]bool {
	if !filepath.IsAbs(gitPath) {
		gitPath = filepath.Join(dir, gitPath)
	}
	data, err := os.ReadFile(gitPath) // #nosec G304 -- the path git itself named
	if err != nil {
		return nil
	}
	out := map[string]bool{}
	for _, line := range strings.Fields(string(data)) {
		out[line] = true
	}
	return out
}

// blamed is one line of `git blame --line-porcelain`: the commit and its author, no address.
type blamed struct {
	commit, author, date string
}

// parseBlame reads `git blame --line-porcelain` output, keyed by the line's number in the file.
func parseBlame(out []byte) map[int]blamed {
	result := map[int]blamed{}
	var (
		cur  blamed
		line int
		at   int64
		tz   string
	)
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		text := sc.Text()
		if strings.HasPrefix(text, "\t") {
			// The line's own content ends each record.
			cur.date = authorDate(at, tz)
			result[line] = cur
			cur, line, at, tz = blamed{}, 0, 0, ""
			continue
		}
		key, value, _ := strings.Cut(text, " ")
		switch {
		case line == 0 && (len(key) == 40 || len(key) == 64) && isHex(key):
			// "<commit> <line in the original> <line in the file> [<lines in group>]"
			cur.commit = key
			if fields := strings.Fields(value); len(fields) >= 2 {
				line, _ = strconv.Atoi(fields[1])
			}
		case key == "author":
			cur.author = value
		case key == "author-time":
			at, _ = strconv.ParseInt(value, 10, 64)
		case key == "author-tz":
			tz = value
		}
	}
	return result
}

// authorDate renders a blame record's author time in the author's own offset, as RFC 3339.
func authorDate(unix int64, tz string) string {
	if unix == 0 {
		return ""
	}
	loc := time.UTC
	if len(tz) == 5 {
		hours, errH := strconv.Atoi(tz[1:3])
		minutes, errM := strconv.Atoi(tz[3:5])
		if errH == nil && errM == nil {
			offset := hours*3600 + minutes*60
			if tz[0] == '-' {
				offset = -offset
			}
			loc = time.FixedZone("", offset)
		}
	}
	return time.Unix(unix, 0).In(loc).Format(time.RFC3339)
}

func isHex(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// uniqueSorted returns lines once each, ascending, so a line two exclusions share is asked once.
func uniqueSorted(lines []int) []int {
	seen := map[int]bool{}
	var out []int
	for _, l := range lines {
		if !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	sort.Ints(out)
	return out
}
