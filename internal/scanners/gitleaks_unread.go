package scanners

import (
	"bufio"
	"bytes"
	"context"
	"io/fs"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/draugr-dev/draugr/internal/toolexec"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// Gitleaks decides by a file's name whether it is an archive, and with no archive depth set it
// skips every file so named without reading it and exits 0. A name counts when it contains `.zip`,
// `.tar`, `.gz` or another archive or compression extension anywhere, so `notes.zip.txt` and
// `release.brief.md` are skipped as surely as `bundle.zip`. The SARIF report says nothing about
// it, so a secret in such a file reads the same as a file with none.
//
// The only record is a line Gitleaks logs at trace level naming the path. So the tree pass runs at
// trace level and its log is read for those lines, each file named reported unread. Reading the
// tool's own account rather than repeating its name rule keeps the answer right when a release
// changes the rule.
//
// What the log says it scanned in bytes is read too. A tree holding a file with content of which
// Gitleaks read nothing, and named no file it skipped, is reported unread at its root, so a skip
// recorded some other way still does not read as a pass.

// gitleaksArchiveSkipped is the message Gitleaks 8.30.1 logs for each file it skips as an archive.
const gitleaksArchiveSkipped = "skipping archive: exceeds max archive depth"

// gitleaksTraceArgs are the arguments that make Gitleaks log the files it skips.
var gitleaksTraceArgs = []string{"--log-level", "trace"}

// gitleaksScanned is the summary Gitleaks logs at the end of a run, with the bytes it read.
var gitleaksScanned = regexp.MustCompile(`\bscanned ~(\d+) bytes\b`)

// ansiEscape is a terminal color sequence. Gitleaks colors its log whether or not stderr is a
// terminal.
var ansiEscape = regexp.MustCompile("\x1b\\[[0-9;]*m")

// gitleaksExec runs a Gitleaks pass and returns its log beside its output. A var so a test can
// substitute it without a Gitleaks on PATH.
var gitleaksExec = func(ctx context.Context, dir string, argv []string) ([]byte, []byte, error) {
	return toolexec.RunWithStderrShown(ctx, dir, argv, nil, gitleaksLogShown)
}

// gitleaksLogShown keeps of a Gitleaks log the lines above debug level, which is what it logs by
// default.
//
// Its trace and debug lines carry the value of each candidate secret it set aside, and Draugr's
// own log and error messages never hold a secret.
func gitleaksLogShown(stderr []byte) []byte {
	var kept []string
	for _, line := range strings.Split(string(stderr), "\n") {
		if level := gitleaksLevel(line); level == "TRC" || level == "DBG" {
			continue
		}
		kept = append(kept, line)
	}
	return []byte(strings.Join(kept, "\n"))
}

// gitleaksLevel returns the level a Gitleaks log line was written at, as it prints it ("TRC",
// "INF"), or "" for a line that names none.
func gitleaksLevel(line string) string {
	fields := strings.Fields(ansiEscape.ReplaceAllString(line, ""))
	if len(fields) < 2 {
		return ""
	}
	switch fields[1] {
	case "TRC", "DBG", "INF", "WRN", "ERR", "FTL", "PNC":
		return fields[1]
	}
	return ""
}

// gitleaksTree runs the tree pass, with what `gitleaks:allow` comments set aside added as
// gitleaksRun does, and returns beside its report the files its log says it did not read.
func gitleaksTree(exec func(ctx context.Context, dir string, argv []string) ([]byte, []byte, error), version func(context.Context) string) func(context.Context, string, []string) ([]byte, []sarif.Input, error) {
	return func(ctx context.Context, dir string, argv []string) ([]byte, []sarif.Input, error) {
		// The first run is the one the report describes. A second, with allow comments ignored,
		// skips the same files.
		var log []byte
		logged := false
		run := func(ctx context.Context, dir string, argv []string) ([]byte, error) {
			out, stderr, err := exec(ctx, dir, argv)
			if !logged {
				log, logged = stderr, true
			}
			return out, err
		}
		out, err := runToReport(ctx, dir, argv, gitleaksRun(run, version))
		if err != nil {
			return nil, nil, err
		}
		return out, gitleaksUnread(log, dir), nil
	}
}

// gitleaksUnread reads a Gitleaks log for the files it skipped as archives, as one unread input
// per file sorted by path, or, where it names none and read nothing from a tree that holds a file
// with content, one for the tree.
func gitleaksUnread(stderr []byte, dir string) []sarif.Input {
	seen := map[string]bool{}
	var out []sarif.Input
	scanned := -1
	sc := bufio.NewScanner(bytes.NewReader(stderr))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := ansiEscape.ReplaceAllString(sc.Text(), "")
		if m := gitleaksScanned.FindStringSubmatch(line); m != nil {
			scanned, _ = strconv.Atoi(m[1])
			continue
		}
		if !strings.Contains(line, gitleaksArchiveSkipped) {
			continue
		}
		path, ok := gitleaksLogPath(line[strings.Index(line, gitleaksArchiveSkipped):])
		if !ok {
			continue
		}
		path = repoRelPath(dir, path)
		if seen[path] {
			continue
		}
		seen[path] = true
		out = append(out, sarif.Input{Path: path, Unread: "skipped as an archive"})
	}
	slices.SortFunc(out, func(a, b sarif.Input) int { return strings.Compare(a.Path, b.Path) })
	if len(out) == 0 && scanned == 0 && holdsContent(dir) {
		out = append(out, sarif.Input{Path: ".", Unread: "no files read"})
	}
	return out
}

// gitleaksLogPath returns the value of the path field in what follows a log line's message.
// Gitleaks quotes a value holding a space, a quote or another character it escapes, and writes any
// other bare.
func gitleaksLogPath(fields string) (string, bool) {
	i := strings.Index(fields, " path=")
	if i < 0 {
		return "", false
	}
	v := fields[i+len(" path="):]
	if strings.HasPrefix(v, `"`) {
		q, err := strconv.QuotedPrefix(v)
		if err != nil {
			return "", false
		}
		p, err := strconv.Unquote(q)
		return p, err == nil
	}
	if j := strings.IndexByte(v, ' '); j >= 0 {
		v = v[:j]
	}
	return v, v != ""
}

// holdsContent reports whether dir holds a regular file with at least one byte, outside .git.
func holdsContent(dir string) bool {
	found := false
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if info, err := d.Info(); err == nil && info.Size() > 0 {
			found = true
			return fs.SkipAll
		}
		return nil
	})
	return found
}
