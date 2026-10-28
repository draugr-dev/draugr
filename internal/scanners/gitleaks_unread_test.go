package scanners

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// The logs under testdata are Gitleaks 8.30.1's stderr at trace level, colors included, for:
//
//   - gitleaks-skipped-archives.log: README.md, notes.zip.txt, bundle.zip (a real zip) and
//     "docs/release notes.tar.md", whose path Gitleaks quotes because it holds a space.
//   - gitleaks-only-archive.log: notes.zip.txt alone, so it scanned ~0 bytes.
//   - gitleaks-nothing-read.log: a zip named `data`, which it skips as a binary file at debug
//     level, and an empty file, so it scanned ~0 bytes and named no archive.
//
// The checkout's path is written as {{dir}}.
func gitleaksLog(t *testing.T, name, dir string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name)) // #nosec G304 -- a fixture this test names
	if err != nil {
		t.Fatal(err)
	}
	return []byte(strings.ReplaceAll(string(raw), "{{dir}}", dir))
}

// gitleaksTreeScanner is the scanner as NewGitleaks builds it, over a checkout at dir, with each
// pass answered by an empty report and the log given.
func gitleaksTreeScanner(dir string, log []byte, calls *[]string) repoScanner {
	s := NewGitleaks().(repoScanner)
	s.checkout = func(context.Context, string, string, git.Scope) (git.Tree, func(), error) {
		return git.Tree{Dir: dir}, func() {}, nil
	}
	s.cacheVersion = nil
	s.runLogged = gitleaksTree(func(_ context.Context, _ string, argv []string) ([]byte, []byte, error) {
		*calls = append(*calls, strings.Join(argv, " "))
		path := argv[slices.Index(argv, "--report-path")+1]
		return nil, log, os.WriteFile(path, []byte(gitleaksReport()), 0o600)
	}, gitleaksVersion("8.30.1"))
	return s
}

// Every file Gitleaks skipped as an archive is named unread, at its path in its own repository,
// whatever else the name holds: a real zip, a text file whose name only contains `.zip`, and a path
// with a space. Two repositories holding the same path, because the path alone would name one file
// where there are two.
func TestGitleaksNamesTheFilesItSkippedAsArchives(t *testing.T) {
	cases := []struct {
		repo, log string
		files     map[string]string
		want      []string
	}{{
		repo: "./api",
		log:  "gitleaks-skipped-archives.log",
		files: map[string]string{
			"README.md": "# Service\n", "notes.zip.txt": "note\n", "bundle.zip": "PK",
			"docs/release notes.tar.md": "note\n",
		},
		want: []string{"bundle.zip", "docs/release notes.tar.md", "notes.zip.txt"},
	}, {
		// Nothing read and one file named: the file is the answer, and the tree is not named too.
		repo:  "./web",
		log:   "gitleaks-only-archive.log",
		files: map[string]string{"notes.zip.txt": "note\n"},
		want:  []string{"notes.zip.txt"},
	}}
	var reports []sarif.Report
	for _, c := range cases {
		dir := writeTree(t, c.files)
		var calls []string
		s := gitleaksTreeScanner(dir, gitleaksLog(t, c.log, dir), &calls)
		rep, err := s.Scan(context.Background(), plugin.RepositoryTarget{URL: c.repo}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(calls) != 2 || !strings.HasSuffix(calls[0], "--log-level trace") {
			t.Errorf("%s: passes %q, want the tree at trace level and again with allow comments ignored", c.repo, calls)
		}
		var got []string
		for _, in := range rep.Inputs {
			if in.Unread != "skipped as an archive" || in.Repository != c.repo || in.Scanner != "gitleaks" {
				t.Errorf("%s: input %+v", c.repo, in)
			}
			got = append(got, in.Path)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: unread %q, want %q", c.repo, got, c.want)
		}
		reports = append(reports, rep)
	}
	merged := sarif.Merge(reports...)
	var named []string
	for _, in := range merged.Inputs {
		if in.Path == "notes.zip.txt" {
			named = append(named, in.Repository)
		}
	}
	slices.Sort(named)
	if !reflect.DeepEqual(named, []string{"./api", "./web"}) {
		t.Errorf("notes.zip.txt named for %q, want each repository", named)
	}
}

// A tree with content of which Gitleaks read nothing, and named nothing it skipped, is named
// unread at its root. A tree with no content to read, and a tree it read, are not.
func TestGitleaksNamesATreeItReadNothingFrom(t *testing.T) {
	nothing := writeTree(t, map[string]string{"data": "PK\x03\x04", "empty.txt": ""})
	if got := gitleaksUnread(gitleaksLog(t, "gitleaks-nothing-read.log", nothing), nothing); !reflect.DeepEqual(got,
		[]sarif.Input{{Path: ".", Unread: "no files read"}}) {
		t.Errorf("a tree with content and 0 bytes read: %+v", got)
	}

	empty := writeTree(t, map[string]string{"empty.txt": "", ".git/HEAD": "ref: refs/heads/main\n"})
	if got := gitleaksUnread(gitleaksLog(t, "gitleaks-nothing-read.log", empty), empty); len(got) != 0 {
		t.Errorf("a tree with nothing to read outside .git: %+v", got)
	}

	read := writeTree(t, map[string]string{"README.md": "# Service\n"})
	clean := "\x1b[90m9:41PM\x1b[0m \x1b[32mINF\x1b[0m \x1b[1mscanned ~10 bytes (10 bytes) in 1.23ms\x1b[0m\n"
	if got := gitleaksUnread([]byte(clean), read); len(got) != 0 {
		t.Errorf("a tree it read: %+v", got)
	}
	// A log without the summary says nothing either way, and is not taken for a tree read empty.
	if got := gitleaksUnread(nil, nothing); len(got) != 0 {
		t.Errorf("no log: %+v", got)
	}
}

// A skip line is read for its path whatever follows it, and a line naming none is passed over.
func TestGitleaksLogPath(t *testing.T) {
	for fields, want := range map[string]string{
		" max_archive_depth=0 path=/c/a.zip":                "/c/a.zip",
		` max_archive_depth=0 path="/c/a b.zip"`:            "/c/a b.zip",
		" path=/c/a.zip max_archive_depth=0":                "/c/a.zip",
		` path="/c/say \"hi\".zip" max_archive_depth=0`:     `/c/say "hi".zip`,
		" max_archive_depth=0":                              "",
		` path="/c/unterminated.zip`:                        "",
		" path=":                                            "",
		" max_archive_depth=0 outer_path=/c/x path=/c/y.gz": "/c/y.gz",
	} {
		got, ok := gitleaksLogPath(fields)
		if got != want || ok != (want != "") {
			t.Errorf("gitleaksLogPath(%q) = %q, %v, want %q", fields, got, ok, want)
		}
	}
}

// What Draugr relays of Gitleaks' log is what Gitleaks logs by default. Its trace and debug lines
// carry each candidate secret it set aside, here a fixture value in the shape it logs them.
func TestGitleaksLogShownKeepsNoTraceOrDebugLine(t *testing.T) {
	log := "\x1b[90m9:41PM\x1b[0m DBG using github.com/wasilibs/go-re2 regex engine\n" +
		"\x1b[90m9:41PM\x1b[0m \x1b[34mTRC\x1b[0m skipping finding: low entropy \x1b[36mfinding=\x1b[0mDRAUGR-FIXTURE-20260101\n" +
		"\x1b[90m9:41PM\x1b[0m \x1b[32mINF\x1b[0m \x1b[1mscanned ~10 bytes (10 bytes) in 1.23ms\x1b[0m\n" +
		"\x1b[90m9:41PM\x1b[0m \x1b[31mERR\x1b[0m could not read file\n" +
		"plain line"
	shown := string(gitleaksLogShown([]byte(log)))
	if strings.Contains(shown, "DRAUGR-FIXTURE") || strings.Contains(shown, "regex engine") {
		t.Errorf("a trace or debug line was kept:\n%s", shown)
	}
	for _, want := range []string{"scanned ~10 bytes", "could not read file", "plain line"} {
		if !strings.Contains(shown, want) {
			t.Errorf("%q was dropped:\n%s", want, shown)
		}
	}
}

// A pass that fails fails the scan, and nothing it logged is read as a skip.
func TestGitleaksTreeReportsAFailedPass(t *testing.T) {
	failed := errors.New("exit status 1")
	run := gitleaksTree(func(context.Context, string, []string) ([]byte, []byte, error) {
		return nil, []byte("anything"), failed
	}, gitleaksVersion("8.30.1"))
	out, inputs, err := run(context.Background(), t.TempDir(), []string{"gitleaks", "dir", ".", "--report-path", ReportPathToken})
	if !errors.Is(err, failed) || out != nil || inputs != nil {
		t.Errorf("out %q inputs %+v err %v, want the failure", out, inputs, err)
	}
}

// NewGitleaks runs the tree pass through the exec that keeps secrets out of Draugr's log.
func TestGitleaksTreeRunsThroughTheFilteredExec(t *testing.T) {
	dir := writeTree(t, map[string]string{"notes.zip.txt": "note\n"})
	prev := gitleaksExec
	t.Cleanup(func() { gitleaksExec = prev })
	var ran int
	gitleaksExec = func(_ context.Context, _ string, argv []string) ([]byte, []byte, error) {
		ran++
		path := argv[slices.Index(argv, "--report-path")+1]
		return nil, gitleaksLog(t, "gitleaks-only-archive.log", dir), os.WriteFile(path, []byte(gitleaksReport()), 0o600)
	}
	s := NewGitleaks().(repoScanner)
	s.checkout = func(context.Context, string, string, git.Scope) (git.Tree, func(), error) {
		return git.Tree{Dir: dir}, func() {}, nil
	}
	rep, err := s.Scan(context.Background(), plugin.RepositoryTarget{URL: "./api"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ran == 0 || len(rep.Inputs) != 1 || rep.Inputs[0].Path != "notes.zip.txt" {
		t.Errorf("exec ran %d times, inputs %+v", ran, rep.Inputs)
	}
}
