package scanners

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A file is text when it holds no NUL byte in the part git reads to decide, and a file that is
// missing, a directory or a link is not read as one.
func TestIsTextFile(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"notes.brief.md": "note\n",
		"empty.tar.md":   "",
		"bundle.zip":     "PK\x03\x04\x00",
		"late.tar.md":    strings.Repeat("a", gitleaksBinarySniff) + "\x00",
	})
	if err := os.Symlink(filepath.Join(dir, "notes.brief.md"), filepath.Join(dir, "link.tar.md")); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]bool{
		"notes.brief.md": true, "empty.tar.md": true, "late.tar.md": true,
		"bundle.zip": false, "link.tar.md": false, "missing.tar.md": false, ".": false,
	} {
		if got := isTextFile(filepath.Join(dir, name)); got != want {
			t.Errorf("%s: text %v, want %v", name, got, want)
		}
	}
}

// Of the files left unread for an archive's name, the text ones are read; a real archive, a file
// unread for another reason and a path outside the checkout stay as they were.
func TestGitleaksNamedTextSplitsTextFromTheRest(t *testing.T) {
	dir := writeTree(t, map[string]string{"notes.brief.md": "note\n", "bundle.zip": "PK\x03\x04\x00"})
	unread := []sarif.Input{
		{Path: "bundle.zip", Unread: gitleaksArchiveReason},
		{Path: "notes.brief.md", Unread: gitleaksArchiveReason},
		{Path: ".", Unread: "no files read"},
		{Path: "../outside.tar.md", Unread: gitleaksArchiveReason},
	}
	text, rest := gitleaksNamedText(dir, unread)
	if !reflect.DeepEqual(text, []string{"notes.brief.md"}) {
		t.Errorf("text %q, want notes.brief.md", text)
	}
	var kept []string
	for _, in := range rest {
		kept = append(kept, in.Path)
	}
	if !reflect.DeepEqual(kept, []string{"bundle.zip", ".", "../outside.tar.md"}) {
		t.Errorf("rest %q", kept)
	}
}

// The scratch run is the tree pass's, in git mode, without the trace level.
func TestGitleaksScratchArgs(t *testing.T) {
	tree := gitleaksArgs("/checkout", nil)
	got := gitleaksScratchArgs(tree)
	want := slices.Clone(tree[:len(tree)-len(gitleaksTraceArgs)])
	want[1] = "git"
	if !reflect.DeepEqual(got, want) {
		t.Errorf("argv %q, want %q", got, want)
	}
	if tree[1] != "dir" {
		t.Error("the tree pass's argv was changed")
	}
}

// A git-mode result reads as the tree pass's: no commit, author, date or message, and a message
// that names no commit.
func TestGitleaksAsTreeTakesTheScratchCommitOff(t *testing.T) {
	report := `{"runs":[{"results":[{"ruleId":"private-key",` +
		`"message":{"text":"private-key has detected secret for file notes.brief.md at commit f355564939f780605a641d75fa394b63d53ec6e3."},` +
		`"partialFingerprints":{"commitSha":"f355564939f780605a641d75fa394b63d53ec6e3","email":"draugr@localhost","author":"draugr","date":"2026-11-23T10:04:49Z","commitMessage":"scratch"}}]}]}`
	got, err := gitleaksAsTree([]byte(report))
	if err != nil || len(got) != 1 {
		t.Fatalf("results %d, err %v", len(got), err)
	}
	var r struct {
		Message             struct{ Text string }
		PartialFingerprints map[string]string
	}
	if err := json.Unmarshal(got[0], &r); err != nil {
		t.Fatal(err)
	}
	if r.Message.Text != "private-key has detected secret for file notes.brief.md." {
		t.Errorf("message %q", r.Message.Text)
	}
	for k, v := range r.PartialFingerprints {
		if v != "" {
			t.Errorf("%s = %q, want blank", k, v)
		}
	}
	if _, err := gitleaksAsTree([]byte("not json")); err == nil {
		t.Error("a report that is not JSON was read")
	}
}

// The scratch repository holds the text files committed at their paths and the checkout's
// .gitleaksignore beside them uncommitted, readable by this user alone, and is gone once the run
// ends, a failed run included. A user's own git hooks and signing setup neither run nor fail it.
func TestGitleaksReadNamedCommitsTheFilesInAScratchRepository(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	home := t.TempDir()
	hooks := filepath.Join(home, "hooks")
	if err := os.MkdirAll(hooks, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hooks, "pre-commit"), []byte("#!/bin/sh\nexit 1\n"), 0o700); err != nil { // #nosec G306 -- a hook must be executable
		t.Fatal(err)
	}
	gitconfig := "[core]\n\thooksPath = " + hooks + "\n[commit]\n\tgpgsign = true\n[gpg]\n\tprogram = /nonexistent\n"
	if err := os.WriteFile(filepath.Join(home, ".gitconfig"), []byte(gitconfig), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)

	dir := writeTree(t, map[string]string{
		"docs/notes.brief.md": "note\n",
		".gitleaksignore":     "docs/notes.brief.md:private-key:1\n",
	})
	failed := errors.New("gitleaks failed")
	var scratch string
	var tracked, ignore string
	var mode os.FileMode
	run := func(_ context.Context, d string, argv []string) ([]byte, error) {
		scratch = d
		if info, err := os.Stat(d); err == nil {
			mode = info.Mode().Perm()
		}
		out, err := exec.Command("git", "-C", d, "ls-files").Output() // #nosec G204 -- the scratch directory this test was handed
		if err != nil {
			t.Fatal(err)
		}
		tracked = strings.TrimSpace(string(out))
		b, _ := os.ReadFile(filepath.Join(d, ".gitleaksignore")) // #nosec G304 -- the scratch directory
		ignore = string(b)
		if argv[1] != "git" {
			t.Errorf("argv %q, want git mode", argv)
		}
		return nil, failed
	}
	_, err := gitleaksReadNamed(context.Background(), dir, gitleaksArgs(dir, nil), []string{"docs/notes.brief.md"}, run)
	if !errors.Is(err, failed) {
		t.Fatalf("err %v, want the run's failure", err)
	}
	if tracked != "docs/notes.brief.md" || ignore == "" {
		t.Errorf("committed %q, .gitleaksignore %q; want the file committed and the ignore file beside it", tracked, ignore)
	}
	if mode != 0o700 {
		t.Errorf("scratch mode %v, want 0700", mode)
	}
	if strings.HasPrefix(scratch, dir) {
		t.Errorf("scratch %s is inside the checkout", scratch)
	}
	if _, err := os.Stat(scratch); !os.IsNotExist(err) {
		t.Errorf("scratch %s left behind after a failed run: %v", scratch, err)
	}
}

// A file that cannot be copied, or a repository git cannot make, fails the read rather than
// reporting nothing found.
func TestGitleaksReadNamedFailsLoudly(t *testing.T) {
	dir := writeTree(t, map[string]string{"notes.brief.md": "note\n"})
	run := func(context.Context, string, []string) ([]byte, error) { return nil, nil }
	if _, err := gitleaksReadNamed(context.Background(), dir, gitleaksArgs(dir, nil), []string{"gone.tar.md"}, run); err == nil {
		t.Error("a file that is gone was read")
	}
	if _, err := gitleaksReadNamed(context.Background(), dir, gitleaksArgs(dir, nil), []string{"../outside.tar.md"}, run); err == nil {
		t.Error("a path outside the checkout was copied")
	}
	t.Setenv("PATH", t.TempDir())
	if _, err := gitleaksReadNamed(context.Background(), dir, gitleaksArgs(dir, nil), []string{"notes.brief.md"}, run); err == nil {
		t.Error("a repository was made with no git")
	}
}

// The tree pass reads the text files it skipped in a second run and reports what that run found,
// at the file's path; a real archive stays unread. When the second run cannot be made, the files
// stay listed unread, as the tree pass left them.
func TestGitleaksTreeReadsTheTextFilesItSkipped(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	dir := writeTree(t, map[string]string{"notes.zip.txt": "note\n", "bundle.zip": "PK\x03\x04\x00"})
	log := []byte("10:00AM TRC skipping archive: exceeds max archive depth max_archive_depth=0 path=bundle.zip\n" +
		"10:00AM TRC skipping archive: exceeds max archive depth max_archive_depth=0 path=notes.zip.txt\n" +
		"10:00AM INF scanned ~0 bytes (0 bytes) in 1ms\n")
	scratchReport := `{"runs":[{"tool":{"driver":{"name":"gitleaks"}},"results":[{"ruleId":"private-key","level":"error",` +
		`"message":{"text":"private-key has detected secret for file notes.zip.txt at commit 0123456."},` +
		`"locations":[{"physicalLocation":{"artifactLocation":{"uri":"notes.zip.txt"},"region":{"startLine":1}}}],` +
		`"partialFingerprints":{"commitSha":"0123456"}}]}]}`
	var passes []string
	tree := gitleaksTree(func(_ context.Context, _ string, argv []string) ([]byte, []byte, error) {
		passes = append(passes, argv[1])
		path := argv[slices.Index(argv, "--report-path")+1]
		report := gitleaksReport()
		if argv[1] == "git" {
			report = scratchReport
		}
		return nil, log, os.WriteFile(path, []byte(report), 0o600)
	}, gitleaksVersion("8.30.1"))
	out, inputs, err := tree(context.Background(), dir, gitleaksArgs(dir, nil))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(passes, []string{"dir", "dir", "git", "git"}) {
		t.Errorf("passes %q, want the tree twice and the scratch repository twice", passes)
	}
	if len(inputs) != 1 || inputs[0].Path != "bundle.zip" {
		t.Errorf("unread %+v, want only bundle.zip", inputs)
	}
	if !strings.Contains(string(out), `"uri":"notes.zip.txt"`) || strings.Contains(string(out), "at commit") ||
		strings.Contains(string(out), "0123456") {
		t.Errorf("report %s, want the finding at notes.zip.txt with no commit", out)
	}

	t.Setenv("PATH", t.TempDir())
	_, inputs, err = tree(context.Background(), dir, gitleaksArgs(dir, nil))
	if err != nil {
		t.Fatal(err)
	}
	var unread []string
	for _, in := range inputs {
		unread = append(unread, in.Path)
	}
	if !reflect.DeepEqual(unread, []string{"bundle.zip", "notes.zip.txt"}) {
		t.Errorf("with no git, unread %q, want both as the tree pass left them", unread)
	}
}
