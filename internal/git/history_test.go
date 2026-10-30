package git

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/saga"
)

// historyRepo is a repository whose commits name their author and date, built with the
// developer's git configuration shut out so a signing key or a hook cannot decide whether it builds.
type historyRepo struct {
	t   *testing.T
	dir string
}

func newHistoryRepo(t *testing.T) *historyRepo {
	t.Helper()
	r := &historyRepo{t: t, dir: t.TempDir()}
	r.git("", "", "init", "-q", "-b", "main")
	return r
}

// git runs a git command in the repository, as author when one is named.
func (r *historyRepo) git(author, date string, args ...string) string {
	r.t.Helper()
	cmd := exec.Command("git", append([]string{"-C", r.dir, "-c", "commit.gpgsign=false"}, args...)...) // #nosec G204 -- test helper
	env := append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1")
	if author != "" {
		email := strings.ToLower(strings.ReplaceAll(author, " ", ".")) + "@example.com"
		env = append(env,
			"GIT_AUTHOR_NAME="+author, "GIT_AUTHOR_EMAIL="+email, "GIT_AUTHOR_DATE="+date,
			"GIT_COMMITTER_NAME="+author, "GIT_COMMITTER_EMAIL="+email, "GIT_COMMITTER_DATE="+date)
	}
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// write puts content at rel in the work tree.
func (r *historyRepo) write(rel, content string) string {
	r.t.Helper()
	full := filepath.Join(r.dir, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		r.t.Fatal(err)
	}
	return full
}

// commit writes content at rel and commits it as author on date, returning the commit.
func (r *historyRepo) commit(rel, content, author, date string) string {
	r.t.Helper()
	r.write(rel, content)
	r.git("", "", "add", "--", rel)
	r.git(author, date, "commit", "-q", "-m", "change "+rel)
	return r.git("", "", "rev-parse", "HEAD")
}

const (
	firstExclusion  = "config:\n  exclude:\n    - rules: [a]\n      reason: first\n"
	secondExclusion = firstExclusion + "    - rules: [b]\n      reason: second\n"
)

// Each line is attributed to the commit that wrote it, by that commit's author and in that
// author's own offset, and nothing about the author but the name is kept.
func TestLineHistoriesNamesTheCommitThatWroteEachLine(t *testing.T) {
	r := newHistoryRepo(t)
	first := r.commit("draugr.saga.yaml", firstExclusion, "Ada Lovelace", "2026-09-14T10:00:00+02:00")
	second := r.commit("draugr.saga.yaml", secondExclusion, "Grace Hopper", "2026-10-01T09:30:00-05:00")

	got := LineHistories(context.Background(), filepath.Join(r.dir, "draugr.saga.yaml"), []int{3, 5})

	want := map[int]saga.LineHistory{
		3: {Path: "draugr.saga.yaml", Commit: first, Author: "Ada Lovelace", Date: "2026-09-14T10:00:00+02:00"},
		5: {Path: "draugr.saga.yaml", Commit: second, Author: "Grace Hopper", Date: "2026-10-01T09:30:00-05:00"},
	}
	for line, w := range want {
		if got[line] != w {
			t.Errorf("line %d = %+v, want %+v", line, got[line], w)
		}
	}
	for _, h := range got {
		if strings.Contains(h.Author, "@") || strings.Contains(h.Author, "example.com") {
			t.Errorf("an email address reached the history: %+v", h)
		}
	}
	if s := got[3].String(); s != "applied in "+first[:12]+" by Ada Lovelace, 2026-09-14 (git history)" {
		t.Errorf("String() = %q", s)
	}
}

// A file below the repository root is named by its path in the repository, which is what a link
// to the line at a commit needs.
func TestLineHistoriesNamesThePathInTheRepository(t *testing.T) {
	r := newHistoryRepo(t)
	r.commit("ci/policy/draugr.saga-fragment.yaml", firstExclusion, "Ada Lovelace", "2026-09-14T10:00:00Z")

	got := LineHistories(context.Background(), filepath.Join(r.dir, "ci", "policy", "draugr.saga-fragment.yaml"), []int{3})
	if got[3].Path != "ci/policy/draugr.saga-fragment.yaml" || got[3].Commit == "" {
		t.Errorf("got %+v, want the repository path and a commit", got[3])
	}
}

// A shallow clone attributes every line it cannot see past to its boundary commit. That commit's
// author may not have written the line, so the history is reported as unavailable rather than
// named; a line a commit inside the clone changed is still reported.
func TestLineHistoriesRefusesAShallowCloneBoundary(t *testing.T) {
	src := newHistoryRepo(t)
	src.commit("draugr.saga.yaml", firstExclusion, "Ada Lovelace", "2026-09-14T10:00:00Z")
	src.commit("README.md", "readme\n", "Ada Lovelace", "2026-09-15T10:00:00Z")
	second := src.commit("draugr.saga.yaml", secondExclusion, "Grace Hopper", "2026-10-01T10:00:00Z")

	clone := filepath.Join(t.TempDir(), "clone")
	// file:// rather than a path, because git ignores --depth for a local path and clones it whole.
	// #nosec G204 -- fixed argv against directories this test made
	if out, err := exec.Command("git", "clone", "-q", "--depth", "2", "file://"+src.dir, clone).CombinedOutput(); err != nil {
		t.Fatalf("clone: %v\n%s", err, out)
	}

	got := LineHistories(context.Background(), filepath.Join(clone, "draugr.saga.yaml"), []int{3, 5})
	if got[3].Commit != "" || got[3].Unavailable != HistoryShallow {
		t.Errorf("line at the boundary = %+v, want unavailable as %q", got[3], HistoryShallow)
	}
	if got[3].Path != "draugr.saga.yaml" {
		t.Errorf("an unavailable history should still name the path: %+v", got[3])
	}
	if got[5].Commit != second || got[5].Author != "Grace Hopper" {
		t.Errorf("line inside the clone = %+v, want %s by Grace Hopper", got[5], second)
	}
}

// A clone of depth one holds a single commit, which is its own boundary, so no line has a history.
func TestLineHistoriesReportsNothingFromADepthOneClone(t *testing.T) {
	src := newHistoryRepo(t)
	src.commit("draugr.saga.yaml", secondExclusion, "Ada Lovelace", "2026-09-14T10:00:00Z")
	clone := filepath.Join(t.TempDir(), "clone")
	// #nosec G204 -- fixed argv against directories this test made
	if out, err := exec.Command("git", "clone", "-q", "--depth", "1", "file://"+src.dir, clone).CombinedOutput(); err != nil {
		t.Fatalf("clone: %v\n%s", err, out)
	}
	for line, h := range LineHistories(context.Background(), filepath.Join(clone, "draugr.saga.yaml"), []int{3, 5}) {
		if h.Unavailable != HistoryShallow {
			t.Errorf("line %d = %+v, want %q", line, h, HistoryShallow)
		}
	}
}

// An exclusion added in an uncommitted change has no commit yet, and a file never committed has
// none for any line. Neither is attributed to whoever wrote the lines around it.
func TestLineHistoriesRefusesWhatIsNotCommitted(t *testing.T) {
	r := newHistoryRepo(t)
	first := r.commit("draugr.saga.yaml", firstExclusion, "Ada Lovelace", "2026-09-14T10:00:00Z")
	r.write("draugr.saga.yaml", secondExclusion)

	got := LineHistories(context.Background(), filepath.Join(r.dir, "draugr.saga.yaml"), []int{3, 5})
	if got[3].Commit != first {
		t.Errorf("the committed line = %+v, want %s", got[3], first)
	}
	if got[5].Commit != "" || got[5].Unavailable != HistoryLineUncommitted {
		t.Errorf("the uncommitted line = %+v, want %q", got[5], HistoryLineUncommitted)
	}

	untracked := r.write("team.saga-fragment.yaml", firstExclusion)
	for _, h := range LineHistories(context.Background(), untracked, []int{3}) {
		if h.Unavailable != HistoryFileUncommitted || h.Path != "team.saga-fragment.yaml" {
			t.Errorf("an untracked file = %+v, want %q", h, HistoryFileUncommitted)
		}
	}
}

// A repository with no commit at all has nothing to blame against.
func TestLineHistoriesInARepositoryWithNoCommits(t *testing.T) {
	r := newHistoryRepo(t)
	file := r.write("draugr.saga.yaml", firstExclusion)
	if h := LineHistories(context.Background(), file, []int{3})[3]; h.Unavailable != HistoryFileUncommitted {
		t.Errorf("got %+v, want %q", h, HistoryFileUncommitted)
	}
}

func TestLineHistoriesOutsideARepository(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "draugr.saga.yaml")
	if err := os.WriteFile(file, []byte(firstExclusion), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(dir))
	if h := LineHistories(context.Background(), file, []int{3})[3]; h != (saga.LineHistory{Unavailable: HistoryNoRepository}) {
		t.Errorf("got %+v, want %q", h, HistoryNoRepository)
	}
}

func TestLineHistoriesWithoutGit(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if h := LineHistories(context.Background(), "draugr.saga.yaml", []int{3})[3]; h.Unavailable != HistoryNoGit {
		t.Errorf("got %+v, want %q", h, HistoryNoGit)
	}
}

// A failure none of the named reasons covers is reported in git's words, without git's prefix.
func TestLineHistoriesReportsGitsOwnFailure(t *testing.T) {
	r := newHistoryRepo(t)
	file := filepath.Join(r.dir, "draugr.saga.yaml")
	r.commit("draugr.saga.yaml", firstExclusion, "Ada Lovelace", "2026-09-14T10:00:00Z")

	h := LineHistories(context.Background(), file, []int{40})[40]
	if !strings.HasPrefix(h.Unavailable, "git blame failed: ") || strings.Contains(h.Unavailable, "fatal:") {
		t.Errorf("got %q, want git's message after %q", h.Unavailable, "git blame failed: ")
	}
	if !strings.Contains(h.String(), "git history unavailable: git blame failed") {
		t.Errorf("String() = %q", h.String())
	}
}

func TestHistoryFailureSaysWhenGitDidNotAnswer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	<-ctx.Done()
	if got := historyFailure(ctx, "git blame", context.DeadlineExceeded); got != "git blame did not answer within 10s" {
		t.Errorf("got %q", got)
	}
}

// Two files in two repositories are each read against their own history. Grouping by file must
// not collapse them into whichever repository was asked first.
func TestRecordExclusionHistoryReadsEachFileInItsOwnRepository(t *testing.T) {
	app := newHistoryRepo(t)
	appCommit := app.commit("draugr.saga.yaml", secondExclusion, "Ada Lovelace", "2026-09-14T10:00:00Z")
	platform := newHistoryRepo(t)
	platformCommit := platform.commit("policy/shared.saga-fragment.yaml", firstExclusion, "Grace Hopper", "2026-10-01T10:00:00Z")

	rules := []saga.ExcludeRule{
		{Reason: "first", File: filepath.Join(app.dir, "draugr.saga.yaml"), Line: 3},
		{Reason: "second", File: filepath.Join(app.dir, "draugr.saga.yaml"), Line: 5},
		{Reason: "shared", File: filepath.Join(platform.dir, "policy", "shared.saga-fragment.yaml"), Line: 3},
		{Reason: "built in code"},
	}
	RecordExclusionHistory(context.Background(), rules)

	for i, want := range []struct{ commit, author, path string }{
		{appCommit, "Ada Lovelace", "draugr.saga.yaml"},
		{appCommit, "Ada Lovelace", "draugr.saga.yaml"},
		{platformCommit, "Grace Hopper", "policy/shared.saga-fragment.yaml"},
	} {
		h := rules[i].History
		if h == nil || h.Commit != want.commit || h.Author != want.author || h.Path != want.path {
			t.Errorf("rule %d history = %+v, want %+v", i, h, want)
		}
	}
	if rules[3].History != nil {
		t.Errorf("a rule with no file was given a history: %+v", rules[3].History)
	}
}

func TestParseBlameReadsEachRecord(t *testing.T) {
	sha := strings.Repeat("a", 40)
	out := sha + " 2 7 1\nauthor A B\nauthor-mail <a@b>\nauthor-time 1760000000\nauthor-tz -0130\n" +
		"boundary\nfilename x\n\tline\n" +
		strings.Repeat("0", 40) + " 3 9 1\nauthor Not Committed Yet\nauthor-time 1760000000\nauthor-tz +0000\n\tother\n"
	got := parseBlame([]byte(out))
	if got[7].commit != sha || got[7].author != "A B" || got[7].date != "2025-10-09T07:23:20-01:30" {
		t.Errorf("line 7 = %+v", got[7])
	}
	if got[9].commit != strings.Repeat("0", 40) {
		t.Errorf("line 9 = %+v", got[9])
	}
}

func TestAuthorDate(t *testing.T) {
	cases := []struct{ tz, want string }{
		{"+0200", "2025-10-09T10:53:20+02:00"},
		{"bogus", "2025-10-09T08:53:20Z"},
		{"+xx00", "2025-10-09T08:53:20Z"},
	}
	for _, c := range cases {
		if got := authorDate(1760000000, c.tz); got != c.want {
			t.Errorf("authorDate(%q) = %q, want %q", c.tz, got, c.want)
		}
	}
	if got := authorDate(0, "+0000"); got != "" {
		t.Errorf("no time should give no date, got %q", got)
	}
	if _, err := time.Parse(time.RFC3339, authorDate(1760000000, "-0700")); err != nil {
		t.Errorf("not RFC 3339: %v", err)
	}
}
