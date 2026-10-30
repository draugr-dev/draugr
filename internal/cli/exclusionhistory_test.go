package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// committedRepo is a git repository built with the developer's configuration shut out, whose
// commits name their author.
type committedRepo struct {
	t   *testing.T
	dir string
}

func newCommittedRepo(t *testing.T, dir string) *committedRepo {
	t.Helper()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	r := &committedRepo{t: t, dir: dir}
	r.run("", "init", "-q", "-b", "main")
	return r
}

func (r *committedRepo) run(author string, args ...string) string {
	r.t.Helper()
	cmd := exec.Command("git", append([]string{"-C", r.dir, "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"}, args...)...) // #nosec G204 -- test helper
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME="+author, "GIT_AUTHOR_EMAIL=someone@example.com",
		"GIT_COMMITTER_NAME="+author, "GIT_COMMITTER_EMAIL=someone@example.com",
		"GIT_AUTHOR_DATE=2026-09-14T10:00:00Z", "GIT_COMMITTER_DATE=2026-09-14T10:00:00Z")
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// commit writes the files and commits them as author, returning the commit.
func (r *committedRepo) commit(author string, files map[string]string) string {
	r.t.Helper()
	for rel, body := range files {
		full := filepath.Join(r.dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			r.t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			r.t.Fatal(err)
		}
		r.run("", "add", "--", rel)
	}
	r.run(author, "commit", "-q", "-m", "change")
	return r.run("", "rev-parse", "HEAD")
}

const historySaga = `project: app
release:
  version: "1.0"
components:
  - name: c
    images:
      - image: repo/x:1
config:
  controllers:
    images:
      enabled: true
  exclude:
    - rules: ["R"]
      reason: "accepted for the test"
`

// historySagaWith is the descriptor also naming fragments.
func historySagaWith(fragments string) string {
	return strings.Replace(historySaga, "config:\n", "fragments:\n"+fragments+"config:\n", 1)
}

func exclusionHistory(t *testing.T, path string) []saga.ExcludeRule {
	t.Helper()
	res, err := loadResolved(context.Background(), path, true)
	if err != nil {
		t.Fatalf("loadResolved: %v", err)
	}
	return res.Model.Config.Exclude
}

// Exclusions written in two repositories, the descriptor's and a sibling checkout holding a
// fragment, are each read against their own repository's history.
func TestAScanReadsEachExclusionInItsOwnRepository(t *testing.T) {
	root := t.TempDir()
	app := newCommittedRepo(t, filepath.Join(root, "app"))
	platform := newCommittedRepo(t, filepath.Join(root, "platform"))
	platformCommit := platform.commit("Grace Hopper", map[string]string{
		"policy/shared.saga-fragment.yaml": "config:\n  exclude:\n    - rules: [\"S\"]\n      reason: \"shared\"\n",
	})
	appCommit := app.commit("Ada Lovelace", map[string]string{
		"draugr.saga.yaml": historySagaWith("  - path: ../platform/policy/shared.saga-fragment.yaml\n"),
	})

	rules := exclusionHistory(t, filepath.Join(app.dir, "draugr.saga.yaml"))
	if len(rules) != 2 {
		t.Fatalf("exclusions = %d, want 2", len(rules))
	}
	for i, want := range []struct{ commit, author, path string }{
		{appCommit, "Ada Lovelace", "draugr.saga.yaml"},
		{platformCommit, "Grace Hopper", "policy/shared.saga-fragment.yaml"},
	} {
		h := rules[i].History
		if h == nil || h.Commit != want.commit || h.Author != want.author || h.Path != want.path {
			t.Errorf("exclusion %d history = %+v, want %+v", i, h, want)
		}
	}
}

// A fragment fetched from another repository is cloned whole, because a remote fragment always
// names its revision, so its exclusion carries that repository's history. Read before the fetch's
// checkout is removed, which is the only copy of it on this machine.
func TestAFragmentFromAnotherRepositoryCarriesThatRepositorysHistory(t *testing.T) {
	root := t.TempDir()
	platform := newCommittedRepo(t, filepath.Join(root, "platform"))
	platformCommit := platform.commit("Grace Hopper", map[string]string{
		"policy/shared.saga-fragment.yaml": "config:\n  exclude:\n    - rules: [\"S\"]\n      reason: \"shared\"\n",
	})
	platform.run("", "tag", "v1.0.0")
	app := newCommittedRepo(t, filepath.Join(root, "app"))
	app.commit("Ada Lovelace", map[string]string{
		"draugr.saga.yaml": historySagaWith("  - url: file://" + filepath.ToSlash(platform.dir) +
			"\n    revision: v1.0.0\n    path: policy/shared.saga-fragment.yaml\n"),
	})

	rules := exclusionHistory(t, filepath.Join(app.dir, "draugr.saga.yaml"))
	fetched := rules[1]
	if !strings.Contains(fetched.Source, "platform") {
		t.Fatalf("second exclusion = %+v, want the fetched fragment's", fetched)
	}
	h := fetched.History
	if h == nil || h.Commit != platformCommit || h.Author != "Grace Hopper" || h.Path != "policy/shared.saga-fragment.yaml" {
		t.Errorf("fetched fragment history = %+v, want %s by Grace Hopper at policy/shared.saga-fragment.yaml", h, platformCommit)
	}
}

// A pipeline's default checkout is one commit deep. Every line then dates from the clone's
// boundary, and the report says so rather than naming whoever made that one commit.
func TestAShallowCheckoutReportsNoHistory(t *testing.T) {
	src := newCommittedRepo(t, filepath.Join(t.TempDir(), "src"))
	src.commit("Ada Lovelace", map[string]string{"draugr.saga.yaml": historySaga})
	src.commit("Grace Hopper", map[string]string{"README.md": "readme\n"})

	clone := filepath.Join(t.TempDir(), "clone")
	// #nosec G204 -- fixed argv against directories this test made
	if out, err := exec.Command("git", "clone", "-q", "--depth", "1", "file://"+src.dir, clone).CombinedOutput(); err != nil {
		t.Fatalf("clone: %v\n%s", err, out)
	}
	h := exclusionHistory(t, filepath.Join(clone, "draugr.saga.yaml"))[0].History
	if h == nil || h.Commit != "" || h.Unavailable != git.HistoryShallow {
		t.Errorf("history = %+v, want unavailable as %q", h, git.HistoryShallow)
	}
}

// An exclusion added in a change nobody has committed has no history yet.
func TestAnUncommittedExclusionHasNoHistory(t *testing.T) {
	app := newCommittedRepo(t, filepath.Join(t.TempDir(), "app"))
	app.commit("Ada Lovelace", map[string]string{"draugr.saga.yaml": historySaga})
	path := filepath.Join(app.dir, "draugr.saga.yaml")
	extra := historySaga + "    - rules: [\"T\"]\n      reason: \"added and not committed\"\n"
	if err := os.WriteFile(path, []byte(extra), 0o600); err != nil {
		t.Fatal(err)
	}
	rules := exclusionHistory(t, path)
	if rules[0].History == nil || rules[0].History.Author != "Ada Lovelace" {
		t.Errorf("committed exclusion = %+v", rules[0].History)
	}
	if h := rules[1].History; h == nil || h.Unavailable != git.HistoryLineUncommitted {
		t.Errorf("uncommitted exclusion = %+v, want %q", h, git.HistoryLineUncommitted)
	}
}

// Only a scan asks git. Every other command loads the descriptor without it.
func TestLoadingADescriptorDoesNotReadHistory(t *testing.T) {
	app := newCommittedRepo(t, filepath.Join(t.TempDir(), "app"))
	app.commit("Ada Lovelace", map[string]string{"draugr.saga.yaml": historySaga})
	res, err := loadResolvedCtx(context.Background(), filepath.Join(app.dir, "draugr.saga.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if h := res.Model.Config.Exclude[0].History; h != nil {
		t.Errorf("history = %+v, want none", h)
	}
}

// The whole path: a scan's report.json lists the exclusion with its file, line and history, and
// the finding it set aside names the same file and line in results.sarif.
func TestReportJSONCarriesTheExclusionsHistory(t *testing.T) {
	app := newCommittedRepo(t, filepath.Join(t.TempDir(), "app"))
	commit := app.commit("Ada Lovelace", map[string]string{"draugr.saga.yaml": historySaga})
	path := filepath.Join(app.dir, "draugr.saga.yaml")

	var buf bytes.Buffer
	out := t.TempDir()
	err := runScan(context.Background(), path, scanOptions{
		failOn: "error", format: "json", outputDir: out, noPublish: true,
	}, fakeRegistry(sarif.LevelError), &buf)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	var doc struct {
		Descriptor struct {
			Exclusions []struct {
				Source     string            `json:"source"`
				Line       int               `json:"line"`
				Reason     string            `json:"reason"`
				GitHistory *saga.LineHistory `json:"gitHistory"`
			} `json:"exclusions"`
		} `json:"descriptor"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("report: %v\n%s", err, buf.String())
	}
	ex := doc.Descriptor.Exclusions
	if len(ex) != 1 || ex[0].Source != path || ex[0].Line != 13 || ex[0].Reason != "accepted for the test" {
		t.Fatalf("exclusions = %+v, want one at %s:13", ex, path)
	}
	if h := ex[0].GitHistory; h == nil || h.Commit != commit || h.Author != "Ada Lovelace" || h.Date != "2026-09-14T10:00:00Z" {
		t.Errorf("gitHistory = %+v, want %s by Ada Lovelace", h, commit)
	}
	if strings.Contains(buf.String(), "someone@example.com") {
		t.Error("an author's email address reached the report")
	}

	data, err := os.ReadFile(filepath.Join(out, "results.sarif")) // #nosec G304 -- the directory this test made
	if err != nil {
		t.Fatal(err)
	}
	rep, err := sarif.FromSARIF(data)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, r := range rep.Results {
		if s := r.Suppression; s != nil && s.Source == path && s.Line == 13 {
			found = true
		}
	}
	if !found {
		t.Errorf("no suppressed finding names %s:13 in results.sarif", path)
	}
}
