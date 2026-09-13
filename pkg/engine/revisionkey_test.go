package engine

import (
	"context"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// treeScanner reads a tree, which is what every scanner but one does.
type treeScanner struct{ name string }

func (t treeScanner) Info() plugin.ScannerInfo { return plugin.ScannerInfo{Name: t.name} }
func (t treeScanner) Scan(context.Context, plugin.Target, plugin.Config) (sarif.Report, error) {
	return sarif.Report{Tool: t.name}, nil
}

// historyScanner reads the commit history, which is Gitleaks in history mode.
type historyScanner struct{ treeScanner }

func (historyScanner) ReadsHistory(plugin.Config) bool { return true }

// The identity of a scoped job is the content of the part it reads.
//
// A pruned checkout is all the scanner can see, so a key naming the whole repository names content
// the job could not read. In a monorepo that is the difference between a commit touching one
// component invalidating that component and invalidating all of them.
func TestAScopedJobIsKeyedOnItsOwnSubtree(t *testing.T) {
	e := New(NewRegistry(), WithTreeResolver(
		func(_ context.Context, _, commit string, paths []string) (string, error) {
			return "tree-of-" + paths[0] + "-at-" + commit, nil
		}))

	job := plugin.ScanJob{
		Scanner: "s",
		Target:  plugin.RepositoryTarget{URL: "/repo", Paths: []string{"services/payments"}},
	}
	got := e.revisionKey(context.Background(), treeScanner{"s"}, job, "abc123")
	if want := "tree-of-services/payments-at-abc123"; got != want {
		t.Errorf("revisionKey = %q, want %q", got, want)
	}
}

// A job that reads history keeps the commit, because two commits can carry an identical tree and
// different history. A revert of a revert, or an empty commit, and a tree key would serve one
// run's answer to the other.
func TestAHistoryReadingJobKeepsTheCommit(t *testing.T) {
	e := New(NewRegistry(), WithTreeResolver(
		func(context.Context, string, string, []string) (string, error) { return "a-tree", nil }))

	job := plugin.ScanJob{
		Scanner: "gitleaks",
		Target:  plugin.RepositoryTarget{URL: "/repo", Paths: []string{"services/payments"}},
	}
	if got := e.revisionKey(context.Background(), historyScanner{treeScanner{"gitleaks"}}, job, "abc123"); got != "abc123" {
		t.Errorf("revisionKey = %q, want the commit: a tree cannot tell two histories apart", got)
	}
}

// Everything that cannot be narrowed keeps what it had, so this is an improvement on the old key
// rather than a replacement for it.
func TestTheCommitStandsWhereNoSubtreeCanBeRead(t *testing.T) {
	tree := func(context.Context, string, string, []string) (string, error) { return "a-tree", nil }
	scoped := plugin.RepositoryTarget{URL: "/repo", Paths: []string{"svc"}}

	for _, tc := range []struct {
		name   string
		engine *Engine
		job    plugin.ScanJob
		commit string
		want   string
	}{
		{
			// An unscoped job's subtree is the whole tree, which the commit already names exactly.
			"an unscoped job", New(NewRegistry(), WithTreeResolver(tree)),
			plugin.ScanJob{Target: plugin.RepositoryTarget{URL: "/repo"}}, "abc123", "abc123",
		},
		{
			"a target that is not a repository", New(NewRegistry(), WithTreeResolver(tree)),
			plugin.ScanJob{Target: plugin.ImageTarget{Ref: "alpine:1"}}, "abc123", "abc123",
		},
		{
			"no resolver wired", New(NewRegistry()),
			plugin.ScanJob{Target: scoped}, "abc123", "abc123",
		},
		{
			// A remote repository, a path absent at this commit, a repository git will not read.
			"a resolver that cannot answer", New(NewRegistry(), WithTreeResolver(
				func(context.Context, string, string, []string) (string, error) { return "", nil })),
			plugin.ScanJob{Target: scoped}, "abc123", "abc123",
		},
		{
			// Nothing to pin to, and nothing to narrow.
			"no commit", New(NewRegistry(), WithTreeResolver(tree)),
			plugin.ScanJob{Target: scoped}, "", "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.engine.revisionKey(context.Background(), treeScanner{"s"}, tc.job, tc.commit); got != tc.want {
				t.Errorf("revisionKey = %q, want %q", got, tc.want)
			}
		})
	}
}

// A resolver that fails is not a reason to lose the pinning altogether.
func TestAFailingTreeResolverFallsBackToTheCommit(t *testing.T) {
	e := New(NewRegistry(), WithTreeResolver(
		func(context.Context, string, string, []string) (string, error) {
			return "", context.DeadlineExceeded
		}))
	job := plugin.ScanJob{Target: plugin.RepositoryTarget{URL: "/repo", Paths: []string{"svc"}}}
	if got := e.revisionKey(context.Background(), treeScanner{"s"}, job, "abc123"); got != "abc123" {
		t.Errorf("revisionKey = %q, want the commit", got)
	}
}
