package engine

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

func repoJob(url string) plugin.ScanJob {
	return plugin.ScanJob{Scanner: "s", Target: plugin.RepositoryTarget{URL: url, Revision: "main"}}
}

// A laptop scanning "." and a pipeline scanning the remote are the same repository, and until the
// remote is resolved they are two unrelated sources that cannot share a cache entry.
func TestResolveRemotesNamesALocalCheckoutByItsRepository(t *testing.T) {
	e := New(NewRegistry(), WithRemoteResolver(func(path string) string {
		if path == "." {
			return "https://github.com/acme/api.git"
		}
		return ""
	}))
	jobs := e.resolveRemotes([]plugin.ScanJob{repoJob(".")})

	got := jobs[0].Target.(plugin.RepositoryTarget)
	if got.Source() != "https://github.com/acme/api.git" {
		t.Errorf("Source() = %q", got.Source())
	}
	// The URL is untouched, because cloning still needs the path it was given.
	if got.URL != "." {
		t.Errorf("URL was rewritten to %q; only the identity should change", got.URL)
	}
	remote := plugin.RepositoryTarget{URL: "https://github.com/acme/api.git", Revision: "main"}
	if got.Identity() != remote.Identity() {
		t.Errorf("a local and a remote scan of one repository still differ:\n  %s\n  %s",
			got.Identity(), remote.Identity())
	}
}

// A repository that exists only on this machine is legitimate, and then the path is the only name
// it has — and the most useful one, since it is where the reader can go and look.
func TestResolveRemotesKeepsThePathWhenThereIsNoRemote(t *testing.T) {
	e := New(NewRegistry(), WithRemoteResolver(func(string) string { return "" }))
	jobs := e.resolveRemotes([]plugin.ScanJob{repoJob("/srv/repos/local-only")})
	if got := jobs[0].Target.(plugin.RepositoryTarget).Source(); got != "/srv/repos/local-only" {
		t.Errorf("Source() = %q, want the path", got)
	}
}

// Not supplying a resolver is how a vendored copy or an air-gapped mirror keeps its path.
func TestResolveRemotesIsOffWithoutAResolver(t *testing.T) {
	e := New(NewRegistry())
	jobs := e.resolveRemotes([]plugin.ScanJob{repoJob(".")})
	if got := jobs[0].Target.(plugin.RepositoryTarget).Remote; got != "" {
		t.Errorf("Remote = %q with no resolver configured", got)
	}
}

// Several components sharing one checkout should ask git once.
func TestResolveRemotesAsksOncePerPath(t *testing.T) {
	calls := 0
	e := New(NewRegistry(), WithRemoteResolver(func(string) string {
		calls++
		return "https://git/x.git"
	}))
	e.resolveRemotes([]plugin.ScanJob{repoJob("."), repoJob("."), repoJob(".")})
	if calls != 1 {
		t.Errorf("resolver called %d times for one path", calls)
	}
}

// Anything that is not a repository passes through untouched.
func TestResolveRemotesIgnoresOtherTargets(t *testing.T) {
	e := New(NewRegistry(), WithRemoteResolver(func(string) string { return "https://git/x.git" }))
	jobs := e.resolveRemotes([]plugin.ScanJob{{Scanner: "s", Target: plugin.ImageTarget{Ref: "alpine:3"}}})
	if _, ok := jobs[0].Target.(plugin.ImageTarget); !ok {
		t.Error("an image target was rewritten")
	}
}
