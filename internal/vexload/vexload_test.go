package vexload

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/saga"
)

const doc = `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://acme.example/vex/1",
  "author": "Acme Ltd",
  "timestamp": "2026-08-01T09:00:00Z",
  "statements": [
    {"vulnerability": {"name": "CVE-2024-1"}, "status": "not_affected",
     "products": [{"@id": "pkg:oci/acme", "subcomponents": [{"@id": "pkg:pypi/flask@0.12.2"}]}]}
  ]
}`

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func fixedClock() func() time.Time {
	return func() time.Time { return time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC) }
}

func TestAPathSourceIsReadAndFingerprinted(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "acme.json", doc)
	l := &Loader{Now: fixedClock()}

	set, err := l.Load(context.Background(), &saga.Model{
		Components: []saga.Component{{Name: "api", VEX: []saga.VEXSource{{Path: path}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := set.ByComponent["api"]
	if len(got) != 1 {
		t.Fatalf("resolved %d documents, want 1", len(got))
	}
	p := got[0].Provenance
	if p.Kind != "path" {
		t.Errorf("kind = %q, want path", p.Kind)
	}
	// The digest is what lets two runs be compared without the document, and the read time is
	// what distinguishes a fresh copy from a fresh claim.
	if !strings.HasPrefix(p.Digest, "sha256:") || len(p.Digest) != len("sha256:")+64 {
		t.Errorf("digest = %q, want a sha256", p.Digest)
	}
	if p.ReadAt.IsZero() || p.Author != "Acme Ltd" || p.Timestamp != "2026-08-01T09:00:00Z" {
		t.Errorf("provenance = %+v, want it to carry who, when read and when asserted", p)
	}
	if p.Statements != 1 {
		t.Errorf("statements = %d, want 1", p.Statements)
	}
}

func TestAURLSourceIsFetched(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(doc))
	}))
	defer srv.Close()

	l := &Loader{Client: srv.Client(), Now: fixedClock()}
	set, err := l.Load(context.Background(), &saga.Model{
		Config: saga.Config{VEXSources: []saga.VEXSource{{URL: srv.URL}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Project) != 1 {
		t.Fatalf("resolved %d project documents, want 1", len(set.Project))
	}
	if got := set.Project[0].Provenance; got.Kind != "url" || got.Location != srv.URL {
		t.Errorf("provenance = %+v, want the URL recorded", got)
	}
}

// A source that cannot be read fails the run. A scan that quietly dropped a supplier's analysis
// would report more findings than the last one with nothing saying why, which reads exactly like
// a codebase that got worse.
func TestASourceThatCannotBeReadIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cases := []struct {
		name string
		src  saga.VEXSource
		want string
	}{
		{"missing file", saga.VEXSource{Path: filepath.Join(t.TempDir(), "absent.json")}, "absent.json"},
		{"404", saga.VEXSource{URL: srv.URL}, "404"},
		{"nothing named", saga.VEXSource{}, "names no path"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l := &Loader{Client: srv.Client(), Now: fixedClock()}
			_, err := l.Load(context.Background(), &saga.Model{
				Components: []saga.Component{{Name: "api", VEX: []saga.VEXSource{c.src}}},
			})
			if err == nil {
				t.Fatal("expected an error rather than a silently dropped source")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %v, want it to mention %q", err, c.want)
			}
			// And it says which component and which entry, so a descriptor with several is
			// fixable without bisecting it.
			if !strings.Contains(err.Error(), `component "api"`) {
				t.Errorf("error = %v, want it to name the component", err)
			}
		})
	}
}

// Every bad source is reported, not just the first: whoever fixes them is going to fix them
// together.
func TestEveryUnreadableSourceIsReported(t *testing.T) {
	dir := t.TempDir()
	l := &Loader{Now: fixedClock()}
	_, err := l.Load(context.Background(), &saga.Model{
		Config: saga.Config{VEXSources: []saga.VEXSource{{Path: filepath.Join(dir, "one.json")}}},
		Components: []saga.Component{{Name: "api", VEX: []saga.VEXSource{
			{Path: filepath.Join(dir, "two.json")},
			{Path: filepath.Join(dir, "three.json")},
		}}},
	})
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, want := range []string{"one.json", "two.json", "three.json"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to mention %q", err, want)
		}
	}
}

func TestARepositorySourceReadsTheFileAndRecordsTheCommit(t *testing.T) {
	repo := t.TempDir()
	write(t, repo, "acme.json", doc)

	l := &Loader{
		Now: fixedClock(),
		Checkout: func(_ context.Context, url, ref string) (string, string, func(), error) {
			if url != "https://git.example/acme" || ref != "v1" {
				t.Errorf("checkout(%q, %q), want the descriptor's url and ref", url, ref)
			}
			return repo, "abc123", func() {}, nil
		},
	}
	set, err := l.Load(context.Background(), &saga.Model{
		Components: []saga.Component{{Name: "api", VEX: []saga.VEXSource{{
			Repository: &saga.VEXRepository{URL: "https://git.example/acme", Ref: "v1", Path: "acme.json"},
		}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	p := set.ByComponent["api"][0].Provenance
	if p.Kind != "repository" {
		t.Errorf("kind = %q, want repository", p.Kind)
	}
	// The resolved commit is what makes a run reproducible when the descriptor named a branch.
	if p.Revision != "abc123" {
		t.Errorf("revision = %q, want the commit actually read", p.Revision)
	}
	if !strings.Contains(p.Location, "acme.json") {
		t.Errorf("location = %q, want it to name the document", p.Location)
	}
}

// A path climbing out of the checkout would read a file from the machine running the scan while
// looking like it came from the supplier.
func TestARepositoryPathCannotEscapeTheCheckout(t *testing.T) {
	repo := t.TempDir()
	outside := filepath.Dir(repo)
	write(t, outside, "secret.json", doc)

	l := &Loader{
		Now: fixedClock(),
		Checkout: func(context.Context, string, string) (string, string, func(), error) {
			return repo, "c", func() {}, nil
		},
	}
	_, err := l.Load(context.Background(), &saga.Model{
		Components: []saga.Component{{Name: "api", VEX: []saga.VEXSource{{
			Repository: &saga.VEXRepository{URL: "u", Path: "../secret.json"},
		}}}},
	})
	if err == nil || !strings.Contains(err.Error(), "escapes the repository") {
		t.Errorf("error = %v, want the escape refused", err)
	}
}

func TestACloneFailureNamesTheRepository(t *testing.T) {
	l := &Loader{
		Now: fixedClock(),
		Checkout: func(context.Context, string, string) (string, string, func(), error) {
			return "", "", func() {}, os.ErrPermission
		},
	}
	_, err := l.Load(context.Background(), &saga.Model{
		Components: []saga.Component{{Name: "api", VEX: []saga.VEXSource{{
			Repository: &saga.VEXRepository{URL: "https://git.example/acme", Path: "a.json"},
		}}}},
	})
	if err == nil || !strings.Contains(err.Error(), "git.example/acme") {
		t.Errorf("error = %v, want it to name the repository", err)
	}
}

// A URL answering with something other than a document — a login page, a tarball — fails as a
// size rather than being parsed as JSON for however long that takes.
func TestAnOversizedResponseIsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		chunk := strings.Repeat("x", 1<<20)
		for range (maxDocument >> 20) + 1 {
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	l := &Loader{Client: srv.Client(), Now: fixedClock()}
	_, err := l.Load(context.Background(), &saga.Model{
		Config: saga.Config{VEXSources: []saga.VEXSource{{URL: srv.URL}}},
	})
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("error = %v, want the oversized response refused by size", err)
	}
}

func TestNoSourcesResolvesToAnEmptySet(t *testing.T) {
	l := &Loader{Now: fixedClock()}
	set, err := l.Load(context.Background(), &saga.Model{
		Components: []saga.Component{{Name: "api"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !set.Empty() {
		t.Errorf("set = %+v, want it empty", set)
	}
}

// The default clock and client exist so the zero value works; exercised so a nil field cannot
// panic in production where a test always supplies one.
func TestTheZeroLoaderWorks(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "acme.json", doc)
	set, err := (&Loader{}).Load(context.Background(), &saga.Model{
		Config: saga.Config{VEXSources: []saga.VEXSource{{Path: path}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Project) != 1 || set.Project[0].Provenance.ReadAt.IsZero() {
		t.Errorf("set = %+v, want a document read with a real clock", set)
	}
}

// A URL that answers with something that is not a document fails as a parse rather than being
// accepted as a document with nothing to say.
func TestAURLServingSomethingElseIsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>sign in</html>"))
	}))
	defer srv.Close()

	l := &Loader{Client: srv.Client(), Now: fixedClock()}
	_, err := l.Load(context.Background(), &saga.Model{
		Config: saga.Config{VEXSources: []saga.VEXSource{{URL: srv.URL}}},
	})
	if err == nil || !strings.Contains(err.Error(), "not a readable OpenVEX document") {
		t.Errorf("error = %v, want the response refused as unparseable", err)
	}
}

// An unreachable host is an error naming the source, not a run that quietly carried on.
func TestAnUnreachableURLIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // nothing is listening now

	l := &Loader{Now: fixedClock()}
	_, err := l.Load(context.Background(), &saga.Model{
		Config: saga.Config{VEXSources: []saga.VEXSource{{URL: url}}},
	})
	if err == nil {
		t.Fatal("expected an error for an unreachable source")
	}
	if !strings.Contains(err.Error(), "config.vexSources[0]") {
		t.Errorf("error = %v, want it to name which source", err)
	}
}

// A document present in the repository but unreadable names the path inside it, rather than
// reporting a clone that appeared to work and produced nothing.
func TestAMissingFileInsideTheRepositoryNamesThePath(t *testing.T) {
	repo := t.TempDir()
	l := &Loader{
		Now: fixedClock(),
		Checkout: func(context.Context, string, string) (string, string, func(), error) {
			return repo, "c", func() {}, nil
		},
	}
	_, err := l.Load(context.Background(), &saga.Model{
		Components: []saga.Component{{Name: "api", VEX: []saga.VEXSource{{
			Repository: &saga.VEXRepository{URL: "u", Path: "vex/absent.json"},
		}}}},
	})
	if err == nil || !strings.Contains(err.Error(), "vex/absent.json") {
		t.Errorf("error = %v, want it to name the path inside the repository", err)
	}
}
