package cli

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// gitRepo makes a repository with one commit and the given directories in it, and returns its root
// as git reports it, with symlinks resolved.
func gitRepo(t *testing.T, dirs ...string) string {
	t.Helper()
	root := t.TempDir()
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(root, d), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, d, "f.txt"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{
		{"init", "-q", "-b", "main"},
		{"-c", "user.email=t@example.com", "-c", "user.name=T", "commit", "-q", "--allow-empty", "-m", "init"},
	} {
		if out, err := exec.Command("git", append([]string{"-C", root}, args...)...).CombinedOutput(); err != nil { // #nosec G204 -- test fixture
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

// Two components in two directories of one checkout, a third at its root, and a remote: the first
// two are cloned from the root and scoped to their directories, with the paths and ignore patterns
// they wrote moved under them; the root and the remote are left as written.
func TestRootLocalRepositoriesScopesEachDirectory(t *testing.T) {
	root := gitRepo(t, "services/payments", "services/web")
	m := &saga.Model{Components: []saga.Component{
		{Name: "payments", Repositories: []saga.Repository{{URL: filepath.Join(root, "services/payments")}}},
		{Name: "web", Repositories: []saga.Repository{{
			URL:    filepath.Join(root, "services/web"),
			Paths:  []string{"src", "go.mod"},
			Ignore: []string{"src/testdata/", "*.gen.go"},
		}}},
		{Name: "all", Repositories: []saga.Repository{{URL: root}}},
		{Name: "upstream", Repositories: []saga.Repository{{URL: "https://github.com/acme/lib"}}},
	}}
	rootLocalRepositories(context.Background(), m)

	want := [][]saga.Repository{
		{{URL: root, Paths: []string{"services/payments"}}},
		{{URL: root, Paths: []string{"services/web/src", "services/web/go.mod"},
			Ignore: []string{"services/web/src/testdata/", "services/web/*.gen.go"}}},
		{{URL: root}},
		{{URL: "https://github.com/acme/lib"}},
	}
	for i, c := range m.Components {
		got := c.Repositories[0]
		w := want[i][0]
		if got.URL != w.URL || !slices.Equal(got.Paths, w.Paths) || !slices.Equal(got.Ignore, w.Ignore) {
			t.Errorf("%s: got %+v, want %+v", c.Name, got, w)
		}
	}
}

// targetRecorder is a repository control that records the targets the engine hands its scanner.
type targetRecorder struct {
	mu      sync.Mutex
	targets []plugin.RepositoryTarget
}

func (*targetRecorder) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: "secrets", Scope: plugin.ScopeComponent}
}

func (*targetRecorder) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	var jobs []plugin.ScanJob
	for _, r := range comp.Repositories {
		jobs = append(jobs, plugin.ScanJob{Scanner: "recorder",
			Target: plugin.RepositoryTarget{URL: r.URL, Paths: r.Paths, Ignore: r.Ignore}})
	}
	return jobs, nil
}

func (*targetRecorder) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	return plugin.ControlResult{Control: "secrets", Report: sarif.Merge(reports...)}, nil
}

func (r *targetRecorder) Scan(_ context.Context, target plugin.Target, _ plugin.Config) (sarif.Report, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.targets = append(r.targets, target.(plugin.RepositoryTarget))
	return sarif.Report{Tool: "recorder"}, nil
}

type recorderScanner struct{ *targetRecorder }

func (recorderScanner) Info() plugin.ScannerInfo { return plugin.ScannerInfo{Name: "recorder"} }

// A descriptor naming two directories of one checkout reaches the scanners as the checkout's root,
// scoped to each directory, which is what makes the clone succeed.
func TestRunScanClonesADirectoryFromItsRoot(t *testing.T) {
	root := gitRepo(t, "services/payments", "services/web")
	rec := &targetRecorder{}
	reg := engine.NewRegistry()
	reg.RegisterController(rec)
	reg.RegisterScanner(recorderScanner{rec})
	path := writeSaga(t, `
project: shop
config:
  controls:
    secrets: {}
components:
  - name: payments
    repositories: [{url: "`+filepath.Join(root, "services/payments")+`"}]
  - name: web
    repositories: [{url: "`+filepath.Join(root, "services/web")+`"}]
`)
	var buf bytes.Buffer
	if err := runScan(context.Background(), path, scanOptions{format: "json", noGate: true}, reg, &buf); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, tg := range rec.targets {
		if tg.URL != root {
			t.Errorf("target URL = %s, want the root %s", tg.URL, root)
		}
		got = append(got, tg.Paths...)
	}
	slices.Sort(got)
	if want := []string{"services/payments", "services/web"}; !slices.Equal(got, want) {
		t.Errorf("paths = %v, want %v", got, want)
	}
}

// A path that does not exist is said to not exist, and not handed to the loader, whose message
// would end by suggesting `draugr validate` on the same missing file.
func TestScanOfAMissingPathSaysItDoesNotExist(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "draugr.saga.yaml")
	err := runScan(context.Background(), missing, scanOptions{format: "json"}, engine.NewRegistry(), &bytes.Buffer{})
	if err == nil || err.Error() != missing+" does not exist" {
		t.Errorf("err = %v, want %q", err, missing+" does not exist")
	}
}

// A relative url resolves against where Draugr runs, like every other path in a descriptor, not
// against the descriptor's directory. A descriptor kept in a subdirectory and run from the root,
// as this repository's own self-scan is, scans the root; read the other way, `url: .` would
// narrow it to the subdirectory with nothing saying so.
func TestARelativeURLResolvesWhereDraugrRuns(t *testing.T) {
	root := gitRepo(t, ".draugr", "app")
	rec := &targetRecorder{}
	reg := engine.NewRegistry()
	reg.RegisterController(rec)
	reg.RegisterScanner(recorderScanner{rec})
	descriptor := filepath.Join(root, ".draugr", "self.saga.yaml")
	if err := os.WriteFile(descriptor, []byte(`
project: self
config:
  controls:
    secrets: {}
components:
  - name: self
    repositories: [{url: "."}]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	if err := runScan(context.Background(), descriptor, scanOptions{format: "json", noGate: true}, reg, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if len(rec.targets) != 1 || rec.targets[0].URL != "." || len(rec.targets[0].Paths) != 0 {
		t.Errorf("targets = %+v, want the working directory, unscoped", rec.targets)
	}
}
