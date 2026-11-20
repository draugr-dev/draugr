package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/draugr-dev/draugr/pkg/cache"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// importStub stands in for the import scanner: one finding per file it is handed, recording each
// target.
type importStub struct {
	mu      sync.Mutex
	targets []plugin.FileTarget
}

func (s *importStub) Info() plugin.ScannerInfo {
	return plugin.ScannerInfo{Name: plugin.ImportScanner, TargetKinds: []plugin.TargetKind{plugin.TargetFile}}
}

func (s *importStub) Scan(_ context.Context, target plugin.Target, _ plugin.Config) (sarif.Report, error) {
	ft := target.(plugin.FileTarget)
	s.mu.Lock()
	s.targets = append(s.targets, ft)
	s.mu.Unlock()
	return sarif.Report{Tool: "example-scanner", Results: []sarif.Result{{
		RuleID: "EX1", Level: sarif.LevelError, Tool: "example-scanner", Location: sarif.Location{URI: filepath.Base(ft.Path)},
	}}}, nil
}

// Two components each importing a file: one job per import, under the control the descriptor
// names, each file's findings belonging to the component that imports it. The digest of each file
// and the component's repositories ride on the target.
func TestImportsArePlannedUnderTheNamedControl(t *testing.T) {
	dir := t.TempDir()
	apiFile, webFile := filepath.Join(dir, "api.sarif"), filepath.Join(dir, "web.sarif")
	for _, p := range []string{apiFile, webFile} {
		if err := os.WriteFile(p, []byte(p), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	reg := NewRegistry()
	reg.RegisterController(repoController{scanner: "unused"})
	stub := &importStub{}
	reg.RegisterScanner(stub)
	model := saga.Model{
		Release: saga.Release{Version: "1"},
		Components: []saga.Component{
			{Name: "api", Exposure: saga.ExposurePublic, Repositories: []saga.Repository{{URL: "https://github.com/acme/api"}},
				Imports: []saga.Import{{Control: "sast", File: apiFile}}},
			{Name: "web", Imports: []saga.Import{{Control: "sast", File: webFile}}},
		},
	}
	res, err := New(reg).Run(context.Background(), model)
	if err != nil {
		t.Fatal(err)
	}
	if len(stub.targets) != 2 {
		t.Fatalf("import jobs = %d, want one per file", len(stub.targets))
	}
	byComponent := map[string]string{}
	for _, r := range res.Controls["sast"].Report.Results {
		byComponent[r.Component] = r.Location.URI
	}
	if byComponent["api"] != "api.sarif" || byComponent["web"] != "web.sarif" {
		t.Errorf("findings by component = %v, want each file's finding on its own component", byComponent)
	}
	for _, ft := range stub.targets {
		if len(ft.Digest) != 64 || ft.Component == "" {
			t.Errorf("target %+v: want a digest and its component", ft)
		}
		if ft.Component == "api" && (len(ft.Repositories) != 1 || ft.Repositories[0].URL != "https://github.com/acme/api") {
			t.Errorf("api's import carries repositories %+v, want its own", ft.Repositories)
		}
	}
}

// An import's repositories are named as the scanned repositories are, by the remote a local checkout
// resolves to, so a finding placed in one meets the native copy in it.
func TestAnImportsRepositoriesAreNamedByTheirRemote(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(repoController{scanner: "unused"})
	reg.RegisterScanner(&importStub{})
	model := saga.Model{Components: []saga.Component{{
		Name: "api", Repositories: []saga.Repository{{URL: "."}, {URL: "/srv/local-only"}},
		Imports: []saga.Import{{Control: "sast", File: "x.sarif"}},
	}}}
	e := New(reg, WithRemoteResolver(func(path string) string {
		if path == "." {
			return "https://github.com/acme/api.git"
		}
		return ""
	}))
	jobs, err := e.Plan(model)
	if err != nil {
		t.Fatal(err)
	}
	var ft plugin.FileTarget
	for _, j := range jobs {
		if f, ok := j.Job.Target.(plugin.FileTarget); ok {
			ft = f
		}
	}
	if len(ft.Repositories) != 2 || ft.Repositories[0].Source() != "https://github.com/acme/api" ||
		ft.Repositories[1].Source() != "/srv/local-only" {
		t.Errorf("repositories = %+v, want the remote for the checkout and the path for the local-only one", ft.Repositories)
	}
}

// The commit the descriptor names reaches the import's target, and a variable left unset reaches it
// as the variable's name with no commit, so the file is read unbound rather than held to the
// reference's text.
func TestAnImportsCommitReachesItsTarget(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(repoController{scanner: "unused"})
	reg.RegisterScanner(&importStub{})
	model := saga.Model{Components: []saga.Component{{
		Name: "api", Repositories: []saga.Repository{{URL: "."}, {URL: "https://github.com/acme/web"}},
		Imports: []saga.Import{
			{Control: "sast", File: "x.sarif", Commit: "0123456789ab"},
			{Control: "sast", File: "y.sarif", Commit: "${{ GITHUB_SHA }}"},
		},
	}}}
	jobs, err := New(reg).Plan(model)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]plugin.FileTarget{}
	for _, j := range jobs {
		if f, ok := j.Job.Target.(plugin.FileTarget); ok {
			got[f.Path] = f
		}
	}
	if x := got["x.sarif"]; x.Commit != "0123456789ab" || x.CommitUnset != "" || len(x.Repositories) != 2 {
		t.Errorf("x.sarif = %+v, want its commit and both repositories", x)
	}
	if y := got["y.sarif"]; y.Commit != "" || y.CommitUnset != "GITHUB_SHA" {
		t.Errorf("y.sarif = %+v, want no commit and the unset variable", y)
	}
}

// Each import's suppressions setting reaches its own target: honored by default and when said, and
// counted only on the import that asks, so one file's setting does not decide another's.
func TestAnImportsSuppressionsSettingReachesItsTarget(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(repoController{scanner: "unused"})
	reg.RegisterScanner(&importStub{})
	model := saga.Model{Components: []saga.Component{{
		Name: "api", Repositories: []saga.Repository{{URL: "."}, {URL: "https://github.com/acme/web"}},
		Imports: []saga.Import{
			{Control: "sast", File: "default.sarif"},
			{Control: "sast", File: "honor.sarif", Suppressions: saga.ImportSuppressionsHonor},
			{Control: "sast", File: "count.sarif", Suppressions: saga.ImportSuppressionsCount},
		},
	}}}
	jobs, err := New(reg).Plan(model)
	if err != nil {
		t.Fatal(err)
	}
	counted := map[string]bool{}
	for _, j := range jobs {
		if f, ok := j.Job.Target.(plugin.FileTarget); ok {
			counted[f.Path] = f.CountSuppressed
		}
	}
	want := map[string]bool{"default.sarif": false, "honor.sarif": false, "count.sarif": true}
	if len(counted) != len(want) {
		t.Fatalf("targets = %v, want %v", counted, want)
	}
	for file, w := range want {
		if counted[file] != w {
			t.Errorf("%s counts its tool's suppressions: %v, want %v", file, counted[file], w)
		}
	}
}

// An import of a service's alerts reaches its target with the source, the token's variable and the
// repository it names, and no file or digest. Two components of one repository each, both importing
// the same source, are two jobs, each with its own repository. Its alerts are read on every run and
// never answered from the cache, since what GitHub lists changes with nothing in the descriptor or
// the tree changing.
func TestAnImportOfASourceIsReadOnEveryRun(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(repoController{scanner: "unused"})
	stub := &importStub{}
	reg.RegisterScanner(stub)
	model := saga.Model{Release: saga.Release{Version: "1"}, Components: []saga.Component{
		{Name: "api", Repositories: []saga.Repository{{URL: "https://github.com/acme/api"}},
			Imports: []saga.Import{{Control: "sast", Source: saga.ImportSourceGitHubDependabot, TokenEnv: "GH_TOKEN"}}},
		{Name: "web", Repositories: []saga.Repository{{URL: "https://github.com/acme/web"}},
			Imports: []saga.Import{{Control: "sast", Source: saga.ImportSourceGitHubDependabot, Repository: "acme/web"}}},
	}}
	e := New(reg, WithCache(cache.NewMemory()))
	for range 2 {
		if _, err := e.Run(context.Background(), model); err != nil {
			t.Fatal(err)
		}
	}
	if len(stub.targets) != 4 {
		t.Fatalf("read %d times, want each source on both runs", len(stub.targets))
	}
	for _, ft := range stub.targets {
		if ft.Source != saga.ImportSourceGitHubDependabot || ft.Path != "" || ft.Digest != "" || len(ft.Repositories) != 1 {
			t.Errorf("target %+v, want the source, no file and the component's repository", ft)
		}
		switch ft.Component {
		case "api":
			if ft.TokenEnv != "GH_TOKEN" || ft.Repositories[0].URL != "https://github.com/acme/api" {
				t.Errorf("api's target %+v", ft)
			}
		case "web":
			if ft.Repository != "acme/web" || ft.Identity() != "github-dependabot acme/web" {
				t.Errorf("web's target %+v", ft)
			}
		}
	}
}

// A control this build does not have refuses the plan, and a component outside the run's scope
// imports nothing.
func TestImportsRespectTheRegistryAndTheScope(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(repoController{scanner: "unused"})
	reg.RegisterScanner(&importStub{})
	model := saga.Model{Components: []saga.Component{
		{Name: "api", Imports: []saga.Import{{Control: "sats", File: "x.sarif"}}},
	}}
	if _, err := New(reg).Plan(model); err == nil || !strings.Contains(err.Error(), `"sats" is not a control this build provides`) {
		t.Errorf("err = %v, want the misspelled control refused", err)
	}

	model.Components[0].Imports[0].Control = "sast"
	model.Components = append(model.Components, saga.Component{Name: "web", Imports: []saga.Import{{Control: "sast", File: "y.sarif"}}})
	jobs, err := New(reg, WithScope(Scope{Components: []string{"web"}})).Plan(model)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].Component != "web" || jobs[0].Job.Target.Kind() != plugin.TargetFile {
		t.Errorf("jobs = %+v, want web's import alone", jobs)
	}
	if ft := jobs[0].Job.Target.(plugin.FileTarget); ft.Digest != "" {
		t.Errorf("digest of a missing file = %q, want empty", ft.Digest)
	}
}
