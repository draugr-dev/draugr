package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

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
