package engine

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// moduleScanner analyzes a whole Go module and reports one finding in each file of the layout the
// tests share, recording every target it was handed.
type moduleScanner struct {
	mu      sync.Mutex
	targets []plugin.RepositoryTarget
}

func (s *moduleScanner) Info() plugin.ScannerInfo {
	return plugin.ScannerInfo{Name: "mod", ModuleManifest: "go.mod"}
}

func (s *moduleScanner) Scan(_ context.Context, target plugin.Target, _ plugin.Config) (sarif.Report, error) {
	s.mu.Lock()
	s.targets = append(s.targets, target.(plugin.RepositoryTarget))
	s.mu.Unlock()
	var results []sarif.Result
	for _, f := range []string{"cmd/api/main.go", "cmd/admin/main.go", "internal/store/store.go", "internal/api/gen.go", ""} {
		results = append(results, sarif.Result{RuleID: "G" + f, Level: sarif.LevelWarning, Location: sarif.Location{URI: f}})
	}
	return sarif.Report{Tool: "mod", Results: results}, nil
}

// repoController plans one job per repository of each component, with the paths it declares.
type repoController struct{ scanner string }

func (c repoController) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: "sast", Scope: plugin.ScopeComponent}
}

func (c repoController) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	var jobs []plugin.ScanJob
	for _, r := range comp.Repositories {
		jobs = append(jobs, plugin.ScanJob{Scanner: c.scanner, Target: plugin.RepositoryTarget{
			URL: r.URL, Revision: r.Revision, Paths: r.Paths, Ignore: r.Ignore,
		}})
	}
	return jobs, nil
}

func (c repoController) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	return plugin.ControlResult{Control: "sast", Report: sarif.Merge(reports...)}, nil
}

// splitModel is the shape the attribution exists for: two services carved out of one module,
// sharing internal/store, which neither names. The api names go.mod and admin does not, and admin
// ignores a generated directory its paths otherwise hold.
func splitModel() saga.Model {
	return saga.Model{
		Release: saga.Release{Version: "1"},
		Config:  saga.Config{Controls: map[string]saga.ControllerSettings{"sast": {"enabled": true}}},
		Components: []saga.Component{
			{Name: "api", Repositories: []saga.Repository{{URL: ".", Paths: []string{"cmd/api", "internal/api", "go.mod"}, Ignore: []string{"internal/api/gen.go"}}}},
			{Name: "admin", Repositories: []saga.Repository{{URL: ".", Paths: []string{"cmd/admin"}}}},
		},
	}
}

// staticModules answers every question with roots, counting how often it was asked.
func staticModules(roots []string, err error, asked *int) ModuleResolver {
	return func(context.Context, string, string, bool, string, []string) ([]string, error) {
		*asked++
		return roots, err
	}
}

// findingsBy lists each component's findings by file.
func findingsBy(res Result) map[string][]string {
	got := map[string][]string{}
	for _, r := range res.Controls["sast"].Report.Results {
		got[r.Component] = append(got[r.Component], r.Location.URI)
	}
	for _, files := range got {
		slices.Sort(files)
	}
	return got
}

func TestWidenToModulesSharesOneAnalysis(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(repoController{scanner: "mod"})
	sc := &moduleScanner{}
	reg.RegisterScanner(sc)
	asked := 0

	res, err := New(reg, WithModuleResolver(staticModules([]string{"."}, nil, &asked))).Run(context.Background(), splitModel())
	if err != nil {
		t.Fatal(err)
	}

	// Both components' paths fall in the root module, so both jobs name the same widened target,
	// with no ignore list, and the module is analyzed once.
	if len(sc.targets) != 1 {
		t.Fatalf("scans = %d, want 1 shared between the components", len(sc.targets))
	}
	if got := sc.targets[0]; !slices.Equal(got.Paths, []string{"."}) || got.Ignore != nil {
		t.Errorf("target = %+v, want the module root and no ignore list", got)
	}
	if res.Stats.Deduped != 1 {
		t.Errorf("deduped = %d, want 1", res.Stats.Deduped)
	}
	if asked != 2 {
		t.Errorf("resolver asked %d times, want once per distinct scope", asked)
	}

	// Each component keeps the files its paths hold; the shared package goes to the component
	// naming go.mod; api's ignored file is reported by nobody, as a scan of its paths would not;
	// the finding with no file is kept by both.
	want := map[string][]string{
		"api":   {"", "cmd/api/main.go", "internal/store/store.go"},
		"admin": {"", "cmd/admin/main.go"},
	}
	got := findingsBy(res)
	for comp, files := range want {
		if !slices.Equal(got[comp], files) {
			t.Errorf("%s findings = %q, want %q", comp, got[comp], files)
		}
	}
}

// reachScanner is a call-graph analyzer of whole Go modules: it answers from where its target's
// Entry starts, reachable from cmd/admin and unreachable from anywhere else.
type reachScanner struct{ moduleScanner }

func (s *reachScanner) Info() plugin.ScannerInfo {
	return plugin.ScannerInfo{Name: "reach", ModuleManifest: "go.mod", Reachability: true}
}

func (s *reachScanner) Scan(_ context.Context, target plugin.Target, _ plugin.Config) (sarif.Report, error) {
	repo := target.(plugin.RepositoryTarget)
	s.mu.Lock()
	s.targets = append(s.targets, repo)
	s.mu.Unlock()
	reach := &sarif.Reachability{State: sarif.ReachabilityUnreachable, Analyzer: "reach"}
	if slices.Contains(repo.Entry, "cmd/admin") {
		reach = &sarif.Reachability{State: sarif.ReachabilityReachable, Analyzer: "reach",
			Paths: []sarif.CallPath{callPath("cmd/admin/main.go")}}
	}
	return sarif.Report{Tool: "reach", Results: []sarif.Result{{
		RuleID: "GO-1", Level: sarif.LevelWarning, Location: sarif.Location{URI: "go.mod"}, Reachability: reach,
	}}}, nil
}

func TestWidenToModulesStartsAReachabilityAnalysisFromEachComponent(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(repoController{scanner: "reach"})
	sc := &reachScanner{}
	reg.RegisterScanner(sc)
	asked := 0

	model := splitModel()
	model.Components[1].Repositories[0].Paths = []string{"cmd/admin", "go.mod"}
	res, err := New(reg, WithModuleResolver(staticModules([]string{"."}, nil, &asked))).Run(context.Background(), model)
	if err != nil {
		t.Fatal(err)
	}

	// One checkout, two analyses: each component's job keeps the module root as its scope and its
	// own paths as where the analysis starts.
	if len(sc.targets) != 2 {
		t.Fatalf("scans = %d, want one per component", len(sc.targets))
	}
	entries := map[string]bool{}
	for _, got := range sc.targets {
		if !slices.Equal(got.Paths, []string{"."}) || got.Ignore != nil {
			t.Errorf("target = %+v, want the module root and no ignore list", got)
		}
		if got.Identity() != sc.targets[0].Identity() {
			t.Errorf("identities differ (%q, %q), so the components would not share a checkout", got.Identity(), sc.targets[0].Identity())
		}
		entries[strings.Join(got.Entry, ",")] = true
	}
	if !entries["cmd/api,internal/api,go.mod"] || !entries["cmd/admin,go.mod"] {
		t.Errorf("entries = %v, want each component's own paths", entries)
	}
	if res.Stats.Deduped != 0 {
		t.Errorf("deduped = %d, want 0: two starting points are two analyses", res.Stats.Deduped)
	}

	verdicts := map[string]sarif.ReachabilityState{}
	for _, r := range res.Controls["sast"].Report.Results {
		verdicts[r.Component] = r.Reachability.State
	}
	if verdicts["api"] != sarif.ReachabilityUnreachable || verdicts["admin"] != sarif.ReachabilityReachable {
		t.Errorf("verdicts = %v, want api unreachable and admin reachable", verdicts)
	}
}

func TestWidenToModulesOrphanGoesToEveryManifestHolder(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(repoController{scanner: "mod"})
	reg.RegisterScanner(&moduleScanner{})
	m := splitModel()
	m.Components[1].Repositories[0].Paths = []string{"cmd/admin", "go.mod"}
	asked := 0

	res, err := New(reg, WithModuleResolver(staticModules([]string{"."}, nil, &asked))).Run(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	got := findingsBy(res)
	for _, comp := range []string{"api", "admin"} {
		if !slices.Contains(got[comp], "internal/store/store.go") {
			t.Errorf("%s findings = %q, want the shared package's finding", comp, got[comp])
		}
	}
}

func TestWidenToModulesLeavesAJobAlone(t *testing.T) {
	for name, opt := range map[string]Option{
		"no resolver":      func(*Engine) {},
		"nothing to widen": WithModuleResolver(staticModules(nil, nil, new(int))),
		"unreadable":       WithModuleResolver(staticModules(nil, errors.New("no such revision"), new(int))),
	} {
		t.Run(name, func(t *testing.T) {
			reg := NewRegistry()
			reg.RegisterController(repoController{scanner: "mod"})
			sc := &moduleScanner{}
			reg.RegisterScanner(sc)
			res, err := New(reg, opt).Run(context.Background(), splitModel())
			if err != nil {
				t.Fatal(err)
			}
			// Unwidened, each job scans its own paths and keeps everything its scanner reports.
			if len(sc.targets) != 2 {
				t.Fatalf("scans = %d, want one per component", len(sc.targets))
			}
			if n := len(findingsBy(res)["admin"]); n != 5 {
				t.Errorf("admin findings = %d, want every finding of an unattributed scan", n)
			}
		})
	}
}

func TestWidenToModulesSkipsWhatItDoesNotApplyTo(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterScanner(&moduleScanner{})
	reg.RegisterScanner(&fakeScanner{name: "files"})
	asked := 0
	e := New(reg, WithModuleResolver(staticModules([]string{"."}, nil, &asked)))
	planned := []PlannedJob{
		{Job: plugin.ScanJob{Scanner: "files", Target: plugin.RepositoryTarget{URL: ".", Paths: []string{"cmd/api"}}}},
		{Job: plugin.ScanJob{Scanner: "mod", Target: plugin.RepositoryTarget{URL: "."}}},
		{Job: plugin.ScanJob{Scanner: "mod", Target: plugin.ImageTarget{Ref: "app:1"}}},
		{Job: plugin.ScanJob{Scanner: "missing", Target: plugin.RepositoryTarget{URL: ".", Paths: []string{"cmd/api"}}}},
	}
	got := e.widenToModules(context.Background(), slices.Clone(planned), saga.Model{})
	for i := range got {
		if got[i].owner != nil {
			t.Errorf("job %d was widened", i)
		}
	}
	if asked != 0 {
		t.Errorf("resolver asked %d times, want 0", asked)
	}
}

// callPath is a route into a dependency starting in file, relative to the module root.
func callPath(file string) sarif.CallPath {
	return sarif.CallPath{Frames: []sarif.CallFrame{
		{Function: "main", File: file, Line: 3},
		{Function: "Parse", Module: "golang.org/x/text", File: "language/parse.go", Line: 9},
	}}
}

func TestModuleOwnerNarrowsReachability(t *testing.T) {
	// A nested module at services/, so the frames' module-relative files have to be placed
	// under it before they are compared with the descriptor's paths.
	owner := func(paths ...string) *moduleOwner {
		return &moduleOwner{
			manifest: "go.mod",
			modules:  []string{"services"},
			own:      git.Scope{Paths: paths},
			claims:   []git.Scope{{Paths: []string{"services/cmd/api", "services/go.mod"}}, {Paths: []string{"services/cmd/admin"}}},
		}
	}
	api, admin := owner("services/cmd/api", "services/go.mod"), owner("services/cmd/admin")
	finding := sarif.Result{RuleID: "GO-1", Location: sarif.Location{URI: "services/go.mod"}, Reachability: &sarif.Reachability{
		State: sarif.ReachabilityReachable, Analyzer: "govulncheck",
		Paths: []sarif.CallPath{callPath("cmd/api/main.go"), callPath("cmd/admin/main.go")},
	}}
	report := sarif.Report{Results: []sarif.Result{finding}}

	adminGot := admin.attribute(report).Results
	if len(adminGot) != 1 || len(adminGot[0].Reachability.Paths) != 1 ||
		adminGot[0].Reachability.Paths[0].Frames[0].File != "cmd/admin/main.go" {
		t.Fatalf("admin = %+v, want the finding with its own route only", adminGot)
	}
	apiGot := api.attribute(report).Results
	if len(apiGot) != 1 || len(apiGot[0].Reachability.Paths) != 1 {
		t.Fatalf("api = %+v, want the finding with its own route only", apiGot)
	}
	if len(report.Results[0].Reachability.Paths) != 2 {
		t.Error("the shared report was modified")
	}

	// Every route owned: the finding is kept as it is.
	both := &moduleOwner{manifest: "go.mod", modules: []string{"services"}, own: git.Scope{Paths: []string{"services"}}}
	if got := both.attribute(report).Results; len(got) != 1 || got[0].Reachability != finding.Reachability {
		t.Errorf("an owner of every route = %+v, want the finding unchanged", got)
	}

	// No route of its own: the component naming go.mod keeps the finding, undetermined; the
	// other drops it.
	elsewhere := sarif.Report{Results: []sarif.Result{{RuleID: "GO-2", Location: sarif.Location{URI: "services/go.mod"},
		Reachability: &sarif.Reachability{State: sarif.ReachabilityReachable, Paths: []sarif.CallPath{callPath("cmd/admin/main.go")}}}}}
	got := api.attribute(elsewhere).Results
	if len(got) != 1 || got[0].Reachability.State != sarif.ReachabilityUnknown || got[0].Reachability.Paths != nil {
		t.Errorf("api, no route of its own = %+v, want the finding kept as unknown", got)
	}
	if got := owner("services/cmd/other").attribute(elsewhere).Results; len(got) != 0 {
		t.Errorf("a component holding neither route nor go.mod = %+v, want nothing", got)
	}

	// A route with no file is placed at the finding's manifest.
	noFile := sarif.CallPath{Frames: []sarif.CallFrame{{Function: "init"}}}
	if f := entryFile(noFile, "services/go.mod"); f != "services/go.mod" {
		t.Errorf("entryFile with no file = %q, want the manifest", f)
	}
	if f := entryFile(callPath("./cmd/api/main.go"), "go.mod"); f != "cmd/api/main.go" {
		t.Errorf("entryFile at the root = %q", f)
	}
}

func TestModuleOwnerNilAndEmpty(t *testing.T) {
	var o *moduleOwner
	r := sarif.Report{Results: []sarif.Result{{RuleID: "x"}}}
	if got := o.attribute(r); len(got.Results) != 1 {
		t.Error("a nil owner changed the report")
	}
	if got := (&moduleOwner{}).attribute(sarif.Report{}); got.Results != nil {
		t.Error("an empty report gained results")
	}
}
