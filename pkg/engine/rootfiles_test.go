package engine

import (
	"context"
	"slices"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// repoController plans one job per repository a component declares, scope included, the way the
// repository controls do.
type repoController struct{ name, scanner string }

func (c repoController) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: c.name, Scope: plugin.ScopeComponent}
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
	return plugin.ControlResult{Control: c.name, Report: sarif.Merge(reports...)}, nil
}

// rootScanner reports what a scoped checkout of a monorepo holds: a root lockfile's flaw, a leaked
// root secret, and one finding inside each path the job was scoped to.
type rootScanner struct{}

func (rootScanner) Info() plugin.ScannerInfo { return plugin.ScannerInfo{Name: "s", Version: "1"} }

func (rootScanner) Scan(_ context.Context, t plugin.Target, _ plugin.Config) (sarif.Report, error) {
	repo := t.(plugin.RepositoryTarget)
	rep := sarif.Report{Tool: "s", Results: []sarif.Result{
		{RuleID: "CVE-1", Level: sarif.LevelError, Location: sarif.Location{URI: "go.mod"}, Repository: repo.Source()},
		{RuleID: "secret", Level: sarif.LevelError, Location: sarif.Location{URI: ".env"}, Repository: repo.Source()},
	}, Inputs: []sarif.Input{
		{Scanner: "s", Repository: repo.Source(), Path: "pyproject.toml", Unread: "no lockfile"},
	}}
	for _, p := range repo.Paths {
		rep.Results = append(rep.Results, sarif.Result{
			RuleID: "own", Level: sarif.LevelError, Location: sarif.Location{URI: p + "/main.go"}, Repository: repo.Source(),
		})
	}
	return rep, nil
}

// bandByExposure ranks on exposure alone, so which classification a finding was ranked under is
// readable from its band.
func bandByExposure(_ string, exposure saga.Exposure, _ saga.Criticality, _ sarif.Result) Priority {
	switch exposure {
	case saga.ExposurePublic:
		return Priority{Band: "P1"}
	case saga.ExposureInternal:
		return Priority{Band: "P3"}
	}
	return Priority{Band: "P4"}
}

func sharedRepoModel(components ...saga.Component) saga.Model {
	return saga.Model{
		Release:    saga.Release{Version: "1"},
		Config:     saga.Config{Controls: map[string]saga.ControllerSettings{"sca": {"enabled": true}}},
		Components: components,
	}
}

func scoped(name string, exposure saga.Exposure, paths ...string) saga.Component {
	return saga.Component{
		Name: name, Exposure: exposure, Criticality: saga.CriticalityImportant,
		Repositories: []saga.Repository{{URL: "https://git.example/mono", Paths: paths}},
	}
}

func runMonorepo(t *testing.T, m saga.Model) Result {
	t.Helper()
	reg := NewRegistry()
	reg.RegisterController(repoController{name: "sca", scanner: "s"})
	reg.RegisterScanner(rootScanner{})
	res, err := New(reg, WithPrioritization(bandByExposure)).Run(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// owners maps each finding at a path to the components it was reported under.
func owners(res Result, uri string) []string {
	var out []string
	for _, r := range res.Controls["sca"].Report.Results {
		if r.Location.URI == uri {
			out = append(out, r.Component)
		}
	}
	slices.Sort(out)
	return out
}

// Two components carved out of one repository: a root file is neither's, so its findings are
// reported once with no component, ranked as the more exposed of the two. Each component's own
// subtree stays its own.
func TestARootFileTwoComponentsShareBelongsToNeither(t *testing.T) {
	res := runMonorepo(t, sharedRepoModel(
		scoped("web", saga.ExposurePublic, "services/web"),
		scoped("api", saga.ExposureInternal, "services/api"),
	))
	for _, uri := range []string{"go.mod", ".env"} {
		if got := owners(res, uri); !slices.Equal(got, []string{""}) {
			t.Errorf("%s reported under %q, want once under no component", uri, got)
		}
	}
	for _, r := range res.Controls["sca"].Report.Results {
		if r.Location.URI == "go.mod" && (r.Priority != "P1" || r.Exposure != string(saga.ExposurePublic) || r.Labels != nil) {
			t.Errorf("unowned finding = %+v, want ranked as the public sharer", r)
		}
	}
	if got := owners(res, "services/web/main.go"); !slices.Equal(got, []string{"web"}) {
		t.Errorf("services/web under %q", got)
	}
	if got := owners(res, "services/api/main.go"); !slices.Equal(got, []string{"api"}) {
		t.Errorf("services/api under %q", got)
	}
	var unread []string
	for _, c := range res.Inputs {
		for _, u := range c.Unread {
			if u.Path == "pyproject.toml" {
				unread = append(unread, c.Component)
			}
		}
	}
	if !slices.Equal(unread, []string{""}) {
		t.Errorf("the root pyproject.toml is listed unread under %q, want once under no component", unread)
	}
}

// The unowned finding is ranked as the most exposed sharer whichever order they were declared in.
func TestAnUnownedRootFindingTakesTheMostExposedSharer(t *testing.T) {
	res := runMonorepo(t, sharedRepoModel(
		scoped("api", saga.ExposureInternal, "services/api"),
		scoped("web", saga.ExposurePublic, "services/web"),
	))
	for _, r := range res.Controls["sca"].Report.Results {
		if r.Location.URI == "go.mod" && r.Priority != "P1" {
			t.Errorf("ranked %s, want the public sharer's P1", r.Priority)
		}
	}
}

// A component that claims the root owns its files, and the others stop reporting them.
func TestAComponentThatClaimsTheRootOwnsItsFiles(t *testing.T) {
	platform := scoped("platform", saga.ExposureInternal)
	res := runMonorepo(t, sharedRepoModel(
		scoped("web", saga.ExposurePublic, "services/web"),
		scoped("api", saga.ExposureInternal, "services/api"),
		platform,
	))
	for _, uri := range []string{"go.mod", ".env"} {
		if got := owners(res, uri); !slices.Equal(got, []string{"platform"}) {
			t.Errorf("%s reported under %q, want platform, which has no paths", uri, got)
		}
	}

	dot := runMonorepo(t, sharedRepoModel(
		scoped("web", saga.ExposurePublic, "services/web"),
		scoped("api", saga.ExposureInternal, "services/api", "."),
	))
	if got := owners(dot, "go.mod"); !slices.Equal(got, []string{"api"}) {
		t.Errorf("go.mod under %q, want api, whose paths include .", got)
	}
}

// Naming a root file claims that file and no other.
func TestNamingARootFileClaimsIt(t *testing.T) {
	res := runMonorepo(t, sharedRepoModel(
		scoped("web", saga.ExposurePublic, "services/web", "go.mod"),
		scoped("api", saga.ExposureInternal, "services/api"),
	))
	if got := owners(res, "go.mod"); !slices.Equal(got, []string{"web"}) {
		t.Errorf("go.mod under %q, want web, which names it", got)
	}
	if got := owners(res, ".env"); !slices.Equal(got, []string{""}) {
		t.Errorf(".env under %q, want nobody: web named go.mod only", got)
	}
}

// With one component on a repository there is nobody to share the root with.
func TestTheOnlyComponentOnARepositoryKeepsItsRoot(t *testing.T) {
	res := runMonorepo(t, sharedRepoModel(scoped("web", saga.ExposurePublic, "services/web")))
	if got := owners(res, "go.mod"); !slices.Equal(got, []string{"web"}) {
		t.Errorf("go.mod under %q, want web", got)
	}
}

func TestMoreUrgent(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"P1", "P2", true}, {"P2", "P1", false}, {"P1", "", true}, {"", "P4", false}, {"", "", false},
	} {
		if got := moreUrgent(tc.a, tc.b); got != tc.want {
			t.Errorf("moreUrgent(%q, %q) = %v", tc.a, tc.b, got)
		}
	}
}
