package engine

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// reposController plans one job per repository a component lists, so a test can give a component
// two repositories and two components one.
type reposController struct {
	name, scanner string
	repos         map[string][]string
}

func (c reposController) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: c.name, Scope: plugin.ScopeComponent}
}

func (c reposController) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	var jobs []plugin.ScanJob
	for _, u := range c.repos[comp.Name] {
		jobs = append(jobs, plugin.ScanJob{Scanner: c.scanner, Target: plugin.RepositoryTarget{URL: u, Revision: "main"}})
	}
	return jobs, nil
}

func (c reposController) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	return plugin.ControlResult{Control: c.name, Report: sarif.Merge(reports...)}, nil
}

// pickyScanner fails on the repositories it is told to and reads the rest.
type pickyScanner struct {
	name   string
	failOn []string
}

func (s pickyScanner) Info() plugin.ScannerInfo { return plugin.ScannerInfo{Name: s.name} }

func (s pickyScanner) Scan(_ context.Context, t plugin.Target, _ plugin.Config) (sarif.Report, error) {
	if r, ok := t.(plugin.RepositoryTarget); ok && slices.Contains(s.failOn, r.URL) {
		return sarif.Report{}, errors.New(s.name + ": git clone " + r.URL + ": Repository not found")
	}
	return sarif.Report{Tool: s.name}, nil
}

// Two repositories on one component, one of them shared with a second component, and three
// controls: the case that hides the bugs this account exists for. One repository proves the loop
// runs; two prove a failure on one does not collapse into the component or into the other.
func TestRunAccountsForEachTarget(t *testing.T) {
	const (
		api     = "https://github.com/acme/api"
		archive = "https://github.com/acme/api-archive"
	)
	repos := map[string][]string{"api": {api, archive}, "web": {api}}
	reg := NewRegistry()
	reg.RegisterController(reposController{name: "sca", scanner: "dep", repos: repos})
	reg.RegisterController(reposController{name: "secrets", scanner: "leak", repos: repos})
	// sast fails on the repository the other two read, so that repository was examined, and the
	// failure is sast's own error rather than a target the run did not reach.
	reg.RegisterController(reposController{name: "sast", scanner: "lint", repos: map[string][]string{"api": {api}}})
	reg.RegisterScanner(pickyScanner{name: "dep", failOn: []string{archive}})
	reg.RegisterScanner(pickyScanner{name: "leak", failOn: []string{archive}})
	reg.RegisterScanner(pickyScanner{name: "lint", failOn: []string{api}})

	on := map[string]saga.ControllerSettings{"sca": {}, "secrets": {}, "sast": {}}
	res, err := New(reg).Run(context.Background(), saga.Model{
		Release:    saga.Release{Version: "1"},
		Components: []saga.Component{{Name: "api", Controls: on}, {Name: "web", Controls: on}},
	})
	if err == nil {
		t.Fatal("want the run to report its failed scans")
	}

	// Sorted by address, where "api-archive" comes before "api@".
	want := []TargetOutcome{
		{Kind: "repository", Target: archive + "@main", Status: TargetFailed, Components: []string{"api"},
			Detail: "dep: git clone " + archive + ": Repository not found"},
		{Kind: "repository", Target: api + "@main", Status: TargetReached, Components: []string{"api", "web"}},
	}
	got := slices.Clone(res.Targets)
	slices.SortFunc(got, func(a, b TargetOutcome) int { return strings.Compare(a.Target, b.Target) })
	if len(got) != len(want) {
		t.Fatalf("targets = %+v, want %+v", got, want)
	}
	for i := range want {
		g, w := got[i], want[i]
		if g.Kind != w.Kind || g.Target != w.Target || g.Status != w.Status || !slices.Equal(g.Components, w.Components) {
			t.Errorf("target %d = %+v, want %+v", i, g, w)
		}
		// Either scanner's words will do, as long as they are a scanner's and not a summary.
		if w.Detail != "" && !strings.HasSuffix(g.Detail, ": git clone "+archive+": Repository not found") {
			t.Errorf("detail = %q, want the scanner's message", g.Detail)
		}
	}

	// Every failure behind the unreached repository, one per control, and nothing of sast's.
	var controls []string
	for _, f := range res.Stats.Failures {
		controls = append(controls, f.Control)
		if !strings.Contains(f.Detail, archive) {
			t.Errorf("failure %+v is not behind the unreached repository", f)
		}
	}
	slices.Sort(controls)
	if !slices.Equal(controls, []string{"sca", "secrets"}) {
		t.Errorf("failures are for %v, want sca and secrets", controls)
	}
	if _, ok := res.ScanErrors["sast"]; !ok {
		t.Error("sast's failure on a repository another control read must stay its own error")
	}
}

// opaqueTarget is a kind the account has no special identity for.
type opaqueTarget struct{}

func (opaqueTarget) Kind() plugin.TargetKind { return "sbom" }
func (opaqueTarget) Identity() string        { return "sbom/app.cdx.json" }

// Each target is named the way doctor names it, so a target doctor checked and the same target in
// the report match.
func TestOutcomeIdentityMatchesDoctor(t *testing.T) {
	for _, c := range []struct {
		target   plugin.Target
		kind, id string
	}{
		// #nosec G101 -- placeholder credentials, there to prove they are left out of the name.
		{plugin.RepositoryTarget{URL: "https://user:token@github.com/acme/api", Revision: "v1", Paths: []string{"svc"}}, "repository", "https://github.com/acme/api@v1"},
		{plugin.RepositoryTarget{URL: "https://github.com/acme/api"}, "repository", "https://github.com/acme/api"},
		{plugin.ImageTarget{Ref: "ghcr.io/acme/api:1", Digest: "sha256:ab"}, "image", "ghcr.io/acme/api:1@sha256:ab"},
		// #nosec G101 -- placeholder credentials, there to prove they are left out of the name.
		{plugin.HostTarget{URL: "https://user:pw@api.example.com/"}, "host", "https://api.example.com/"},
		{plugin.KubernetesTarget{Cluster: "prod", Namespaces: []string{"b", "a"}}, "cluster", "kubernetes/prod"},
		{plugin.KubernetesTarget{}, "cluster", "kubernetes"},
		{opaqueTarget{}, "sbom", "sbom/app.cdx.json"},
	} {
		kind, id := outcomeIdentity(c.target)
		if kind != c.kind || id != c.id {
			t.Errorf("outcomeIdentity(%#v) = %q %q, want %q %q", c.target, kind, id, c.kind, c.id)
		}
	}
}

// A target every job skipped was not read, and says why; a job that collapsed into a failed one
// was not read either, and is never reported as reached for having no failure of its own.
func TestTargetOutcomesForSkippedAndCollapsedJobs(t *testing.T) {
	team := plugin.KubernetesTarget{Cluster: "prod", Namespaces: []string{"team-a"}}
	repo := plugin.RepositoryTarget{URL: "https://github.com/acme/api"}
	planned := []PlannedJob{
		{Control: "kubernetes", Component: "team-a", Job: plugin.ScanJob{Scanner: "kube-bench-job", Target: team}},
		{Control: "sca", Component: "api", Job: plugin.ScanJob{Scanner: "dep", Target: repo}},
		{Control: "sca", Component: "", Job: plugin.ScanJob{Scanner: "dep"}},
	}
	skipped := []SkippedJob{
		{Control: "kubernetes", Scanner: "kube-bench-job", Component: "team-a", Reason: "audits the whole cluster", target: team},
		{Control: "sca", Scanner: "dep", Component: "api"},
	}
	got := targetOutcomes(planned, skipped, nil, nil)
	if len(got) != 2 {
		t.Fatalf("got %+v, want the cluster and the repository", got)
	}
	if c := got[0]; c.Status != TargetSkipped || c.Detail != "audits the whole cluster" || c.Target != "kubernetes/prod" {
		t.Errorf("cluster = %+v, want skipped with its reason", c)
	}
	if r := got[1]; r.Status != TargetFailed || r.Detail != "" {
		t.Errorf("repository = %+v, want failed with no detail of its own", r)
	}
}

// A failure says more than a skip about why nothing was read, and the first failure is the one
// kept.
func TestTargetOutcomesPreferTheFirstFailure(t *testing.T) {
	repo := plugin.RepositoryTarget{URL: "https://github.com/acme/api"}
	planned := []PlannedJob{{Control: "sca", Component: "api", Job: plugin.ScanJob{Scanner: "dep", Target: repo}}}
	got := targetOutcomes(planned,
		[]SkippedJob{{Component: "api", Reason: "skipped", target: repo}},
		[]Unscanned{
			{Component: "api", Detail: "first", target: repo},
			{Component: "api", Detail: "second", target: repo},
			{Component: "api", Detail: "no target"},
		}, nil)
	if len(got) != 1 || got[0].Status != TargetFailed || got[0].Detail != "first" {
		t.Errorf("got %+v, want failed with the first failure", got)
	}
}

// absentScanner is a scanner whose tool is not installed.
type absentScanner struct{}

func (absentScanner) Info() plugin.ScannerInfo { return plugin.ScannerInfo{Name: "dep"} }

func (absentScanner) Scan(context.Context, plugin.Target, plugin.Config) (sarif.Report, error) {
	return sarif.Report{}, fmt.Errorf("dep: %w", exec.ErrNotFound)
}

// A tool that is not installed never tried the target. Its control's error says so once, and the
// target is not a failure to reach it, or one missing binary is a row for every repository.
func TestAMissingToolSkipsItsTargets(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(reposController{name: "sca", scanner: "dep", repos: map[string][]string{
		"api": {"https://github.com/acme/api", "https://github.com/acme/lib"},
	}})
	reg.RegisterScanner(absentScanner{})
	res, err := New(reg).Run(context.Background(), saga.Model{
		Release:    saga.Release{Version: "1"},
		Components: []saga.Component{{Name: "api", Controls: map[string]saga.ControllerSettings{"sca": {}}}},
	})
	if err == nil {
		t.Fatal("a run whose tool is missing must still fail")
	}
	if len(res.Targets) != 2 {
		t.Fatalf("targets = %+v, want both repositories", res.Targets)
	}
	for _, o := range res.Targets {
		if o.Status != TargetSkipped || !strings.Contains(o.Detail, "executable file not found") {
			t.Errorf("%s = %s %q, want skipped with the tool's error", o.Target, o.Status, o.Detail)
		}
	}
	if len(res.Stats.Failures) != 0 {
		t.Errorf("failures = %+v, want none: the control's error says it", res.Stats.Failures)
	}
	if len(res.ScanErrors["sca"]) == 0 {
		t.Error("the control's error is missing")
	}
}
