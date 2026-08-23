package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// hostEffectController plans one job per host, carrying each host's environment onto its target —
// the shape every live-target controller has.
type hostEffectController struct{ scanner string }

func (c hostEffectController) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: "dast", Scope: plugin.ScopeComponent, DefaultScanners: []string{c.scanner}}
}

func (c hostEffectController) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	jobs := make([]plugin.ScanJob, 0, len(comp.Hosts))
	for _, h := range comp.Hosts {
		jobs = append(jobs, plugin.ScanJob{
			Scanner: c.scanner,
			Target:  plugin.HostTarget{Name: h.Name, URL: h.URL, Environment: h.Environment},
		})
	}
	return jobs, nil
}

func (c hostEffectController) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	return plugin.ControlResult{Control: "dast", Report: sarif.Merge(reports...)}, nil
}

type hostEffectScanner struct{ effects []plugin.Effect }

func (s hostEffectScanner) Info() plugin.ScannerInfo {
	return plugin.ScannerInfo{
		Name: "prober", Controls: []string{"dast"},
		TargetKinds: []plugin.TargetKind{plugin.TargetHost}, Effects: s.effects,
	}
}

func (s hostEffectScanner) Scan(_ context.Context, t plugin.Target, _ plugin.Config) (sarif.Report, error) {
	return sarif.Report{Tool: "prober", Results: []sarif.Result{{RuleID: t.Identity()}}}, nil
}

// twoEnvironments is the case one host cannot show: a descriptor listing a staging endpoint and a
// production one. Any permission read once for the whole model grants both.
func twoEnvironments(perms saga.EffectPermissions) saga.Model {
	return saga.Model{
		Config: saga.Config{
			Controllers:  map[string]saga.ControllerSettings{"dast": {"enabled": true}},
			AllowEffects: perms,
		},
		Components: []saga.Component{{
			Name: "web",
			Hosts: []saga.Host{
				{Name: "staging", URL: "https://staging.example.com", Environment: "staging"},
				{Name: "prod", URL: "https://example.com", Environment: "production"},
			},
		}},
	}
}

func hostEngine(t *testing.T, effects []plugin.Effect) *Engine {
	t.Helper()
	reg := NewRegistry()
	reg.RegisterController(hostEffectController{scanner: "prober"})
	reg.RegisterScanner(hostEffectScanner{effects: effects})
	return New(reg)
}

var intrusive = []plugin.Effect{{Kind: plugin.EffectMutate, Detail: "writes to the target"}}

// The point of the whole change: one descriptor, one scanner, two endpoints, and the permission
// applies to one of them.
func TestAPermissionGrantedToStagingDoesNotReachProduction(t *testing.T) {
	model := twoEnvironments(saga.EffectPermissions{
		ByEnvironment: map[string][]string{"staging": {"mutate"}},
	})
	jobs, err := hostEngine(t, intrusive).Plan(model)
	if err == nil {
		t.Fatal("production was permitted an effect only staging accepted")
	}
	if len(jobs) != 1 {
		t.Fatalf("planned %d jobs, want 1 (staging)", len(jobs))
	}
	if got := plugin.EnvironmentOf(jobs[0].Job.Target); got != "staging" {
		t.Errorf("the surviving job is in %q, want staging", got)
	}
	// The message has to name the environment that refused, or the reader widens the permission
	// to every environment to get past it — which is the outcome this exists to prevent.
	if !strings.Contains(err.Error(), "against production") {
		t.Errorf("the refusal does not name the environment: %v", err)
	}
	if !strings.Contains(err.Error(), "config.allowEffects.production") {
		t.Errorf("the refusal does not name the fix: %v", err)
	}
}

// The list form still means every environment. Existing descriptors keep working, and a descriptor
// that grants an effect everywhere reads as saying so.
func TestTheListFormPermitsEveryEnvironment(t *testing.T) {
	model := twoEnvironments(saga.EffectPermissions{Everywhere: []string{"mutate"}})
	jobs, err := hostEngine(t, intrusive).Plan(model)
	if err != nil {
		t.Fatalf("a blanket permission refused a job: %v", err)
	}
	if len(jobs) != 2 {
		t.Errorf("planned %d jobs, want 2", len(jobs))
	}
}

// Nothing granted refuses both, and says so about both rather than stopping at the first.
func TestNoPermissionRefusesEveryEnvironment(t *testing.T) {
	jobs, err := hostEngine(t, intrusive).Plan(twoEnvironments(saga.EffectPermissions{}))
	if err == nil {
		t.Fatal("an intrusive scanner ran with no permission at all")
	}
	if len(jobs) != 0 {
		t.Errorf("planned %d jobs, want 0", len(jobs))
	}
	for _, env := range []string{"staging", "production"} {
		if !strings.Contains(err.Error(), "against "+env) {
			t.Errorf("the refusal does not mention %s: %v", env, err)
		}
	}
}

// A scanner with no effects needing consent is unaffected by any of this.
func TestAReadOnlyScannerNeedsNoPermission(t *testing.T) {
	jobs, err := hostEngine(t, nil).Plan(twoEnvironments(saga.EffectPermissions{}))
	if err != nil {
		t.Fatalf("a read-only scanner was refused: %v", err)
	}
	if len(jobs) != 2 {
		t.Errorf("planned %d jobs, want 2", len(jobs))
	}
}

// --allow-effects is one person at one terminal accepting one run. Asking them to name an
// environment as well would be asking them to repeat what the descriptor already says.
func TestTheFlagAppliesEverywhere(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(hostEffectController{scanner: "prober"})
	reg.RegisterScanner(hostEffectScanner{effects: intrusive})
	jobs, err := New(reg, WithAllowedEffects([]string{"mutate"})).Plan(twoEnvironments(saga.EffectPermissions{}))
	if err != nil {
		t.Fatalf("the flag did not reach both environments: %v", err)
	}
	if len(jobs) != 2 {
		t.Errorf("planned %d jobs, want 2", len(jobs))
	}
}

// A finding says where it was found, so a report can be ranked on it later.
func TestFindingsCarryTheEnvironment(t *testing.T) {
	model := twoEnvironments(saga.EffectPermissions{})
	run, err := hostEngine(t, nil).Run(context.Background(), model)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, res := range run.Controls["dast"].Report.Results {
		got[res.RuleID] = res.Environment
	}
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2: %v", len(got), got)
	}
	for id, env := range got {
		if env == "" {
			t.Errorf("finding %q carries no environment", id)
		}
	}
	if got["https://staging.example.com"] == got["https://example.com"] {
		t.Errorf("both findings claim the same environment: %v", got)
	}
}
