package engine

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/sbom"
)

// TestConsentRecordsTheFlagBesideTheDescriptor: --allow-effects accepts an effect no reviewed file
// names, and the record keeps the descriptor's list beside the run's so the difference shows.
func TestConsentRecordsTheFlagBesideTheDescriptor(t *testing.T) {
	s := effectScanner{
		name:    "needs-root",
		effects: []plugin.Effect{{Kind: plugin.EffectPrivilege, Detail: "reads the host filesystem"}},
	}
	// Spelled as somebody types a flag, and repeating what the descriptor already accepts.
	e := effectEngine(t, s, WithAllowedEffects([]string{" Privilege ", "mutate"}))
	res, err := e.Run(context.Background(), effectModel("network", "mutate"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := EffectConsent{
		Declared: []plugin.EffectKind{plugin.EffectMutate, plugin.EffectNetwork},
		Allowed:  []plugin.EffectKind{plugin.EffectMutate, plugin.EffectNetwork, plugin.EffectPrivilege},
	}
	if !slices.Equal(res.Consent.Declared, want.Declared) || !slices.Equal(res.Consent.Allowed, want.Allowed) {
		t.Errorf("Consent = %+v, want %+v", res.Consent, want)
	}
	if len(res.Effects) != 1 || res.Effects[0].Kind != plugin.EffectPrivilege {
		t.Errorf("Effects = %+v, want the privilege the flag let run", res.Effects)
	}
}

// TestConsentWithNothingAcceptedIsEmpty: a descriptor that accepts nothing and a run given no flag
// record nothing on either side.
func TestConsentWithNothingAcceptedIsEmpty(t *testing.T) {
	res, err := effectEngine(t, effectScanner{name: "reads"}).Run(context.Background(), effectModel())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Consent.Declared) != 0 || len(res.Consent.Allowed) != 0 {
		t.Errorf("Consent = %+v, want nothing accepted", res.Consent)
	}
}

// controlScanner serves one named control and declares whatever effects a test needs.
type controlScanner struct {
	name, control string
	effects       []plugin.Effect
	// ran is set by every job, and jobs run concurrently.
	ran *atomic.Bool
}

func (s controlScanner) Info() plugin.ScannerInfo {
	return plugin.ScannerInfo{
		Name: s.name, Controls: []string{s.control},
		TargetKinds: []plugin.TargetKind{plugin.TargetImage}, Effects: s.effects,
	}
}

func (s controlScanner) Scan(context.Context, plugin.Target, plugin.Config) (sarif.Report, error) {
	if s.ran != nil {
		s.ran.Store(true)
	}
	return sarif.Report{Tool: s.name}, nil
}

// controlPlanner plans one job per image for its scanner, under its own control name.
type controlPlanner struct{ name, scanner string }

func (c controlPlanner) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: c.name, Scope: plugin.ScopeComponent, DefaultScanners: []string{c.scanner}}
}

func (c controlPlanner) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	var jobs []plugin.ScanJob
	for _, img := range comp.Images {
		jobs = append(jobs, plugin.ScanJob{Scanner: c.scanner, Target: plugin.ImageTarget{Ref: img.Image}})
	}
	return jobs, nil
}

func (c controlPlanner) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	return plugin.ControlResult{Control: c.name, Report: sarif.Merge(reports...)}, nil
}

// TestAScopedRunUsesLessThanTheDescriptorAccepts: --controls narrows the run to a control whose
// scanner only reads, so the effect the descriptor accepts for the other control is accepted and
// not used. A record of the descriptor alone would describe a cluster change that never happened.
func TestAScopedRunUsesLessThanTheDescriptorAccepts(t *testing.T) {
	var changed atomic.Bool
	reg := NewRegistry()
	reg.RegisterController(controlPlanner{name: "images", scanner: "reads"})
	reg.RegisterController(controlPlanner{name: "cluster", scanner: "creates-a-job"})
	reg.RegisterScanner(controlScanner{name: "reads", control: "images"})
	reg.RegisterScanner(controlScanner{
		name: "creates-a-job", control: "cluster", ran: &changed,
		effects: []plugin.Effect{{Kind: plugin.EffectMutate, Detail: "creates a Job in the cluster"}},
	})
	model := saga.Model{
		Config: saga.Config{
			Controls: map[string]saga.ControllerSettings{
				"images": {"enabled": true}, "cluster": {"enabled": true},
			},
			AllowEffects: saga.EffectPermissions{"mutate"},
		},
		Components: []saga.Component{
			{Name: "web", Images: []saga.Image{{Image: "web:1"}}},
			{Name: "api", Images: []saga.Image{{Image: "api:1"}}},
		},
	}

	whole, err := New(reg).Run(context.Background(), model)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(whole.Effects) != 1 || whole.Effects[0].Kind != plugin.EffectMutate {
		t.Fatalf("the unscoped run used %+v, want the mutate it accepted", whole.Effects)
	}

	changed.Store(false)
	scoped, err := New(reg, WithScope(Scope{Controls: []string{"images"}})).Run(context.Background(), model)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if changed.Load() {
		t.Fatal("the scope left the cluster control out, and its scanner ran anyway")
	}
	if len(scoped.Effects) != 0 {
		t.Errorf("the scoped run used %+v, want nothing beyond reading", scoped.Effects)
	}
	accepted := []plugin.EffectKind{plugin.EffectMutate}
	if !slices.Equal(scoped.Consent.Declared, accepted) || !slices.Equal(scoped.Consent.Allowed, accepted) {
		t.Errorf("Consent = %+v, want mutate declared and allowed", scoped.Consent)
	}
}

// pickySBOM inventories every target except those it is told to fail on.
type pickySBOM struct{ failOn map[string]string }

func (g pickySBOM) Generate(_ context.Context, component string, t plugin.Target, format saga.SBOMFormat) (sbom.Document, error) {
	name := sbom.TargetName(t)
	if reason, ok := g.failOn[name]; ok {
		return sbom.Document{}, errors.New(reason)
	}
	return sbom.Document{Component: component, Target: name, Format: format, Bytes: []byte(`{"bomFormat":"CycloneDX"}`)}, nil
}

func (pickySBOM) Assemble(_ string, _ saga.Release, f saga.SBOMFormat, docs []sbom.Document) (sbom.Document, error) {
	if len(docs) == 0 {
		return sbom.Document{}, errors.New("config.sbom.scope: nothing to assemble into a project document")
	}
	return sbom.Document{Project: true, Format: f, Bytes: []byte(`{"bomFormat":"CycloneDX","assembled":true}`)}, nil
}

// twoRepositories is one component holding two repositories, the shape that collapses a
// per-repository result into a per-component one, and a second component beside it.
func twoRepositories(scope saga.SBOMScope) saga.Model {
	return saga.Model{
		Project: "shop",
		Release: saga.Release{Version: "2.0.0"},
		Config:  saga.Config{SBOM: &saga.SBOMConfig{Enabled: true, Scope: scope}},
		Components: []saga.Component{
			{Name: "storefront", Repositories: []saga.Repository{
				{URL: "https://github.com/acme/storefront"},
				{URL: "https://github.com/acme/storefront-theme"},
			}},
			{Name: "api", Images: []saga.Image{{Image: "ghcr.io/acme/api:2.0.0"}}},
		},
	}
}

// TestAnSBOMThatFailsForOneOfTwoRepositoriesNamesIt: the failure is recorded against the
// repository it was about, the other repository's document is kept, and the run's scan errors
// say the same thing once.
func TestAnSBOMThatFailsForOneOfTwoRepositoriesNamesIt(t *testing.T) {
	gen := pickySBOM{failOn: map[string]string{
		"https://github.com/acme/storefront-theme": "checkout https://github.com/acme/storefront-theme: repository not found",
	}}
	res, err := New(NewRegistry(), WithSBOM(gen)).Run(context.Background(), twoRepositories(""))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var written []string
	for _, d := range res.SBOMs {
		written = append(written, d.Component+" "+d.Target)
	}
	want := []string{"storefront https://github.com/acme/storefront", "api ghcr.io/acme/api:2.0.0"}
	if !slices.Equal(written, want) {
		t.Errorf("documents = %v, want %v", written, want)
	}
	wantFailure := SBOMFailure{
		Scope: saga.SBOMScopeComponent, Component: "storefront", Target: "https://github.com/acme/storefront-theme",
		Format: sbom.DefaultFormat, Reason: "checkout https://github.com/acme/storefront-theme: repository not found",
	}
	if len(res.SBOMFailures) != 1 || res.SBOMFailures[0] != wantFailure {
		t.Errorf("SBOMFailures = %+v, want %+v", res.SBOMFailures, wantFailure)
	}
	if got := res.ScanErrors[sbomPseudoControl]; len(got) != 1 || got[0] != wantFailure.Reason {
		t.Errorf("ScanErrors[%s] = %v, want the one reason", sbomPseudoControl, got)
	}
}

// TestAProjectSBOMMissingATargetSaysWhichOne: under scope: project the assembled document is
// written without the repository whose inventory failed, so that repository is what the record
// has to name.
func TestAProjectSBOMMissingATargetSaysWhichOne(t *testing.T) {
	gen := pickySBOM{failOn: map[string]string{
		"https://github.com/acme/storefront": "syft https://github.com/acme/storefront: exit status 1",
	}}
	res, err := New(NewRegistry(), WithSBOM(gen)).Run(context.Background(), twoRepositories(saga.SBOMScopeProject))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.SBOMs) != 1 || !res.SBOMs[0].Project {
		t.Fatalf("SBOMs = %+v, want the assembled document alone", res.SBOMs)
	}
	if len(res.SBOMFailures) != 1 || res.SBOMFailures[0].Target != "https://github.com/acme/storefront" ||
		res.SBOMFailures[0].Component != "storefront" {
		t.Errorf("SBOMFailures = %+v, want the storefront repository", res.SBOMFailures)
	}
}

// TestAProjectSBOMWithNothingToAssembleFailsAfterItsTargets: every target's inventory fails, so the
// project document has nothing to be assembled from and fails as well, after the targets that
// explain why.
func TestAProjectSBOMWithNothingToAssembleFailsAfterItsTargets(t *testing.T) {
	gen := pickySBOM{failOn: map[string]string{
		"https://github.com/acme/storefront":       "syft https://github.com/acme/storefront: exit status 1",
		"https://github.com/acme/storefront-theme": "syft https://github.com/acme/storefront-theme: exit status 1",
		"ghcr.io/acme/api:2.0.0":                   "syft ghcr.io/acme/api:2.0.0: unauthorized",
	}}
	res, err := New(NewRegistry(), WithSBOM(gen)).Run(context.Background(), twoRepositories(saga.SBOMScopeProject))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.SBOMs) != 0 {
		t.Errorf("SBOMs = %+v, want none", res.SBOMs)
	}
	var scopes []string
	for _, f := range res.SBOMFailures {
		scopes = append(scopes, string(f.Scope)+" "+f.Target)
	}
	want := []string{
		"component https://github.com/acme/storefront",
		"component https://github.com/acme/storefront-theme",
		"component ghcr.io/acme/api:2.0.0",
		"project ",
	}
	if !slices.Equal(scopes, want) {
		t.Errorf("failures = %q, want %q", scopes, want)
	}
}

// TestAnSBOMFailureWithNoTargetSaysSo: a failure that belongs to no one target, the generator
// missing or the run canceled, names none.
func TestAnSBOMFailureWithNoTargetSaysSo(t *testing.T) {
	res, err := New(NewRegistry()).Run(context.Background(), twoRepositories(saga.SBOMScopeBoth))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.SBOMFailures) != 1 {
		t.Fatalf("SBOMFailures = %+v, want one", res.SBOMFailures)
	}
	f := res.SBOMFailures[0]
	if f.Target != "" || f.Scope != saga.SBOMScopeBoth || !strings.Contains(f.Reason, "no generator") {
		t.Errorf("failure = %+v, want the configured scope, no target and the missing generator", f)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, _ = New(NewRegistry(), WithSBOM(pickySBOM{})).Run(ctx, twoRepositories(""))
	if len(res.SBOMFailures) != 1 || res.SBOMFailures[0].Target != "" ||
		res.SBOMFailures[0].Reason != context.Canceled.Error() {
		t.Errorf("SBOMFailures = %+v, want the cancellation once, naming no target", res.SBOMFailures)
	}
}
