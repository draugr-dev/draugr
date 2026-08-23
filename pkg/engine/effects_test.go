package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// effectScanner is a scanner that declares whatever effects a test needs.
type effectScanner struct {
	name    string
	effects []plugin.Effect
	ran     *bool
}

func (s effectScanner) Info() plugin.ScannerInfo {
	return plugin.ScannerInfo{
		Name:        s.name,
		Controls:    []string{"images"},
		TargetKinds: []plugin.TargetKind{plugin.TargetImage},
		Effects:     s.effects,
	}
}

func (s effectScanner) Scan(context.Context, plugin.Target, plugin.Config) (sarif.Report, error) {
	if s.ran != nil {
		*s.ran = true
	}
	return sarif.Report{Tool: s.name}, nil
}

// effectController plans one job for the scanner under test.
type effectController struct{ scanner string }

func (c effectController) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: "images", Scope: plugin.ScopeComponent, DefaultScanners: []string{c.scanner}}
}

func (c effectController) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	return []plugin.ScanJob{{Scanner: c.scanner, Target: plugin.ImageTarget{Ref: "alpine:3"}}}, nil
}

func (c effectController) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	return plugin.ControlResult{Control: "images", Report: sarif.Merge(reports...)}, nil
}

func effectModel(allow ...string) saga.Model {
	return saga.Model{
		Config: saga.Config{
			Controllers:  map[string]saga.ControllerSettings{"images": {"enabled": true}},
			AllowEffects: saga.EffectPermissions{Everywhere: allow},
		},
		Components: []saga.Component{{Name: "app", Images: []saga.Image{{Image: "alpine:3"}}}},
	}
}

func effectEngine(t *testing.T, s plugin.Scanner, opts ...Option) *Engine {
	t.Helper()
	reg := NewRegistry()
	reg.RegisterController(effectController{scanner: s.Info().Name})
	reg.RegisterScanner(s)
	return New(reg, opts...)
}

// The point of the whole mechanism: a scanner that would change the target does not get to,
// until someone has said it may.
func TestScannerWithUnacceptedEffectDoesNotRun(t *testing.T) {
	var ran bool
	s := effectScanner{
		name: "creates-things",
		ran:  &ran,
		effects: []plugin.Effect{{
			Kind: plugin.EffectMutate, Detail: "creates a Job in the cluster",
		}},
	}
	_, err := effectEngine(t, s).Run(context.Background(), effectModel())
	if err == nil {
		t.Fatal("expected the run to refuse a scanner with an unaccepted effect")
	}
	if ran {
		t.Error("the scanner ran despite its effect not being accepted")
	}
	// The refusal has to say what would have happened and how to allow it; a block nobody can
	// act on is its own dead end.
	for _, want := range []string{"creates a Job in the cluster", "allowEffects", "--allow-effects"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should contain %q, got: %v", want, err)
		}
	}
}

func TestAcceptingAnEffectInTheSagaLetsItRun(t *testing.T) {
	var ran bool
	s := effectScanner{
		name: "creates-things", ran: &ran,
		effects: []plugin.Effect{{Kind: plugin.EffectMutate, Detail: "creates a Job"}},
	}
	if _, err := effectEngine(t, s).Run(context.Background(), effectModel("mutate")); err != nil {
		t.Fatalf("accepted effect should run: %v", err)
	}
	if !ran {
		t.Error("the scanner did not run")
	}
}

// --allow-effects is the one-off equivalent of the reviewed setting.
func TestAcceptingAnEffectByFlagLetsItRun(t *testing.T) {
	var ran bool
	s := effectScanner{
		name: "needs-root", ran: &ran,
		effects: []plugin.Effect{{Kind: plugin.EffectPrivilege, Detail: "reads the host filesystem"}},
	}
	e := effectEngine(t, s, WithAllowedEffects([]string{"privilege"}))
	if _, err := e.Run(context.Background(), effectModel()); err != nil {
		t.Fatalf("flag-accepted effect should run: %v", err)
	}
	if !ran {
		t.Error("the scanner did not run")
	}
}

// A dynamic scanner exists to send traffic. Gating the thing the control is *for* would train
// people to accept without reading, so network is declared and recorded, not gated.
func TestNetworkEffectIsDeclaredNotGated(t *testing.T) {
	var ran bool
	s := effectScanner{
		name: "probes", ran: &ran,
		effects: []plugin.Effect{{Kind: plugin.EffectNetwork, Detail: "sends probe traffic"}},
	}
	res, err := effectEngine(t, s).Run(context.Background(), effectModel())
	if err != nil {
		t.Fatalf("a network effect should not block a run: %v", err)
	}
	if !ran {
		t.Error("the scanner did not run")
	}
	if len(res.Effects) != 1 || res.Effects[0].Kind != plugin.EffectNetwork {
		t.Errorf("the run should record what it did: %+v", res.Effects)
	}
}

// A scanner that only reads an artifact says nothing, which keeps the disclosure worth reading.
func TestReadOnlyScannerRecordsNoEffects(t *testing.T) {
	res, err := effectEngine(t, effectScanner{name: "reads"}).Run(context.Background(), effectModel())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Effects) != 0 {
		t.Errorf("want no effects recorded, got %+v", res.Effects)
	}
}

func TestDedupeEffects(t *testing.T) {
	net := plugin.Effect{Kind: plugin.EffectNetwork, Detail: "probes"}
	mut := plugin.Effect{Kind: plugin.EffectMutate, Detail: "creates"}
	got := dedupeEffects([]plugin.Effect{net, mut, net, mut})
	if len(got) != 2 {
		t.Fatalf("want 2 distinct effects, got %+v", got)
	}
	// Stable order, so two runs of the same scan produce the same report.
	if got[0].Kind != plugin.EffectMutate || got[1].Kind != plugin.EffectNetwork {
		t.Errorf("effects should be ordered deterministically, got %+v", got)
	}
	if dedupeEffects(nil) != nil {
		t.Error("no effects should stay nil")
	}
}

func TestEffectKindRequiresConsent(t *testing.T) {
	for kind, want := range map[plugin.EffectKind]bool{
		plugin.EffectMutate:    true,
		plugin.EffectPrivilege: true,
		plugin.EffectNetwork:   false,
	} {
		if got := kind.RequiresConsent(); got != want {
			t.Errorf("%s.RequiresConsent() = %v, want %v", kind, got, want)
		}
	}
}
