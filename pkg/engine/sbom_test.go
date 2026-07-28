package engine

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sbom"
)

// fakeSBOM records what it was asked to inventory, so dedup and ordering are assertable without
// Syft on PATH.
type fakeSBOM struct {
	calls []string
	fail  bool
}

func (f *fakeSBOM) Generate(_ context.Context, component string, t plugin.Target, format saga.SBOMFormat) (sbom.Document, error) {
	f.calls = append(f.calls, component+"/"+t.Identity())
	if f.fail {
		return sbom.Document{}, errors.New("syft exploded")
	}
	return sbom.Document{Component: component, Target: t.Identity(), Format: format, Bytes: []byte("{}")}, nil
}

func sbomModel() saga.Model {
	return saga.Model{
		Release: saga.Release{Name: "app", Version: "1"},
		Config:  saga.Config{SBOM: &saga.SBOMConfig{Enabled: true, Format: saga.SBOMCycloneDXJSON}},
		Components: []saga.Component{
			{
				Name:         "web",
				Repositories: []saga.Repository{{URL: "https://git/web"}},
				Images:       []saga.Image{{Image: "web:1"}, {Image: "sidecar:2"}},
			},
			{Name: "api", Repositories: []saga.Repository{{URL: "https://git/api"}}},
		},
	}
}

func TestSBOMDisabledDoesNothing(t *testing.T) {
	f := &fakeSBOM{}
	m := sbomModel()
	m.Config.SBOM = nil

	res, err := New(NewRegistry(), WithSBOM(f)).Run(context.Background(), m)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(f.calls) != 0 {
		t.Errorf("generator was called %d times with SBOM disabled", len(f.calls))
	}
	if len(res.SBOMs) != 0 || res.ScanErrors != nil {
		t.Errorf("want a clean run, got SBOMs=%d errors=%v", len(res.SBOMs), res.ScanErrors)
	}
}

func TestSBOMGeneratesOnePerDistinctTarget(t *testing.T) {
	f := &fakeSBOM{}
	res, err := New(NewRegistry(), WithSBOM(f)).Run(context.Background(), sbomModel())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := []string{"web/https://git/web@", "web/web:1", "web/sidecar:2", "api/https://git/api@"}
	if strings.Join(f.calls, ",") != strings.Join(want, ",") {
		t.Errorf("calls = %v\nwant  = %v", f.calls, want)
	}
	if len(res.SBOMs) != 4 {
		t.Fatalf("SBOMs = %d, want 4", len(res.SBOMs))
	}
	// The configured format has to reach the generator; defaulting silently to SPDX when the
	// Saga asked for CycloneDX would produce documents the consumer can't parse.
	for _, d := range res.SBOMs {
		if d.Format != saga.SBOMCycloneDXJSON {
			t.Errorf("document %s has format %q, want the configured one", d.Target, d.Format)
		}
	}
}

func TestSBOMDeduplicatesRepeatedTargets(t *testing.T) {
	// The same image in two components is one artifact, not two: the inventory of an image does
	// not depend on who references it.
	f := &fakeSBOM{}
	m := sbomModel()
	m.Components = []saga.Component{
		{Name: "a", Images: []saga.Image{{Image: "shared:1"}}},
		{Name: "b", Images: []saga.Image{{Image: "shared:1"}}},
	}
	res, err := New(NewRegistry(), WithSBOM(f)).Run(context.Background(), m)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(f.calls) != 1 || len(res.SBOMs) != 1 {
		t.Errorf("calls=%v SBOMs=%d, want one of each", f.calls, len(res.SBOMs))
	}
}

func TestSBOMFailureIsReportedAndMakesTheRunIncomplete(t *testing.T) {
	// Asking for an inventory and not getting one must not pass quietly — the same rule that
	// makes a missing scanner fail the gate rather than reporting a clean pass.
	f := &fakeSBOM{fail: true}
	res, err := New(NewRegistry(), WithSBOM(f)).Run(context.Background(), sbomModel())
	if err != nil {
		t.Fatalf("Run should not error on SBOM failure, it records it: %v", err)
	}
	msgs, ok := res.ScanErrors[sbomPseudoControl]
	if !ok {
		t.Fatalf("ScanErrors = %v, want an entry under %q", res.ScanErrors, sbomPseudoControl)
	}
	if len(msgs) != 4 {
		t.Errorf("want one error per target, got %d: %v", len(msgs), msgs)
	}
	if len(res.SBOMs) != 0 {
		t.Errorf("no documents should survive a total failure, got %d", len(res.SBOMs))
	}
}

func TestSBOMEnabledWithoutAGeneratorIsAnError(t *testing.T) {
	// Silence here would be the worst outcome: the Saga says "produce evidence", the run says
	// nothing, and the absence looks deliberate.
	res, err := New(NewRegistry()).Run(context.Background(), sbomModel())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	msgs := res.ScanErrors[sbomPseudoControl]
	if len(msgs) != 1 || !strings.Contains(msgs[0], "no generator") {
		t.Errorf("ScanErrors[%s] = %v, want a missing-generator error", sbomPseudoControl, msgs)
	}
}

func TestSBOMStopsOnContextCancellation(t *testing.T) {
	f := &fakeSBOM{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, _ := New(NewRegistry(), WithSBOM(f)).Run(ctx, sbomModel())
	if len(f.calls) != 0 {
		t.Errorf("a cancelled run should not start generating: %v", f.calls)
	}
	if len(res.ScanErrors[sbomPseudoControl]) == 0 {
		t.Error("cancellation should be recorded, not silently skipped")
	}
}
