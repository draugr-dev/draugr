package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// privilegedScanner reads its target and declares that it needs more access than reading takes.
type privilegedScanner struct{ fakeScanner }

func (privilegedScanner) Info() plugin.ScannerInfo {
	return plugin.ScannerInfo{Name: "fake", Effects: []plugin.Effect{{
		Kind: plugin.EffectPrivilege, Detail: "reads the node's filesystem as root",
	}}}
}

// TestTheFlagsEffectsReachReportJSON: the descriptor accepts mutate, --allow-effects accepts
// privilege for this run, and report.json carries both lists, so a reader judging the run sees the
// effect no reviewed file accepted.
func TestTheFlagsEffectsReachReportJSON(t *testing.T) {
	reg := engine.NewRegistry()
	reg.RegisterController(fakeController{})
	reg.RegisterScanner(privilegedScanner{fakeScanner{level: sarif.LevelNote}})
	path := writeSaga(t, `
project: app
release:
  version: "1.0"
config:
  allowEffects: [mutate]
  controls:
    images:
      enabled: true
components:
  - name: web
    images:
      - image: repo/web:1
  - name: api
    images:
      - image: repo/api:1
`)
	dir := t.TempDir()
	opts := scanOptions{failOn: "error", outputDir: dir, allowEffects: []string{"privilege"}}
	if err := runScan(context.Background(), path, opts, reg, &bytes.Buffer{}); err != nil {
		t.Fatalf("runScan: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "report.json")) // #nosec G304 -- test-controlled path under t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Effects struct {
			Declared []string `json:"declared"`
			Allowed  []string `json:"allowed"`
			Used     []struct{ Kind, Detail string }
		} `json:"effects"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("report.json: %v", err)
	}
	if !slices.Equal(doc.Effects.Declared, []string{"mutate"}) {
		t.Errorf("declared = %v, want the descriptor's [mutate]", doc.Effects.Declared)
	}
	if !slices.Equal(doc.Effects.Allowed, []string{"mutate", "privilege"}) {
		t.Errorf("allowed = %v, want [mutate privilege] after --allow-effects", doc.Effects.Allowed)
	}
	if len(doc.Effects.Used) != 1 || doc.Effects.Used[0].Kind != "privilege" ||
		doc.Effects.Used[0].Detail != "reads the node's filesystem as root" {
		t.Errorf("used = %+v, want the privilege the scanner declared, once for both images", doc.Effects.Used)
	}
}
