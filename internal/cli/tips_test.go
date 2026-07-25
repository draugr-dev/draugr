package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func runWithFindings() engine.Result {
	return engine.Result{Controls: map[string]plugin.ControlResult{
		"sast": {Report: sarif.Report{Results: []sarif.Result{{RuleID: "R", Level: sarif.LevelError}}}},
	}}
}

func unclassifiedModel() *saga.Model {
	return &saga.Model{Components: []saga.Component{{Name: "web"}}}
}

func TestPrintScanTipsShownWhenUnclassified(t *testing.T) {
	var b bytes.Buffer
	printScanTips(&b, unclassifiedModel(), runWithFindings(), false)
	if !strings.Contains(b.String(), "draugr classify") {
		t.Errorf("expected the classify tip for an unclassified saga:\n%s", b.String())
	}
}

func TestPrintScanTipsSuppressed(t *testing.T) {
	// --no-tips
	var b bytes.Buffer
	printScanTips(&b, unclassifiedModel(), runWithFindings(), true)
	if b.Len() != 0 {
		t.Errorf("--no-tips should suppress tips, got %q", b.String())
	}
	// DRAUGR_NO_TIPS
	t.Setenv("DRAUGR_NO_TIPS", "1")
	var b2 bytes.Buffer
	printScanTips(&b2, unclassifiedModel(), runWithFindings(), false)
	if b2.Len() != 0 {
		t.Errorf("DRAUGR_NO_TIPS should suppress tips, got %q", b2.String())
	}
}

func TestPrintScanTipsSkippedWhenClassified(t *testing.T) {
	m := &saga.Model{Components: []saga.Component{{Name: "web", Exposure: saga.Exposure("public")}}}
	var b bytes.Buffer
	printScanTips(&b, m, runWithFindings(), false)
	if b.Len() != 0 {
		t.Errorf("classified saga should get no exposure/criticality tip, got %q", b.String())
	}
}

func TestPrintScanTipsSkippedWhenNoFindings(t *testing.T) {
	var b bytes.Buffer
	printScanTips(&b, unclassifiedModel(), engine.Result{}, false)
	if b.Len() != 0 {
		t.Errorf("no findings should mean no tip, got %q", b.String())
	}
}
