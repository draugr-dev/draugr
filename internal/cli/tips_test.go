package cli

import (
	"bytes"
	"slices"
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

func TestUncoveredSurfacesNamesWhatNobodyChecks(t *testing.T) {
	// A descriptor declaring a host with the host controls off scans everything about that
	// component except the thing it exposes to the internet, and says nothing.
	model := &saga.Model{
		Config: saga.Config{Controllers: map[string]saga.ControllerSettings{
			"sca": {"enabled": true},
		}},
		Components: []saga.Component{
			{Name: "web", Repositories: []saga.Repository{{URL: "u"}}, Hosts: []saga.Host{{URL: "h"}}},
			{Name: "svc", Images: []saga.Image{{Image: "i"}}},
		},
	}
	got := uncoveredSurfaces(model)
	want := []string{
		"web declares hosts, and headers, tls are not enabled",
		"svc declares images, and images is not enabled",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestUncoveredSurfacesTreatsPartialCoverAsCovered(t *testing.T) {
	// One enabled control means somebody is looking. Nagging about the rest would make the note
	// routine, and a routine note is one nobody reads.
	model := &saga.Model{
		Config: saga.Config{Controllers: map[string]saga.ControllerSettings{
			"headers": {"enabled": true},
		}},
		Components: []saga.Component{{Name: "web", Hosts: []saga.Host{{URL: "h"}}}},
	}
	if got := uncoveredSurfaces(model); len(got) != 0 {
		t.Errorf("partial cover is cover: %q", got)
	}
}

func TestUncoveredSurfacesRespectsAPerComponentOverride(t *testing.T) {
	// A control enabled on the component alone still counts as looking.
	model := &saga.Model{
		Components: []saga.Component{{
			Name:        "svc",
			Images:      []saga.Image{{Image: "i"}},
			Controllers: map[string]saga.ControllerSettings{"images": {"enabled": true}},
		}},
	}
	if got := uncoveredSurfaces(model); len(got) != 0 {
		t.Errorf("a per-component enable is still enabled: %q", got)
	}
}

func TestUncoveredSurfacesIsSilentWhenEverythingIsCovered(t *testing.T) {
	model := &saga.Model{
		Config:     saga.Config{Controllers: map[string]saga.ControllerSettings{"sca": {"enabled": true}}},
		Components: []saga.Component{{Name: "web", Repositories: []saga.Repository{{URL: "u"}}}},
	}
	if got := uncoveredSurfaces(model); len(got) != 0 {
		t.Errorf("nothing to say: %q", got)
	}
}

func TestScanTipsNoteAppearsWithoutAnyFindings(t *testing.T) {
	// The case the note exists for: an empty report over a surface nobody looked at is exactly
	// when a reader concludes there is nothing to find.
	model := &saga.Model{Components: []saga.Component{{Name: "svc", Images: []saga.Image{{Image: "i"}}}}}
	var out bytes.Buffer
	printScanTips(&out, model, engine.Result{}, false)
	if !strings.Contains(out.String(), "nothing checks part of what this descriptor declares") {
		t.Errorf("the note must not depend on findings:\n%s", out.String())
	}
}

func TestScanTipsNoteIsSuppressible(t *testing.T) {
	model := &saga.Model{Components: []saga.Component{{Name: "svc", Images: []saga.Image{{Image: "i"}}}}}
	var out bytes.Buffer
	printScanTips(&out, model, engine.Result{}, true)
	if out.Len() != 0 {
		t.Errorf("--no-tips should silence it:\n%s", out.String())
	}
	t.Setenv("DRAUGR_NO_TIPS", "1")
	var env bytes.Buffer
	printScanTips(&env, model, engine.Result{}, false)
	if env.Len() != 0 {
		t.Errorf("DRAUGR_NO_TIPS should silence it:\n%s", env.String())
	}
}
