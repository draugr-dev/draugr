package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func unclassifiedModel() *saga.Model {
	return &saga.Model{Components: []saga.Component{{Name: "web"}}}
}

// tips builds a context for a run nothing else is asserted about, so each test can set only the
// one field it is exercising.
func tips(model *saga.Model, run engine.Result, opts *scanOptions) tipContext {
	if opts == nil {
		opts = &scanOptions{format: "console"}
	}
	return tipContext{model: model, run: run, opts: opts}
}

func TestSuggestionsAreSuppressible(t *testing.T) {
	// --no-tips and DRAUGR_NO_TIPS take the advisory rows away and leave the report's own alone.
	slow := engine.Result{Stats: engine.Stats{Duration: 3 * time.Minute}}
	if got := scanSuggestions(tips(unclassifiedModel(), slow, nil)); len(got) == 0 {
		t.Fatal("an uncached three-minute run is the case --cache-dir exists for")
	}
	if got := scanSuggestions(tips(unclassifiedModel(), slow, &scanOptions{noTips: true})); got != nil {
		t.Errorf("--no-tips should suppress them, got %+v", got)
	}
	t.Setenv("DRAUGR_NO_TIPS", "1")
	if got := scanSuggestions(tips(unclassifiedModel(), slow, nil)); got != nil {
		t.Errorf("DRAUGR_NO_TIPS should suppress them, got %+v", got)
	}
}

func TestUncoveredSurfacesReachTheReport(t *testing.T) {
	// The case it exists for: an empty report over a surface nobody looked at is exactly when a
	// reader concludes there is nothing to find.
	model := &saga.Model{Components: []saga.Component{{Name: "svc", Images: []saga.Image{{Image: "i"}}}}}
	got := uncoveredFor(model)
	if len(got) != 1 || got[0].Component != "svc" || got[0].Surface != "images" {
		t.Fatalf("the gap must travel with the report, got %+v", got)
	}
	if len(got[0].Controls) == 0 {
		t.Error("a gap that does not name the control that would close it cannot be acted on")
	}
}

func TestSurfaceNoteCountsEveryControlThatLooksAtAHost(t *testing.T) {
	// dast is one of the three, and a note that leaves it out describes a host nothing is testing
	// as missing two controls. What Draugr will and will not enable for somebody is a different
	// question from what is looking at their service.
	model := &saga.Model{Components: []saga.Component{{Name: "web", Hosts: []saga.Host{{URL: "h"}}}}}
	var out bytes.Buffer
	printUncoveredSurfaceNote(&out, model)
	for _, want := range []string{"web hosts", "3 controls off", "dast, headers, tls"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the note never said %q:\n%s", want, out.String())
		}
	}
}

func TestSurfaceNoteOmitsDastWithoutHosts(t *testing.T) {
	// dast only looks at a host, so on an image-only descriptor it is not among the controls that
	// would have examined anything.
	model := &saga.Model{Components: []saga.Component{{Name: "svc", Images: []saga.Image{{Image: "i"}}}}}
	var out bytes.Buffer
	printUncoveredSurfaceNote(&out, model)
	if strings.Contains(out.String(), "dast") {
		t.Errorf("no hosts declared, so dast is not the reader's question:\n%s", out.String())
	}
}

func TestSurfaceNoteSaysNothingWhenCovered(t *testing.T) {
	model := &saga.Model{
		Config:     saga.Config{Controls: map[string]saga.ControllerSettings{"headers": {"enabled": true}, "tls": {"enabled": true}}},
		Components: []saga.Component{{Name: "web", Hosts: []saga.Host{{URL: "h"}}}},
	}
	var out bytes.Buffer
	printUncoveredSurfaceNote(&out, model)
	if out.Len() != 0 {
		t.Errorf("everything covered, so no note and no dast clause:\n%s", out.String())
	}
}

// priorityRun returns a run holding one finding at the given priority.
func priorityRun(priority string) engine.Result {
	return engine.Result{Controls: map[string]plugin.ControlResult{
		"sca": {Report: sarif.Report{Results: []sarif.Result{
			{RuleID: "CVE-1", Level: sarif.LevelError, Priority: priority},
		}}},
	}}
}

func TestPriorityGateTipFiresOnAPassCarryingP1s(t *testing.T) {
	// The one tip here that corrects the reader's model of the run rather than extending it: a
	// PASS carrying a P1, on a run judged by severity. On a run judged by the band there is
	// nothing to correct, because the band is what failed or did not.
	c := tipContext{
		model:   &saga.Model{Components: []saga.Component{{Name: "web", Exposure: saga.Exposure("public")}}},
		run:     priorityRun("P1"),
		verdict: norn.Result{Verdict: norn.Pass},
		opts:    &scanOptions{format: "console", failOn: "critical"},
	}
	if !tipByName(t, "priority-gate").when(c) {
		t.Fatal("a pass carrying a P1 under a severity gate is the case this exists for")
	}
	if got := tipByName(t, "priority-gate").what(c); got != "--fail-on P2" {
		t.Errorf("the tip must name the flag that changes the outcome: %q", got)
	}
	// And it says nothing where the gate already reads the band: telling somebody to add the gate
	// they are running reads as the product not knowing what it did.
	c.opts = &scanOptions{format: "console"}
	if tipByName(t, "priority-gate").when(c) {
		t.Error("the tip fired on a run already judged by the band")
	}
}

func TestPriorityGateTipIsSilentWhenAlreadyGated(t *testing.T) {
	base := tipContext{
		model:   &saga.Model{Components: []saga.Component{{Name: "web"}}},
		run:     priorityRun("P1"),
		verdict: norn.Result{Verdict: norn.Pass},
	}
	for _, tc := range []struct {
		name string
		opts *scanOptions
	}{
		{"already gated on priority", &scanOptions{failOnPriority: "P2"}},
		{"gate switched off entirely", &scanOptions{noGate: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			c.opts = tc.opts
			if tipByName(t, "priority-gate").when(c) {
				t.Error("advising a gate the caller has already decided about is noise")
			}
		})
	}
}

func TestPriorityGateTipIsSilentOnAFail(t *testing.T) {
	// Nothing to correct: the run already failed, so the reader is not about to walk away
	// believing a P1 was acceptable.
	c := tipContext{
		model:   &saga.Model{Components: []saga.Component{{Name: "web"}}},
		run:     priorityRun("P1"),
		verdict: norn.Result{Verdict: norn.Fail},
		opts:    &scanOptions{},
	}
	if tipByName(t, "priority-gate").when(c) {
		t.Error("a failing run needs no advice about failing")
	}
}

func TestPriorityGateTipIgnoresLowerBands(t *testing.T) {
	c := tipContext{
		model:   &saga.Model{Components: []saga.Component{{Name: "web"}}},
		run:     priorityRun("P3"),
		verdict: norn.Result{Verdict: norn.Pass},
		opts:    &scanOptions{},
	}
	if tipByName(t, "priority-gate").when(c) {
		t.Error("P3 findings on a pass are not a gate the reader is missing")
	}
}

func TestCountAtOrAboveSkipsSuppressed(t *testing.T) {
	// A suppressed finding was decided about by somebody, with a reason. Counting it towards
	// "you should gate harder" would advise the reader to re-litigate their own exclusion.
	run := engine.Result{Controls: map[string]plugin.ControlResult{
		"sca": {Report: sarif.Report{Results: []sarif.Result{
			{RuleID: "a", Priority: "P1"},
			{RuleID: "b", Priority: "P1", Suppression: &sarif.Suppression{Justification: "accepted"}},
		}}},
	}}
	if got := countAtOrAbove(run, "P2"); got != 1 {
		t.Errorf("got %d, want 1, the suppressed finding must not count", got)
	}
}

func TestCacheTipWaitsForARunSlowEnoughToMatter(t *testing.T) {
	slow := tipContext{
		model: unclassifiedModel(),
		run:   engine.Result{Stats: engine.Stats{Duration: 3 * time.Minute}},
		opts:  &scanOptions{},
	}
	if !tipByName(t, "cache").when(slow) {
		t.Error("three uncached minutes is what --cache-dir is for")
	}
	if got := tipByName(t, "cache").why(slow); !strings.Contains(got, "3m0s") {
		t.Errorf("the tip should quote the time it is arguing about: %q", got)
	}

	quick := slow
	quick.run = engine.Result{Stats: engine.Stats{Duration: 2 * time.Second}}
	if tipByName(t, "cache").when(quick) {
		t.Error("advice that costs more attention than it saves time is noise")
	}

	cached := slow
	cached.opts = &scanOptions{cacheDir: "/tmp/c"}
	if tipByName(t, "cache").when(cached) {
		t.Error("the caller already has a cache")
	}
}

func TestScanTipsAreCappedPerRun(t *testing.T) {
	// Every tip below is individually reasonable, which is exactly how a tip block becomes
	// furniture. The cap is the thing being tested.
	t.Setenv("CI", "true")
	c := tipContext{
		// A declared surface nothing looks at, so the controls tip has something to answer too.
		model:   &saga.Model{Components: []saga.Component{{Name: "web", Hosts: []saga.Host{{URL: "h"}}}}},
		run:     engine.Result{Stats: engine.Stats{Duration: 5 * time.Minute}, Controls: capRunControls()},
		verdict: norn.Result{Verdict: norn.Pass},
		// Judged on severity, which is what the priority-gate tip is about. Under the default the
		// gate already reads the band and that tip has nothing to say.
		opts: &scanOptions{format: "console", failOn: "critical"},
	}
	// All four conditions hold.
	for _, tip := range scanTips {
		if !tip.when(c) {
			t.Fatalf("test setup no longer triggers %q, so the cap is not what is being measured", tip.name)
		}
	}
	got := scanSuggestions(c)
	if len(got) != maxTipsPerRun {
		t.Errorf("offered %d, want the cap of %d: %+v", len(got), maxTipsPerRun, got)
	}
	// And the ones offered are the two the ordering promises.
	if got[0].What != "--fail-on P2" || got[1].What != "builtBy: upstream" {
		t.Errorf("the cap must keep the highest-consequence tips, not the first two to evaluate: %+v", got)
	}
}

func TestEveryTipHasADistinctName(t *testing.T) {
	seen := map[string]bool{}
	for _, tip := range scanTips {
		if tip.name == "" {
			t.Error("a tip with no name cannot be asserted on")
		}
		if seen[tip.name] {
			t.Errorf("duplicate tip name %q", tip.name)
		}
		seen[tip.name] = true
	}
}

// tipByName finds a tip in the library, failing the test if the name has moved.
func tipByName(t *testing.T, name string) scanTip {
	t.Helper()
	for _, tip := range scanTips {
		if tip.name == name {
			return tip
		}
	}
	t.Fatalf("no tip named %q", name)
	return scanTip{}
}

// capRunControls is a run that satisfies every tip's condition at once, so the cap is the only
// thing the test measures. An image finding is here because the built-upstream tip needs one.
func capRunControls() map[string]plugin.ControlResult {
	controls := priorityRun("P1").Controls
	controls["images"] = plugin.ControlResult{Report: sarif.Report{Results: []sarif.Result{
		{RuleID: "CVE-2", Level: sarif.LevelError, Priority: "P1", Image: "vendor/redis:8.2.2"},
	}}}
	return controls
}
