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

func runWithFindings() engine.Result {
	return engine.Result{Controls: map[string]plugin.ControlResult{
		"sast": {Report: sarif.Report{Results: []sarif.Result{{RuleID: "R", Level: sarif.LevelError}}}},
	}}
}

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

func TestPrintScanTipsShownWhenUnclassified(t *testing.T) {
	t.Setenv("CI", "")
	var b bytes.Buffer
	printScanTips(&b, tips(unclassifiedModel(), runWithFindings(), nil))
	if !strings.Contains(b.String(), "draugr classify") {
		t.Errorf("expected the classify tip for an unclassified saga:\n%s", b.String())
	}
}

func TestPrintScanTipsSuppressed(t *testing.T) {
	// --no-tips
	var b bytes.Buffer
	printScanTips(&b, tips(unclassifiedModel(), runWithFindings(), &scanOptions{noTips: true}))
	if b.Len() != 0 {
		t.Errorf("--no-tips should suppress tips, got %q", b.String())
	}
	// DRAUGR_NO_TIPS
	t.Setenv("DRAUGR_NO_TIPS", "1")
	var b2 bytes.Buffer
	printScanTips(&b2, tips(unclassifiedModel(), runWithFindings(), nil))
	if b2.Len() != 0 {
		t.Errorf("DRAUGR_NO_TIPS should suppress tips, got %q", b2.String())
	}
}

func TestPrintScanTipsSkippedWhenClassified(t *testing.T) {
	t.Setenv("CI", "")
	m := &saga.Model{Components: []saga.Component{{Name: "web", Exposure: saga.Unstated(saga.Exposure("public"))}}}
	var b bytes.Buffer
	printScanTips(&b, tips(m, runWithFindings(), nil))
	if b.Len() != 0 {
		t.Errorf("classified saga should get no exposure/criticality tip, got %q", b.String())
	}
}

func TestPrintScanTipsSkippedWhenNoFindings(t *testing.T) {
	t.Setenv("CI", "")
	var b bytes.Buffer
	printScanTips(&b, tips(unclassifiedModel(), engine.Result{}, nil))
	if b.Len() != 0 {
		t.Errorf("no findings should mean no tip, got %q", b.String())
	}
}

func TestScanTipsNoteAppearsWithoutAnyFindings(t *testing.T) {
	// The case the note exists for: an empty report over a surface nobody looked at is exactly
	// when a reader concludes there is nothing to find.
	model := &saga.Model{Components: []saga.Component{{Name: "svc", Images: []saga.Image{{Image: "i"}}}}}
	var out bytes.Buffer
	printScanTips(&out, tips(model, engine.Result{}, nil))
	if !strings.Contains(out.String(), "Not checked:") {
		t.Errorf("the note must not depend on findings:\n%s", out.String())
	}
}

func TestScanTipsNoteIsSuppressible(t *testing.T) {
	model := &saga.Model{Components: []saga.Component{{Name: "svc", Images: []saga.Image{{Image: "i"}}}}}
	var out bytes.Buffer
	printScanTips(&out, tips(model, engine.Result{}, &scanOptions{noTips: true}))
	if out.Len() != 0 {
		t.Errorf("--no-tips should silence it:\n%s", out.String())
	}
	t.Setenv("DRAUGR_NO_TIPS", "1")
	var env bytes.Buffer
	printScanTips(&env, tips(model, engine.Result{}, nil))
	if env.Len() != 0 {
		t.Errorf("DRAUGR_NO_TIPS should silence it:\n%s", env.String())
	}
}

func TestSurfaceNoteExplainsWhyDastIsAbsent(t *testing.T) {
	// A reader who knows Draugr has a dast control, and sees a host listed as unchecked without
	// it, reads the omission as a gap in the note rather than as the deliberate choice it is.
	model := &saga.Model{Components: []saga.Component{{Name: "web", Hosts: []saga.Host{{URL: "h"}}}}}
	var out bytes.Buffer
	printUncoveredSurfaceNote(&out, model)
	if !strings.Contains(out.String(), "dast is never suggested") {
		t.Errorf("a host surface must say why dast is not among the controls named:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "attack traffic") {
		t.Errorf("naming dast without the reason is worse than not naming it:\n%s", out.String())
	}
}

func TestSurfaceNoteOmitsDastWithoutHosts(t *testing.T) {
	// dast only scans a host, so on a repository-only descriptor the clause answers a question
	// nobody asked — and the note is already at the length where a spare line costs it readers.
	model := &saga.Model{Components: []saga.Component{{Name: "svc", Images: []saga.Image{{Image: "i"}}}}}
	var out bytes.Buffer
	printUncoveredSurfaceNote(&out, model)
	if strings.Contains(out.String(), "dast") {
		t.Errorf("no hosts declared, so dast is not the reader's question:\n%s", out.String())
	}
}

func TestSurfaceNoteSaysNothingWhenCovered(t *testing.T) {
	model := &saga.Model{
		Config:     saga.Config{Controllers: map[string]saga.ControllerSettings{"headers": {"enabled": true}, "tls": {"enabled": true}}},
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
	// PASS that a priority gate would have failed.
	c := tipContext{
		model:   &saga.Model{Components: []saga.Component{{Name: "web", Exposure: saga.Unstated(saga.Exposure("public"))}}},
		run:     priorityRun("P1"),
		verdict: norn.Result{Verdict: norn.Pass},
		opts:    &scanOptions{format: "console"},
	}
	if !tipByName(t, "priority-gate").when(c) {
		t.Fatal("a pass with a P1 finding and no --fail-on-priority is the case this exists for")
	}
	if got := tipByName(t, "priority-gate").text(c); !strings.Contains(got, "--fail-on-priority") {
		t.Errorf("the tip must name the flag that changes the outcome: %q", got)
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
		t.Errorf("got %d, want 1 — the suppressed finding must not count", got)
	}
}

func TestPublishTipFiresOnlyInCIWithNowhereToPutTheReport(t *testing.T) {
	base := tipContext{
		model: &saga.Model{Components: []saga.Component{{Name: "web"}}},
		run:   runWithFindings(),
		opts:  &scanOptions{format: "console"},
	}
	t.Setenv("CI", "true")
	if !tipByName(t, "publish").when(base) {
		t.Fatal("in CI with no -o and no publishers, the report exists only in the log")
	}

	withOutput := base
	withOutput.opts = &scanOptions{format: "console", outputDir: "out"}
	if tipByName(t, "publish").when(withOutput) {
		t.Error("-o keeps the report, so there is nothing to say")
	}

	withPublisher := base
	withPublisher.model = &saga.Model{
		Config:     saga.Config{Publishers: []saga.PublisherConfig{{Kind: "github"}}},
		Components: []saga.Component{{Name: "web"}},
	}
	if tipByName(t, "publish").when(withPublisher) {
		t.Error("a configured publisher is already the answer")
	}

	t.Setenv("CI", "")
	if tipByName(t, "publish").when(base) {
		t.Error("at a terminal the report is on screen, which is where the reader is looking")
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
	if got := tipByName(t, "cache").text(slow); !strings.Contains(got, "3m0s") {
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
		model:   unclassifiedModel(),
		run:     engine.Result{Stats: engine.Stats{Duration: 5 * time.Minute}, Controls: capRunControls()},
		verdict: norn.Result{Verdict: norn.Pass},
		opts:    &scanOptions{format: "console"},
	}
	// All four conditions hold.
	for _, tip := range scanTips {
		if !tip.when(c) {
			t.Fatalf("test setup no longer triggers %q, so the cap is not what is being measured", tip.name)
		}
	}
	var out bytes.Buffer
	printScanTips(&out, c)
	if got := strings.Count(out.String(), "\nTip: "); got != maxTipsPerRun {
		t.Errorf("printed %d tips, want the cap of %d:\n%s", got, maxTipsPerRun, out.String())
	}
	// And the ones printed are the two the ordering promises.
	if !strings.Contains(out.String(), "--fail-on-priority") || !strings.Contains(out.String(), "only in this log") {
		t.Errorf("the cap must keep the highest-consequence tips, not the first two to evaluate:\n%s", out.String())
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
