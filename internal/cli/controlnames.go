package cli

import (
	"fmt"
	"strings"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// checkControlNames rejects a descriptor that names a control this build cannot run.
//
// Fatal rather than reported. A control name is written because someone decided a check should
// happen or a threshold should differ; if the name is wrong, the decision is not being applied
// and the run goes green anyway. That is a descriptor claiming something it is not doing, and it
// survives review because it looks exactly like a descriptor that works.
//
// Checked against the **registry**, not a fixed list. "Unknown" therefore means *this binary
// cannot run it* — which stays the right question if controls ever arrive from plugins, because
// a descriptor asking for a control the runner does not have should fail there too. Skipping it
// silently would be the green tick that means nothing.
func checkControlNames(reg *engine.Registry, model *saga.Model) error {
	known := map[string]bool{}
	for _, c := range reg.Controllers() {
		known[c.Info().Name] = true
	}

	// Ordered so the message is stable between runs, and grouped so a descriptor with several
	// mistakes reports all of them rather than one per re-run.
	var problems []string
	report := func(where, name string) {
		if name == "" || known[name] {
			return
		}
		msg := fmt.Sprintf("%s: %q is not a control this build of Draugr provides", where, name)
		if near := nearestControl(name, known); near != "" {
			msg += fmt.Sprintf(" — did you mean %q?", near)
		}
		problems = append(problems, msg)
	}

	for _, name := range sortedKeys(model.Config.Controllers) {
		report("config.controllers", name)
	}
	if g := model.Config.Gate; g != nil {
		for _, name := range sortedKeys(g.Controls) {
			report("config.gate.controls", name)
		}
	}
	for i := range model.Components {
		c := &model.Components[i]
		for _, name := range sortedKeys(c.Controllers) {
			report(fmt.Sprintf("components[%q].controllers", c.Name), name)
		}
	}

	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("%s\n\nrun `draugr controls` to see what this build provides",
		strings.Join(problems, "\n"))
}

// nearestControl returns the known control closest to name, or "" when nothing is close enough.
//
// The suggestion is most of the value: "iaac is not a control" leaves someone scanning a list,
// and "did you mean iac?" ends it. The threshold keeps it honest — a wild guess beside an error
// is worse than no guess, because it sends the reader somewhere wrong.
func nearestControl(name string, known map[string]bool) string {
	best, bestDist := "", 0
	for candidate := range known {
		d := editDistance(strings.ToLower(name), candidate)
		// At most a third of the name wrong, and never more than three edits: enough for a typo,
		// not enough to match a different control.
		limit := min(len(candidate)/3+1, 3)
		if d > limit {
			continue
		}
		if best == "" || d < bestDist || (d == bestDist && candidate < best) {
			best, bestDist = candidate, d
		}
	}
	return best
}
