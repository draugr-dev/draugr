package engine

import (
	"github.com/draugr-dev/draugr/internal/nonshipping"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// markToolDependencies marks each dependency finding in a file a developer tool's dependencies are
// pinned in, such as a lockfile under `.config/mise/`, so the report lists it after the
// application's own and names it as a tool's. It still counts: the tool runs in CI and on
// developers' machines.
//
// Only sca, which reads a repository's dependency files. The path is read below the repository
// path the component declares, as the non-shipping mark's is, and a finding already marked as
// under docs, examples or tests keeps that mark alone.
//
// A Go module that builds nothing but tools takes the same mark from the repository scanner instead,
// because only its files say so and the checkout holding them is gone by the time this runs.
func markToolDependencies(controls map[string]plugin.ControlResult, model saga.Model) {
	cr, ok := controls["sca"]
	if !ok {
		return
	}
	for i := range cr.Report.Results {
		res := &cr.Report.Results[i]
		if res.NonShipping == "" && res.Aside == "" &&
			nonshipping.ToolDependency(belowDeclaredRoot(model, res.Component, res.Location.URI)) {
			res.Aside = sarif.AsideTooling
		}
	}
	controls["sca"] = cr
}
