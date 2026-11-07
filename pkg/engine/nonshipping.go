package engine

import (
	"strings"

	"github.com/draugr-dev/draugr/internal/nonshipping"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A repository holds more than what it ships. Documentation carries example manifests, a test tree
// carries fixtures written to be insecure, and an example application is written for clarity rather
// than for production. Every scanner that walks the tree reports them as it reports the code, and in
// a chart repository the fixtures outnumber the chart by thousands to one.
//
// So each finding of a control that opts in is marked with the kind of directory its file sits
// under, and the control's nonShippingPaths decides whether those count. The mark is a fact about
// the path, the same whichever scanner reported it, and the report lists marked findings after the
// rest whether they count or not.

// nonShippingSetting is a control's nonShippingPaths.
var nonShippingSetting = settingPolicy{
	covers: func(r *sarif.Result) bool { return r.NonShipping != "" },
	decide: func(c plugin.Controller) (func(saga.Model, string) (bool, string), bool) {
		p, ok := c.(plugin.NonShippingPolicy)
		if !ok {
			return nil, false
		}
		return p.ReportsNonShipping, true
	},
	justification: sarif.JustificationNonShipping,
}

// markNonShipping marks each finding of a control implementing NonShippingPolicy whose file sits
// under a directory of documentation, examples or tests.
//
// Only those controls. A control that does not implement it is one whose findings stay live
// wherever they are, and secrets is the case: a credential committed in a test fixture still opens
// whatever it opens.
//
// The path is read below the repository path the component declares, so a component a descriptor
// roots at `examples/demo` on purpose is scanned as the shipped code it says it is. Only what lies
// beneath that root is matched.
func (e *Engine) markNonShipping(controls map[string]plugin.ControlResult, model saga.Model) {
	for name, cr := range controls {
		ctrl, ok := e.reg.Controller(name)
		if !ok {
			continue
		}
		if _, ok := ctrl.(plugin.NonShippingPolicy); !ok {
			continue
		}
		for i := range cr.Report.Results {
			res := &cr.Report.Results[i]
			res.NonShipping = nonshipping.KindOf(belowDeclaredRoot(model, res.Component, res.Location.URI))
		}
		controls[name] = cr
	}
}

// belowDeclaredRoot is uri with the longest repository path the component declares removed from
// its front, or uri unchanged where no declared path holds it.
//
// Every repository of the component is consulted rather than the one the finding names, because a
// finding names its repository by where the checkout came from, which for a local path is the
// remote it resolved to rather than the URL the descriptor wrote.
func belowDeclaredRoot(model saga.Model, component, uri string) string {
	best := ""
	for i := range model.Components {
		comp := &model.Components[i]
		if comp.Name != component {
			continue
		}
		for _, repo := range comp.Repositories {
			for _, p := range repo.Paths {
				p = strings.Trim(strings.TrimSuffix(strings.TrimSuffix(strings.TrimSpace(p), "/**"), "/*"), "/")
				if p == "" || p == "." {
					continue
				}
				if strings.HasPrefix(uri, p+"/") && len(p) > len(best) {
					best = p
				}
			}
		}
	}
	if best == "" {
		return uri
	}
	return strings.TrimPrefix(uri, best+"/")
}

// applyNonShipping sets aside each marked finding whose component's control says not to count them,
// and returns how many it set aside. After the dependency settings, so a finding in a development
// dependency declared in a test manifest keeps the development reason.
func (e *Engine) applyNonShipping(controls map[string]plugin.ControlResult, model saga.Model) (suppressed int) {
	return e.applySetting(controls, model, nonShippingSetting)
}
