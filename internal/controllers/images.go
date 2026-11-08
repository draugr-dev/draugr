package controllers

import (
	"encoding/json"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

const (
	imagesControl = "images"
	trivyScanner  = "trivy"
)

// imagesOptionSchema describes cpeMatches where it sits, under the control.
var imagesOptionSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    ` + cpeMatchesProperty + `
  }
}`)

// Images is the container-image security control. It plans one Trivy scan per image in a
// component and aggregates the results.
type Images struct{}

// NewImages returns the images controller.
func NewImages() plugin.Controller { return Images{} }

// Info identifies the controller (component-scoped).
func (Images) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{
		Name:            imagesControl,
		Scope:           plugin.ScopeComponent,
		Summary:         "Find known flaws in the operating system and packages baked into a container image.",
		DefaultScanners: []string{"trivy"},
		OptionSchema:    imagesOptionSchema,
	}
}

// Plan produces one scan job per image declared on the component.
func (Images) Plan(model saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	// Through resolveScanners rather than named directly, even with one scanner to choose from.
	// Naming it here would discard the descriptor's images block before anything could look at it,
	// so an option written there would neither take effect nor be reported, and the scanner's
	// declared schema, which exists to make that an error, would never be consulted.
	selections := resolveScanners(model, comp, imagesControl, []string{trivyScanner})
	jobs := make([]plugin.ScanJob, 0, len(comp.Images)*len(selections))
	for _, img := range comp.Images {
		target := plugin.ImageTarget{
			Ref: img.Image, Digest: img.Digest,
			Upstream: comp.PublishesImage(img) == saga.BuiltByUpstream,
		}
		for _, sel := range selections {
			jobs = append(jobs, plugin.ScanJob{Scanner: sel.Name, Target: target, Config: sel.Config})
		}
	}
	return jobs, nil
}

// ReportsCPEMatches resolves cpeMatches for one component, and names the key that decided it: the
// component's setting first, then the project's, and with neither written the default, suppress, named
// by the project's key.
func (Images) ReportsCPEMatches(model saga.Model, component string) (bool, string) {
	return controlSetting(model, component, imagesControl, cpeMatchesKey, false)
}

// Aggregate merges the scan reports and summarizes findings by severity.
func (Images) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	merged := sarif.Merge(reports...)
	counts := merged.Counts()
	return plugin.ControlResult{
		Control: imagesControl,
		Report:  merged,
		Summary: plugin.Summary{
			Errors:   counts.Error,
			Warnings: counts.Warning,
			Notes:    counts.Note,
		},
	}, nil
}
