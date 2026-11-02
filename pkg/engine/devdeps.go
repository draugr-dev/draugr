package engine

import (
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// Whether a dependency is used only in development is a fact about one package in one manifest,
// and only some scanners report it. Trivy marks each development dependency in every lockfile
// format it reads; Grype reports some of the same packages and marks none. Left there, the same
// development dependency counted in a pnpm lockfile, where Grype reads it, and was set aside in an
// npm one, where it does not, and which of the two a reader saw depended on the format.
//
// So the mark is a property of the package in its file, and every scanner's finding about that
// package in that file carries it, whichever scanner read it there. One setting then decides
// whether those findings count.

// devPackageKey is one package in one manifest of one repository or image, for one component.
//
// The location is part of it, unlike the key correlation counts a flaw under. The same package can
// be a development dependency in one lockfile and a runtime one in another lockfile of the same
// repository, and the mark is about the first file only.
type devPackageKey struct {
	component, repository, image, purl, location string
}

// devPackageKeyOf is the key a finding's package is marked under, and false for a finding with no
// package URL to match on.
func devPackageKeyOf(res sarif.Result) (devPackageKey, bool) {
	if res.Package == nil || res.Package.PURL == "" {
		return devPackageKey{}, false
	}
	return devPackageKey{
		component: res.Component, repository: res.Repository, image: res.Image,
		purl: correlationPURL(res.Package.PURL), location: res.Location.URI,
	}, true
}

// markDevCopies gives every finding about a package the development mark another scanner's
// finding about the same package in the same file already carries.
//
// A finding no marked finding shares a package and file with keeps what its scanner said. A Grype
// finding in a file Trivy did not read, or about a package Trivy reported nothing against, carries
// no mark, because nothing that can tell has said it is one.
func markDevCopies(controls map[string]plugin.ControlResult) {
	for name, cr := range controls {
		dev := map[devPackageKey]bool{}
		for _, res := range cr.Report.Results {
			if key, ok := devPackageKeyOf(res); ok && res.Package.Dev {
				dev[key] = true
			}
		}
		if len(dev) == 0 {
			continue
		}
		for i := range cr.Report.Results {
			res := &cr.Report.Results[i]
			key, ok := devPackageKeyOf(*res)
			if !ok || res.Package.Dev || !dev[key] {
				continue
			}
			// A copy, because a scanner may hand several findings the same package value.
			pkg := *res.Package
			pkg.Dev = true
			res.Package = &pkg
		}
		controls[name] = cr
	}
}

// applyDevDependencies sets aside each finding in a development dependency whose component's
// control says not to count them, and returns how many it set aside.
//
// After the descriptor's exclusions and any supplier's claim, so a finding somebody decided about
// keeps the reason they gave. The setting names a kind of finding rather than this one, and a
// decision about this one says more.
//
// The suppression names the setting rather than a file, OriginSetting, so the report can list it
// apart from the exclusions somebody wrote and a reader knows which key to change.
func (e *Engine) applyDevDependencies(controls map[string]plugin.ControlResult, model saga.Model) (suppressed int) {
	for name, cr := range controls {
		ctrl, ok := e.reg.Controller(name)
		if !ok {
			continue
		}
		policy, ok := ctrl.(plugin.DevDependencyPolicy)
		if !ok {
			continue
		}
		type answer struct {
			report bool
			source string
		}
		decided := map[string]answer{}
		n := 0
		for i := range cr.Report.Results {
			res := &cr.Report.Results[i]
			if res.Suppressed() || res.Package == nil || !res.Package.Dev {
				continue
			}
			a, seen := decided[res.Component]
			if !seen {
				a.report, a.source = policy.ReportsDevDependencies(model, res.Component)
				decided[res.Component] = a
			}
			if a.report {
				continue
			}
			res.Suppression = &sarif.Suppression{
				Kind:          "external",
				Origin:        sarif.OriginSetting,
				Justification: sarif.JustificationDevDependency,
				Source:        a.source,
			}
			n++
		}
		if n > 0 {
			counts := cr.Report.Counts()
			cr.Summary = plugin.Summary{Errors: counts.Error, Warnings: counts.Warning, Notes: counts.Note}
			controls[name] = cr
			suppressed += n
		}
	}
	return suppressed
}
