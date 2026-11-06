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
//
// Whether the runtime provides a dependency is the same kind of fact, read from a pom.xml's scope
// rather than from a scanner, and it travels between copies the same way.

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

// packageMarks are the marks one package carries in one file.
type packageMarks struct{ dev, provided bool }

// markDevCopies gives every finding about a package the development and provided marks another
// scanner's finding about the same package in the same file already carries.
//
// A finding no marked finding shares a package and file with keeps what its scanner said. A Grype
// finding in a file Trivy did not read, or about a package Trivy reported nothing against, carries
// no development mark, because nothing that can tell has said it is one.
func markDevCopies(controls map[string]plugin.ControlResult) {
	for name, cr := range controls {
		marked := map[devPackageKey]packageMarks{}
		for _, res := range cr.Report.Results {
			key, ok := devPackageKeyOf(res)
			if !ok || (!res.Package.Dev && !res.Package.Provided) {
				continue
			}
			m := marked[key]
			m.dev = m.dev || res.Package.Dev
			m.provided = m.provided || res.Package.Provided
			marked[key] = m
		}
		if len(marked) == 0 {
			continue
		}
		for i := range cr.Report.Results {
			res := &cr.Report.Results[i]
			key, ok := devPackageKeyOf(*res)
			if !ok {
				continue
			}
			m := marked[key]
			if (!m.dev || res.Package.Dev) && (!m.provided || res.Package.Provided) {
				continue
			}
			// A copy, because a scanner may hand several findings the same package value.
			pkg := *res.Package
			pkg.Dev = pkg.Dev || m.dev
			pkg.Provided = pkg.Provided || m.provided
			res.Package = &pkg
		}
		controls[name] = cr
	}
}

// settingPolicy is one control setting that sets aside a kind of dependency: which findings it
// covers, the control's answer for a component, and the reason each suppression records.
type settingPolicy struct {
	covers        func(*sarif.Package) bool
	decide        func(plugin.Controller) (func(saga.Model, string) (bool, string), bool)
	justification string
}

// devDependencySetting is config.controls.sca.devDependencies.
var devDependencySetting = settingPolicy{
	covers: func(p *sarif.Package) bool { return p.Dev },
	decide: func(c plugin.Controller) (func(saga.Model, string) (bool, string), bool) {
		p, ok := c.(plugin.DevDependencyPolicy)
		if !ok {
			return nil, false
		}
		return p.ReportsDevDependencies, true
	},
	justification: sarif.JustificationDevDependency,
}

// providedDependencySetting is config.controls.sca.providedDependencies.
var providedDependencySetting = settingPolicy{
	covers: func(p *sarif.Package) bool { return p.Provided },
	decide: func(c plugin.Controller) (func(saga.Model, string) (bool, string), bool) {
		p, ok := c.(plugin.ProvidedDependencyPolicy)
		if !ok {
			return nil, false
		}
		return p.ReportsProvidedDependencies, true
	},
	justification: sarif.JustificationProvidedByRuntime,
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
	return e.applySetting(controls, model, devDependencySetting)
}

// applyProvidedDependencies sets aside each finding in a dependency the runtime provides whose
// component's control says not to count them, and returns how many it set aside. After
// applyDevDependencies, so a package marked both keeps the development reason.
func (e *Engine) applyProvidedDependencies(controls map[string]plugin.ControlResult, model saga.Model) (suppressed int) {
	return e.applySetting(controls, model, providedDependencySetting)
}

// applySetting sets aside each finding the setting covers whose component's control says not to
// count them, and returns how many it set aside.
func (e *Engine) applySetting(controls map[string]plugin.ControlResult, model saga.Model, s settingPolicy) (suppressed int) {
	for name, cr := range controls {
		ctrl, ok := e.reg.Controller(name)
		if !ok {
			continue
		}
		reports, ok := s.decide(ctrl)
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
			if res.Suppressed() || res.Package == nil || !s.covers(res.Package) {
				continue
			}
			a, seen := decided[res.Component]
			if !seen {
				a.report, a.source = reports(model, res.Component)
				decided[res.Component] = a
			}
			if a.report {
				continue
			}
			res.Suppression = &sarif.Suppression{
				Kind:          "external",
				Origin:        sarif.OriginSetting,
				Justification: s.justification,
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
