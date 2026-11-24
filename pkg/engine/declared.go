package engine

import (
	"slices"
	"time"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// Declarations is what a descriptor declared, as one run read it: how each component is
// classified, which controls it turned on, and which findings it set aside.
//
// Recorded on the run so that results.sarif can carry it. A comparison judges a change against its
// base, and the change's own descriptor is part of the change: read alone, a pull request that
// declares its component less exposed, turns a control off or excludes its own finding is judged by
// the declaration it introduces. The base's record is what holds it to the declaration that was
// already in force.
type Declarations struct {
	// Components are the components this run covered, in the descriptor's order.
	Components []ComponentDeclaration
	// Controls are the project-wide controls the descriptor turned on and this run covered, sorted.
	Controls []string
	// Exclusions are the config.exclude rules in force for this run, lapsed ones left out.
	Exclusions []saga.ExcludeRule
}

// ComponentDeclaration is what a descriptor declared for one component.
type ComponentDeclaration struct {
	Name string
	// Exposure and Criticality are as declared, empty where the descriptor declares none. The
	// ranking reads an empty one as the most exposed or most critical level.
	Exposure    saga.Exposure
	Criticality saga.Criticality
	// Controls are the per-component controls the descriptor turned on for it and this run
	// covered, sorted.
	Controls []string
	// Repositories are the URLs of the repositories it declares, as written. A comparison follows a
	// repository from one component to another by them, where a change renames a component or moves
	// a repository between two.
	Repositories []string
}

// declarations reads what model declares, for the part of it this engine's scope covers.
//
// Read from the descriptor rather than from the jobs that were planned. A control that planned
// nothing, a component with no image under images, still ran as far as the descriptor is
// concerned, and the question a comparison asks of it is whether the change turned it off.
func (e *Engine) declarations(model saga.Model, now time.Time) Declarations {
	var d Declarations
	for _, name := range sortedControllerNames(e.reg.controllers) {
		if !e.scope.includesControl(name) {
			continue
		}
		if e.reg.controllers[name].Info().Scope == plugin.ScopeProject && model.Config.ControllerEnabled(name) {
			d.Controls = append(d.Controls, name)
		}
	}
	for i := range model.Components {
		comp := &model.Components[i]
		if !e.scope.IncludesComponent(comp.Name) {
			continue
		}
		c := ComponentDeclaration{Name: comp.Name, Exposure: comp.Exposure, Criticality: comp.Criticality}
		for _, repo := range comp.Repositories {
			c.Repositories = append(c.Repositories, repo.URL)
		}
		for _, name := range sortedControllerNames(e.reg.controllers) {
			if !e.scope.includesControl(name) || e.reg.controllers[name].Info().Scope != plugin.ScopeComponent {
				continue
			}
			if comp.ControllerEnabled(name, model.Config) {
				c.Controls = append(c.Controls, name)
			}
		}
		d.Components = append(d.Components, c)
	}
	for _, rule := range model.Config.Exclude {
		if !rule.ExpiredOn(now) {
			d.Exclusions = append(d.Exclusions, rule)
		}
	}
	slices.Sort(d.Controls)
	return d
}
