// Package builtins assembles the default registry of controllers and scanners that ship
// with Draugr.
package builtins

import (
	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/internal/scanners"
	dsurveyors "github.com/draugr-dev/draugr/internal/surveyors"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/surveyor"
)

// Registry returns an engine.Registry populated with the built-in controllers and
// scanners.
func Registry() *engine.Registry {
	reg := engine.NewRegistry()
	reg.RegisterController(controllers.NewImages())
	reg.RegisterController(controllers.NewSCA())
	reg.RegisterScanner(scanners.NewTrivy())
	reg.RegisterScanner(scanners.NewTrivyFS())
	return reg
}

// SurveyorRegistry returns a surveyor.Registry populated with the built-in surveyors
// (the Ravens).
func SurveyorRegistry() *surveyor.Registry {
	reg := surveyor.NewRegistry()
	reg.Register(dsurveyors.NewK8sImages())
	reg.Register(dsurveyors.NewGitHubOrgRepos())
	return reg
}
