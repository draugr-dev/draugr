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
	reg.RegisterController(controllers.NewSecrets())
	reg.RegisterController(controllers.NewSAST())
	reg.RegisterController(controllers.NewIAC())
	reg.RegisterController(controllers.NewHeaders())
	reg.RegisterScanner(scanners.NewTrivy())
	reg.RegisterScanner(scanners.NewTrivyFS())
	reg.RegisterScanner(scanners.NewGitleaks())
	reg.RegisterScanner(scanners.NewSemgrep())
	reg.RegisterScanner(scanners.NewGosec())
	reg.RegisterScanner(scanners.NewTrivyConfig())
	reg.RegisterScanner(scanners.NewHTTPHeaders())
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
