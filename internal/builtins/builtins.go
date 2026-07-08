// Package builtins assembles the default registry of controllers and scanners that ship
// with Draugr.
package builtins

import (
	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/internal/scanners"
	"github.com/draugr-dev/draugr/pkg/engine"
)

// Registry returns an engine.Registry populated with the built-in controllers and
// scanners.
func Registry() *engine.Registry {
	reg := engine.NewRegistry()
	reg.RegisterController(controllers.NewImages())
	reg.RegisterScanner(scanners.NewTrivy())
	return reg
}
