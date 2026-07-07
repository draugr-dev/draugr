package engine

import "github.com/draugr-dev/draugr/pkg/plugin"

// Registry holds the controllers and scanners available to the engine, keyed by name.
type Registry struct {
	controllers map[string]plugin.Controller
	scanners    map[string]plugin.Scanner
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		controllers: make(map[string]plugin.Controller),
		scanners:    make(map[string]plugin.Scanner),
	}
}

// RegisterController adds a controller, keyed by its Info().Name.
func (r *Registry) RegisterController(c plugin.Controller) {
	r.controllers[c.Info().Name] = c
}

// RegisterScanner adds a scanner, keyed by its Info().Name.
func (r *Registry) RegisterScanner(s plugin.Scanner) {
	r.scanners[s.Info().Name] = s
}

// Controller returns the named controller, if registered.
func (r *Registry) Controller(name string) (plugin.Controller, bool) {
	c, ok := r.controllers[name]
	return c, ok
}

// Scanner returns the named scanner, if registered.
func (r *Registry) Scanner(name string) (plugin.Scanner, bool) {
	s, ok := r.scanners[name]
	return s, ok
}
