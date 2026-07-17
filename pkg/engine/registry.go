package engine

import (
	"sort"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

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

// Scanners returns all registered scanners, sorted by Info().Name for stable output.
func (r *Registry) Scanners() []plugin.Scanner {
	out := make([]plugin.Scanner, 0, len(r.scanners))
	for _, s := range r.scanners {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Info().Name < out[j].Info().Name })
	return out
}

// Controllers returns all registered controllers, sorted by Info().Name for stable output.
func (r *Registry) Controllers() []plugin.Controller {
	out := make([]plugin.Controller, 0, len(r.controllers))
	for _, c := range r.controllers {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Info().Name < out[j].Info().Name })
	return out
}
