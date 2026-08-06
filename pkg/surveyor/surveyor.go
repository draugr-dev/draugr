// Package surveyor is the discovery framework: plugins that inspect an environment
// and return Saga fragments, which are merged so the descriptor can write itself.
package surveyor

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// Registry holds surveyors keyed by name.
type Registry struct {
	surveyors map[string]plugin.Surveyor
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{surveyors: make(map[string]plugin.Surveyor)}
}

// Register adds a surveyor, keyed by its Info().Name.
func (r *Registry) Register(s plugin.Surveyor) {
	r.surveyors[s.Info().Name] = s
}

// Get returns the named surveyor, if registered.
func (r *Registry) Get(name string) (plugin.Surveyor, bool) {
	s, ok := r.surveyors[name]
	return s, ok
}

// Names returns the registered surveyor names in sorted order.
func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.surveyors))
	for name := range r.surveyors {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Request asks a named surveyor to survey a scope.
type Request struct {
	Surveyor string
	Scope    plugin.SurveyScope
}

// Run executes each request in order and merges the resulting fragments. Errors (unknown
// surveyor, survey failure) are collected and returned alongside whatever was discovered.
func (r *Registry) Run(ctx context.Context, requests []Request) (saga.Fragment, error) {
	var (
		frags []saga.Fragment
		errs  []error
	)
	for _, req := range requests {
		s, ok := r.Get(req.Surveyor)
		if !ok {
			errs = append(errs, fmt.Errorf("no surveyor %q", req.Surveyor))
			continue
		}
		frag, err := s.Survey(ctx, req.Scope)
		if err != nil {
			errs = append(errs, fmt.Errorf("survey %s: %w", req.Surveyor, err))
			continue
		}
		frags = append(frags, frag)
	}
	return MergeFragments(frags...), errors.Join(errs...)
}

// MergeFragments combines fragments into one, deduplicating components by name and
// unioning each component's surface (repositories, images, hosts, infrastructure).
func MergeFragments(frags ...saga.Fragment) saga.Fragment {
	var out saga.Fragment
	for _, frag := range frags {
		for _, comp := range frag.Components {
			out.Components = saga.UpsertComponent(out.Components, comp)
		}
	}
	return out
}

// Apply merges a fragment into an existing model, upserting components by name.
//
// Delegates to saga.Merge so a surveyor's fragment and a `fragments:` entry go through one
// merge. Two merges would eventually disagree about what a repeated component name means.
func Apply(model *saga.Model, frag saga.Fragment) { saga.Merge(model, frag) }
