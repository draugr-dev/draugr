// Package surveyor is the Raven framework: discovery plugins that inspect an environment
// and return Saga fragments, which are merged so the descriptor can write itself.
//
// Odin's ravens, Huginn and Muninn, fly the world and report back what they see.
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
			out.Components = upsertComponent(out.Components, comp)
		}
	}
	return out
}

// Apply merges a fragment into an existing model, upserting components by name.
func Apply(model *saga.Model, frag saga.Fragment) {
	for _, comp := range frag.Components {
		model.Components = upsertComponent(model.Components, comp)
	}
}

// upsertComponent appends comp, or unions its surface into an existing same-named one.
func upsertComponent(components []saga.Component, comp saga.Component) []saga.Component {
	for i := range components {
		if components[i].Name == comp.Name {
			components[i] = unionComponent(components[i], comp)
			return components
		}
	}
	return append(components, comp)
}

func unionComponent(a, b saga.Component) saga.Component {
	a.Repositories = unionRepositories(a.Repositories, b.Repositories)
	a.Images = unionImages(a.Images, b.Images)
	a.Hosts = unionHosts(a.Hosts, b.Hosts)
	a.Infrastructure = unionInfra(a.Infrastructure, b.Infrastructure)
	return a
}

func unionRepositories(a, b []saga.Repository) []saga.Repository {
	seen := make(map[string]bool)
	for _, r := range a {
		seen[r.URL+"@"+r.Revision] = true
	}
	for _, r := range b {
		if key := r.URL + "@" + r.Revision; !seen[key] {
			seen[key] = true
			a = append(a, r)
		}
	}
	return a
}

func unionImages(a, b []saga.Image) []saga.Image {
	seen := make(map[string]bool)
	for _, img := range a {
		seen[img.Image] = true
	}
	for _, img := range b {
		if !seen[img.Image] {
			seen[img.Image] = true
			a = append(a, img)
		}
	}
	return a
}

func unionHosts(a, b []saga.Host) []saga.Host {
	seen := make(map[string]bool)
	for _, h := range a {
		seen[h.URL] = true
	}
	for _, h := range b {
		if !seen[h.URL] {
			seen[h.URL] = true
			a = append(a, h)
		}
	}
	return a
}

func unionInfra(a, b []saga.Infrastructure) []saga.Infrastructure {
	seen := make(map[string]bool)
	for _, in := range a {
		seen[in.Kind+"/"+in.Ref] = true
	}
	for _, in := range b {
		if key := in.Kind + "/" + in.Ref; !seen[key] {
			seen[key] = true
			a = append(a, in)
		}
	}
	return a
}
