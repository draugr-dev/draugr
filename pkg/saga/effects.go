package saga

import (
	"fmt"
	"sort"

	"gopkg.in/yaml.v3"
)

// EffectPermissions is which scanner effects are accepted, and where.
//
// Two shapes, because the descriptor is answering two different questions. A list accepts an
// effect everywhere:
//
//	allowEffects: [network]
//
// A mapping accepts it per environment, which is what makes the permission match the decision:
//
//	allowEffects:
//	  staging: [network, mutate]
//	  production: []
//
// The list form is not a shorthand for the mapping. It says "in every environment", including ones
// nobody has declared yet, and a descriptor granting that should read as saying it.
type EffectPermissions struct {
	// Everywhere are the effects accepted regardless of environment.
	Everywhere []string
	// ByEnvironment are the effects accepted in one named environment. A declared environment with
	// an empty list accepts nothing, which is a decision and not an omission.
	ByEnvironment map[string][]string
}

// Empty reports whether nothing was accepted at all.
func (p EffectPermissions) Empty() bool {
	return len(p.Everywhere) == 0 && len(p.ByEnvironment) == 0
}

// In lists the effects accepted for a target in the named environment.
//
// An unstated environment gets only what was accepted everywhere. Falling back to the most
// permissive entry would let a target that declared nothing inherit a permission somebody granted
// to staging.
func (p EffectPermissions) In(environment string) []string {
	out := append([]string(nil), p.Everywhere...)
	if environment == "" {
		return out
	}
	return append(out, p.ByEnvironment[environment]...)
}

// Environments lists the environments the descriptor named, sorted.
func (p EffectPermissions) Environments() []string {
	out := make([]string, 0, len(p.ByEnvironment))
	for env := range p.ByEnvironment {
		out = append(out, env)
	}
	sort.Strings(out)
	return out
}

// UnmarshalYAML accepts either shape.
func (p *EffectPermissions) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.SequenceNode:
		return node.Decode(&p.Everywhere)
	case yaml.MappingNode:
		return node.Decode(&p.ByEnvironment)
	case 0:
		return nil
	default:
		return fmt.Errorf("allowEffects must be a list of effects, or a mapping of environment to effects")
	}
}

// MarshalYAML writes back whichever shape was given, so a descriptor round-trips and the digest of
// a re-serialized model does not depend on which form somebody wrote.
func (p EffectPermissions) MarshalYAML() (any, error) {
	if len(p.ByEnvironment) > 0 {
		return p.ByEnvironment, nil
	}
	if len(p.Everywhere) > 0 {
		return p.Everywhere, nil
	}
	return nil, nil
}

// validate checks the environments the permissions are keyed by.
//
// The effect names themselves are checked by the schema, which generates their enum from the
// taxonomy in pkg/plugin — a package this one cannot import, because it imports this one.
func (p EffectPermissions) validate() []error {
	var errs []error
	for _, env := range p.Environments() {
		if !environmentName.MatchString(env) {
			errs = append(errs, fmt.Errorf(
				"config.allowEffects: %q is not an environment name (lowercase letters, digits and dashes)", env))
		}
	}
	return errs
}
