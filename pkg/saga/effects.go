package saga

import (
	"fmt"
	"sort"

	"gopkg.in/yaml.v3"
)

// EffectPermissions is which scanner effects a descriptor accepts.
//
// One shape: a list, applying to everything the descriptor points at.
//
//	allowEffects: [network]
//
// It was briefly also a mapping of environment to effects, so one descriptor could permit an
// intrusive scan of one target and refuse it for another. That put two shapes behind one key and
// made the strictness of the permission depend on which one an author had reached for. A
// descriptor describes one set of things a scan may do; a different answer is a different
// descriptor, which is also a separate file to review and a separate run to point at something.
type EffectPermissions []string

// UnmarshalYAML accepts a list, and refuses a mapping by name.
//
// It exists only to refuse. A mapping of environment to effects used to parse here, so leaving it
// to the default decoder means somebody who wrote a correct descriptor last week gets
// "cannot unmarshal !!map into saga.EffectPermissions" — a type error about a Go type they have
// never heard of, for a shape our own documentation told them to write.
func (p *EffectPermissions) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.MappingNode {
		return fmt.Errorf("config.allowEffects was a mapping of environment to effects and is " +
			"now a list: `allowEffects: [network]`. A scan that may do different things to " +
			"different targets is a second descriptor, which is also a second file to review")
	}
	var list []string
	if err := node.Decode(&list); err != nil {
		return fmt.Errorf("config.allowEffects must be a list of effects (%s)", effectKindList())
	}
	*p = list
	return nil
}

// Empty reports whether nothing was accepted at all.
func (p EffectPermissions) Empty() bool { return len(p) == 0 }

// validate rejects an effect kind nothing declares, so a permission that can never apply is a
// refusal rather than a line that quietly does nothing.
func (p EffectPermissions) validate() []error {
	var errs []error
	for _, kind := range p {
		if !knownEffect(kind) {
			errs = append(errs, fmt.Errorf(
				"config.allowEffects: %q is not an effect kind (%s)", kind, effectKindList()))
		}
	}
	return errs
}

// effectKinds are the kinds a scanner can declare. Held here rather than imported from plugin,
// which imports this package.
var effectKinds = []string{"disclosure", "mutate", "network", "privilege"}

func knownEffect(kind string) bool {
	i := sort.SearchStrings(effectKinds, kind)
	return i < len(effectKinds) && effectKinds[i] == kind
}

func effectKindList() string {
	out := ""
	for i, k := range effectKinds {
		if i > 0 {
			out += ", "
		}
		out += k
	}
	return out
}
