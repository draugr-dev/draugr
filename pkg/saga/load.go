package saga

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// envPattern matches ${{ VAR_NAME }} with optional surrounding whitespace.
var envPattern = regexp.MustCompile(`\$\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}`)

// Load parses a Saga descriptor from YAML bytes, substituting ${{ VAR }} references from
// the environment and validating the result.
func Load(data []byte) (*Model, error) { return loadModel(data, true) }

// loadModel parses a descriptor. validate is false when the caller will merge fragments first and
// validate the result — a descriptor whose components all arrive from fragments is legitimately
// incomplete until they do.
func loadModel(data []byte, validate bool) (*Model, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parse saga: %w", err)
	}

	if missing := substituteEnv(&root); len(missing) > 0 {
		return nil, fmt.Errorf("undefined environment variable(s) referenced in saga: %s",
			strings.Join(missing, ", "))
	}

	var m Model
	if root.Kind != 0 { // empty document decodes to the zero Model
		if err := decodeStrict(&root, &m); err != nil {
			return nil, err
		}
	}
	if validate {
		// Load has no directory to resolve a relative path against, so a descriptor that needs
		// fragments cannot be honored from bytes alone. Saying so beats returning a model that
		// silently describes less than the file does.
		if len(m.Fragments) > 0 {
			return nil, fmt.Errorf("this descriptor names %d fragment(s), which are resolved "+
				"relative to the file — load it from a path rather than from bytes", len(m.Fragments))
		}
		if err := m.Validate(); err != nil {
			return nil, err
		}
	}
	return &m, nil
}

// decodeStrict decodes the substituted document into a Model, rejecting keys the model doesn't
// define. Unknown keys are almost always typos, and a silently ignored `repositores:` disables a
// whole surface without a word. It also keeps the CLI honest with the published JSON Schema,
// which sets additionalProperties:false — an editor flagging what `draugr validate` accepts is
// worse than either being strict alone.
//
// Scanner options stay free-form: they live in ControllerSettings (a map), which strict decoding
// doesn't constrain — each scanner validates its own block against its ConfigSchema at plan time.
func decodeStrict(root *yaml.Node, m *Model) error {
	// KnownFields lives on the Decoder, not on Node.Decode, so round-trip the substituted tree.
	substituted, err := yaml.Marshal(root)
	if err != nil {
		return fmt.Errorf("parse saga: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(substituted))
	dec.KnownFields(true)
	if err := dec.Decode(m); err != nil {
		return fmt.Errorf("parse saga: %w", unknownFieldHint(err))
	}
	return nil
}

// unknownFieldHint rewrites yaml.v3's "field X not found in type saga.Y" into something a reader
// can act on, naming the Saga section rather than a Go type.
func unknownFieldHint(err error) error {
	msg := err.Error()
	match := unknownField.FindStringSubmatch(msg)
	if match == nil {
		return err
	}
	field, goType := match[1], match[2]
	section := strings.TrimPrefix(strings.ToLower(goType), "saga.")
	if section == "model" {
		// The root document isn't a named section to a reader; "model" is our Go type.
		section = "the top level"
	}
	if why, ok := removedFields[section+"."+field]; ok {
		return fmt.Errorf("%s.%s was removed: %s", section, field, why)
	}
	return fmt.Errorf("unknown field %q in %s — check the spelling, or see "+
		"https://draugr.dev/docs/latest/reference/saga-schema/", field, section)
}

// removedFields explains a field that used to parse, keyed by "section.field".
//
// A removed field arrives as an unknown one, and "unknown field" sends someone hunting for a typo
// in a line they copied from our own documentation. Naming the removal costs one map entry and
// answers the question the error otherwise raises.
var removedFields = map[string]string{
	"release.stage": "nothing read it, so deleting the line changes no result. " +
		"Where a scan is pointed is a property of the target, not of the release",
	"host.environment":           environmentRemoved,
	"infrastructure.environment": environmentRemoved,
}

// environmentRemoved explains a target that still labels itself.
//
// The label existed to be matched by a per-environment `config.allowEffects`, and with that gone
// nothing read it — a field that changes no result is one a reader can only be misled by. A
// descriptor that needs different permissions for different targets is two descriptors, which is
// also two files to review and two runs to point at something.
const environmentRemoved = "nothing read it once config.allowEffects stopped being keyed by " +
	"environment, so deleting the line changes no result. A scan that may do different things " +
	"to different targets is a second descriptor"

var unknownField = regexp.MustCompile(`field (\S+) not found in type (\S+)`)

// LoadFile reads and parses a Saga descriptor, merging any local fragments it names.
//
// Remote fragments need a Fetcher, which needs git, which lives in internal/ — so a descriptor
// using one gets an error here naming it rather than a descriptor that quietly contains less than
// it says. Callers that can fetch use ResolveFile.
func LoadFile(path string) (*Model, error) {
	res, err := ResolveFile(path, nil)
	if err != nil {
		return nil, err
	}
	return res.Model, nil
}

// loadModelFile reads one descriptor without resolving its fragments.
func loadModelFile(path string) (*Model, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is operator-provided by design
	if err != nil {
		return nil, fmt.Errorf("read saga %q: %w", path, err)
	}
	return loadModel(data, false)
}

// substituteEnv walks the parsed YAML tree and replaces every ${{ VAR }} in scalar
// values with the corresponding environment variable. Because it operates on parsed
// nodes, YAML comments (which live in the nodes' comment fields, not in scalar values)
// are never substituted. It returns any referenced-but-undefined variable names, so
// config mistakes fail fast instead of silently producing empty values.
func substituteEnv(root *yaml.Node) []string {
	var missing []string
	seen := map[string]bool{}

	var walk func(*yaml.Node)
	walk = func(n *yaml.Node) {
		if n == nil {
			return
		}
		if n.Kind == yaml.ScalarNode {
			n.Value = envPattern.ReplaceAllStringFunc(n.Value, func(match string) string {
				name := envPattern.FindStringSubmatch(match)[1]
				if val, ok := os.LookupEnv(name); ok {
					return val
				}
				if !seen[name] {
					seen[name] = true
					missing = append(missing, name)
				}
				return match
			})
		}
		for _, child := range n.Content {
			walk(child)
		}
	}

	walk(root)
	return missing
}
