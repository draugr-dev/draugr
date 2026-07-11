package saga

import (
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
func Load(data []byte) (*Model, error) {
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
		if err := root.Decode(&m); err != nil {
			return nil, fmt.Errorf("parse saga: %w", err)
		}
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// LoadFile reads and parses a Saga descriptor from a file path.
func LoadFile(path string) (*Model, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is operator-provided by design
	if err != nil {
		return nil, fmt.Errorf("read saga %q: %w", path, err)
	}
	return Load(data)
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
