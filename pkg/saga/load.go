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
// validate the result, a descriptor whose components all arrive from fragments is legitimately
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
	foldOlderSpellings(&m)
	if validate {
		// Load has no directory to resolve a relative path against, so a descriptor that needs
		// fragments cannot be honored from bytes alone. Saying so beats returning a model that
		// silently describes less than the file does.
		if len(m.Fragments) > 0 {
			return nil, fmt.Errorf("this descriptor names %d fragment(s), which are resolved "+
				"relative to the file. Load it from a path rather than from bytes", len(m.Fragments))
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
// which sets additionalProperties:false, an editor flagging what `draugr validate` accepts is
// worse than either being strict alone.
//
// Scanner options stay free-form: they live in ControllerSettings (a map), which strict decoding
// doesn't constrain, each scanner validates its own block against its ConfigSchema at plan time.
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
	typeName := strings.TrimPrefix(strings.ToLower(goType), "saga.")
	section, ok := sections[typeName]
	if !ok {
		// TestEverySectionHasAKeyPath keeps this unreachable. The type name is a poor answer and
		// a better one than none.
		section = typeName
	}
	if why, ok := removedFields[section+"."+field]; ok {
		return fmt.Errorf("%s.%s was removed: %s", section, field, why)
	}
	return fmt.Errorf("unknown field %q in %s. Check the spelling, or see "+
		"https://draugr.dev/docs/latest/reference/saga-schema/", field, section)
}

// sections gives, for each type a descriptor can decode into, the path a reader actually writes.
//
// yaml.v3 reports an unknown key against the Go type that was being filled in, and a reader has
// never seen those names. `gateconfig` is `config.gate`, and the reference page is indexed by the
// second, so an error naming the first cannot be searched with the word it offers a link for.
//
// Keyed by the lowercased type name, which is what the decoder's message carries.
var sections = map[string]string{
	// The root document is not a section to a reader; "model" is our word for the whole file.
	"model":                "the top level",
	"release":              "release",
	"config":               "config",
	"gateconfig":           "config.gate",
	"excluderule":          "config.exclude",
	"vexdecision":          "config.exclude[].vex",
	"exploitabilityconfig": "config.exploitability",
	"reachabilityconfig":   "config.reachability",
	"sbomconfig":           "config.sbom",
	"reportconfig":         "config.reports",
	"publisherconfig":      "config.publishers",
	"vexconfig":            "config.vex",
	// One type with two homes, and naming either one alone would be a half-answer to somebody
	// looking at the other.
	"vexsource":      "config.vexSources or components[].vex",
	"vexrepository":  "config.vexSources[].repository",
	"component":      "components",
	"repository":     "components[].repositories",
	"image":          "components[].images",
	"host":           "components[].hosts",
	"hostauth":       "components[].hosts[].auth",
	"hostspec":       "components[].hosts[].spec",
	"infrastructure": "components[].infrastructure",
	"fragmentref":    "fragments",
	"reference":      "references",
	"fragment":       "the top level of a fragment",
	"fragmentconfig": "config, in a fragment",
}

// removedFields explains a field that used to parse, keyed by "section.field".
//
// A removed field arrives as an unknown one, and "unknown field" sends someone hunting for a typo
// in a line they copied from our own documentation. Naming the removal costs one map entry and
// answers the question the error otherwise raises.
var removedFields = map[string]string{
	"release.name": "it named the project, which is what the top-level `project` names. Move " +
		"the value there, `project: payments-api`, and a release keeps only its version",
	"release.stage": "nothing read it, so deleting the line changes no result. " +
		"Where a scan is pointed is a property of the target, not of the release",
	"config.reports": "a report is rendered for a destination, so it is named on the one that " +
		"takes it. Move each entry under the `config.publishers` entry it was for, which is also " +
		"where `filename` and `minPriority` now mean something. For local artifacts with no " +
		"destination, `-o <dir>` writes report.json and results.sarif, and `--report <format>` " +
		"adds to them",
	"components[].hosts.environment":          environmentRemoved,
	"components[].infrastructure.environment": environmentRemoved,
}

// environmentRemoved explains a target that still labels itself.
//
// The label existed to be matched by a per-environment `config.allowEffects`, and with that gone
// nothing read it, a field that changes no result is one a reader can only be misled by. A
// descriptor that needs different permissions for different targets is two descriptors, which is
// also two files to review and two runs to point at something.
const environmentRemoved = "nothing read it once config.allowEffects stopped being keyed by " +
	"environment, so deleting the line changes no result. A scan that may do different things " +
	"to different targets is a second descriptor"

var unknownField = regexp.MustCompile(`field (\S+) not found in type (\S+)`)

// LoadFile reads and parses a Saga descriptor, merging any local fragments it names.
//
// Remote fragments need a Fetcher, which needs git, which lives in internal/, so a descriptor
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

// foldOlderSpellings moves a descriptor written against a name we have moved off onto the current
// one, once, at the point it loads.
//
// Here rather than at each reader. Sixty-odd places ask a model what controls it enables, and a
// rename that leaves them all checking two fields is a rename that has to be got right sixty times
// and will be got right fifty-nine.
//
// The current spelling wins where a descriptor somehow carries both. Validation refuses that, so
// this only decides what a model built in code gets, and the newer name is the one somebody meant.
func foldOlderSpellings(m *Model) {
	m.Config.Controls = merged(m.Config.Controls, m.Config.Controllers)
	m.Config.Controllers = nil
	for i := range m.Components {
		m.Components[i].Controls = merged(m.Components[i].Controls, m.Components[i].Controllers)
		m.Components[i].Controllers = nil
	}
}

// merged returns current where it has an entry and older where it does not, or nil when neither
// has anything. Nil rather than an empty map, so "no controls configured" stays one answer.
func merged(current, older map[string]ControllerSettings) map[string]ControllerSettings {
	if len(older) == 0 {
		return current
	}
	if len(current) == 0 {
		return older
	}
	out := make(map[string]ControllerSettings, len(current)+len(older))
	for k, v := range older {
		out[k] = v
	}
	for k, v := range current {
		out[k] = v
	}
	return out
}
