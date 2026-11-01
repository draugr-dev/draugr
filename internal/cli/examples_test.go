package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/pkg/publish"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// TestShippedExamplesValidate holds the examples to the same rules a user's descriptor is held to.
//
// Nothing else does. `examples/` is not scanned, not linted and not loaded by any other test, so a
// control that was renamed, a scanner option that gained a schema, or a key that was always a typo
// stays in a file we hand people as the thing to copy. The failure is quiet in the worst way: the
// example is wrong, the repository is green, and the first person to find out is someone starting
// from it.
//
// Through loadAndCheck rather than a check of its own, because a guard that validates examples
// differently from `draugr validate` is a second opinion about what a valid descriptor is, and the
// two would eventually disagree about a file we ship.
func TestShippedExamplesValidate(t *testing.T) {
	t.Parallel()

	paths, err := filepath.Glob("../../examples/*.saga.yaml")
	if err != nil {
		t.Fatalf("glob examples: %v", err)
	}
	// Fragments live beside the descriptor that collects them and also one directory down, which is
	// the shape a real repository has. So both are checked. A fragment is a descriptor a user copies
	// too.
	for _, pattern := range []string{
		"../../examples/*.saga-fragment.yaml",
		"../../examples/*/*.saga-fragment.yaml",
	} {
		fragments, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatalf("glob fragments: %v", err)
		}
		paths = append(paths, fragments...)
	}

	// A guard that checks nothing passes. If the examples move or the suffix changes, this should
	// say so rather than report success over an empty list.
	if len(paths) == 0 {
		t.Fatal("no descriptors found under examples/. Either they moved, or their suffix " +
			"changed and this guard has been checking nothing")
	}

	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			if err := loadAndCheck(path); err != nil {
				t.Errorf("%s is not a descriptor Draugr accepts: %v\n"+
					"It is shipped as the file to copy, so this is wrong for every reader before "+
					"it is wrong for us.", path, err)
			}
		})
	}
}

// TestShippedExamplesUseNothingDeprecated keeps the files we hand people ahead of the deprecations
// we ship, not behind them.
//
// An example that trips a deprecation teaches the thing being removed, and does it to exactly the
// reader who has no way to know better. It also makes the notice itself worthless: somebody who
// copied our example and then saw us warn about it reads the warning as noise.
func TestShippedExamplesUseNothingDeprecated(t *testing.T) {
	t.Parallel()

	paths, err := filepath.Glob("../../examples/*.saga.yaml")
	if err != nil {
		t.Fatalf("glob examples: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("no descriptors found under examples/, this guard has been checking nothing")
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			model, err := saga.LoadFile(path)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if model.ProjectName() == "" {
				// An example is what somebody copies. One that files under nothing teaches a
				// shape the plane rejects.
				t.Error("this example names no project")
			}
		})
	}
}

// TestEveryDescriptorFieldAppearsInAnExample keeps `examples/` a complete account of what a Saga
// can say.
//
// A capability absent from the examples is one users do not know they have, and a shape nobody
// writes is a shape nobody tests. Both have happened: `builtBy` decides what the report tells a
// reader to do about a package inside an image they did not build, and it was documented, schema'd
// and shipped without appearing in a single file we hand people to copy.
//
// Read off the model rather than from a list kept beside it, because a list is the thing that goes
// stale in exactly the same way. A new field fails this the moment it is added, which is the
// cheapest moment to write the four lines of example it needs.
func TestEveryDescriptorFieldAppearsInAnExample(t *testing.T) {
	t.Parallel()

	corpus := readExamples(t)
	var missing []string
	for _, key := range sagaKeys() {
		// An example is what somebody copies, so a spelling we are moving off must not appear in
		// one. Held honest below: a key listed here has to actually say it is deprecated.
		if deprecatedKeys[key] {
			continue
		}
		// Written as a key, not merely mentioned. A commented-out key counts. Several options are only
		// ever shown that way, and a reader copies a commented line as readily as a live one, but a name
		// inside an English sentence does not. Prose satisfying this guard is how it would come to pass
		// while the field it names appears nowhere anybody could copy.
		if !regexp.MustCompile(`(?m)^[\t ]*(#[\t ]*)?`+regexp.QuoteMeta(key)+`:`).MatchString(corpus) &&
			!regexp.MustCompile(`(?m)^[\t ]*(#[\t ]*)?- `+regexp.QuoteMeta(key)+`:`).MatchString(corpus) {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("no example writes these descriptor fields: %s\n"+
			"Add each to the example it belongs in, with a line saying what it decides. "+
			"A field nobody has seen written is one users do not know they have.",
			strings.Join(missing, ", "))
	}
}

// sagaKeys is every yaml key the descriptor model declares, read from the struct tags.
// deprecatedKeys are descriptor fields that still load and that no example should teach.
//
// Not a way to skip writing an example. TestDeprecatedKeysSayTheyAreDeprecated refuses an entry
// the schema does not mark, so a field cannot be parked here to get out of the guard above.
var deprecatedKeys = map[string]bool{
	// Replaced by `failOn`, which takes a band or a severity. Still read, so a descriptor written
	// before the merge keeps working.
	"failOnPriority": true,
	// Replaced by `controls`, the word every other surface uses. Still read, and folded into
	// `controls` when a descriptor loads.
	"controllers": true,
}

// TestDeprecatedKeysSayTheyAreDeprecated keeps the exemption list from becoming a place to hide a
// field nobody wrote an example for.
func TestDeprecatedKeysSayTheyAreDeprecated(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile("../../pkg/saga/draugr.saga.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	var walk func(any)
	walk = func(n any) {
		switch v := n.(type) {
		case map[string]any:
			for key, child := range v {
				if props, ok := v["properties"].(map[string]any); ok {
					for name, def := range props {
						if d, ok := def.(map[string]any); ok {
							if desc, _ := d["description"].(string); strings.HasPrefix(desc, "Deprecated:") {
								found[name] = true
							}
						}
					}
				}
				_ = key
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(doc)
	for key := range deprecatedKeys {
		if !found[key] {
			t.Errorf("%q is exempt from the example guard and the schema does not call it "+
				"deprecated. Either write the example, or say in the schema that it is going.", key)
		}
	}
}

func sagaKeys() []string {
	seen := map[string]bool{}
	var walk func(reflect.Type)
	walk = func(t reflect.Type) {
		for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Map {
			t = t.Elem()
		}
		if t.Kind() != reflect.Struct {
			return
		}
		for i := range t.NumField() {
			f := t.Field(i)
			name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
			// "-" is a field the descriptor never carries: provenance the loader fills in.
			if name != "" && name != "-" {
				seen[name] = true
			}
			walk(f.Type)
		}
	}
	walk(reflect.TypeOf(saga.Model{}))
	walk(reflect.TypeOf(saga.Fragment{}))

	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// readExamples is every example file as one string, so a field may be demonstrated wherever it
// belongs rather than all of them in one descriptor.
func readExamples(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	for _, pattern := range []string{
		"../../examples/*.yaml", "../../examples/*.yml", "../../examples/*/*.yaml",
	} {
		paths, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatalf("glob %s: %v", pattern, err)
		}
		for _, path := range paths {
			body, err := os.ReadFile(path) // #nosec G304 -- a fixed glob under examples/
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			b.Write(body)
			b.WriteString("\n")
		}
	}
	if b.Len() == 0 {
		t.Fatal("no examples read, this guard has been checking nothing")
	}
	return b.String()
}

// TestEveryControlAppearsInAnExample holds the example set to the catalog.
//
// A control registered and never written down is one users do not know they have: `draugr controls`
// lists it, the reference documents it, and the file people actually copy has never mentioned it.
// Registration is the trigger, so a new control brings this failure with it rather than waiting for
// somebody to notice the gap.
//
// A commented block counts, the same as for a field. Two controls send real traffic or need a key,
// and an example that cannot be run as shipped is worse than one that shows them commented with
// the reason.
func TestEveryControlAppearsInAnExample(t *testing.T) {
	t.Parallel()

	corpus := readExamples(t)
	var missing []string
	for _, name := range controlNames(builtins.Registry()) {
		if !regexp.MustCompile(`(?m)^[\t ]*(#[\t ]*)?` + regexp.QuoteMeta(name) + `:`).MatchString(corpus) {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("no example enables these controls: %s\n"+
			"Add each under config.controls in the example it suits, with a line saying what it "+
			"checks. Comment it out where running it needs a key or sends real traffic, and say "+
			"which.", strings.Join(missing, ", "))
	}
}

// TestEveryPublisherAppearsInAnExample does the same for destinations.
//
// A publisher is the half of reporting somebody has to be told exists. Its kind is the only string
// that selects it, it is never suggested by anything a reader types, and a descriptor that renders
// reports and delivers them nowhere looks finished.
func TestEveryPublisherAppearsInAnExample(t *testing.T) {
	t.Parallel()

	corpus := readExamples(t)
	var missing []string
	for _, kind := range publish.Kinds() {
		if !regexp.MustCompile(`(?m)^[\t ]*(#[\t ]*)?- kind: ` + regexp.QuoteMeta(kind) + `\b`).MatchString(corpus) {
			missing = append(missing, kind)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("no example writes these publishers: %s\n"+
			"Add each under config.publishers, with the report format it needs beside it. A "+
			"destination nobody has seen written is one users do not know they can reach.",
			strings.Join(missing, ", "))
	}
}

// TestEveryScannerOptionAppearsInAnExample reaches the half the field guard cannot see.
//
// A scanner's options live in ControllerSettings, which is a free-form map, so they have no struct
// tags and TestEveryDescriptorFieldAppearsInAnExample walks straight past them. They are real keys
// with real defaults, they are the difference between a control that runs and one that runs against
// your own ruleset, mirror or cluster, and nothing was holding them to an example.
//
// Read from the published schema, which is generated from each scanner's own ConfigSchema, so a
// scanner that gains an option brings this failure with it.
//
// Held per scanner, at the path a descriptor writes it: config.controls.<control>.<scanner>.<option>.
// Scanners share option names (pkgTypes, dbRepository, byCve, deny, config), so a name matched
// anywhere in the file passes for a scanner whose block is absent, and the file that claims to
// show every option shows one scanner's and not the other's.
func TestEveryScannerOptionAppearsInAnExample(t *testing.T) {
	t.Parallel()

	controls := controlSchemas(t)
	body, err := os.ReadFile("../../examples/scanner-options.saga.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if missing := missingScannerOptions(controls, string(body)); len(missing) > 0 {
		t.Errorf("examples/scanner-options.saga.yaml does not write these under config.controls: %s\n"+
			"Add each under its own control and scanner, with a line saying what it decides. "+
			"Comment it out where using it needs a credential or a cluster.",
			strings.Join(missing, ", "))
	}
}

// TestMissingScannerOptionsReadsEachScannersOwnBlock holds the guard above to the per-scanner
// reading: an option written under one scanner does not answer for the same option under another,
// and a commented block counts the same as a live one.
func TestMissingScannerOptionsReadsEachScannersOwnBlock(t *testing.T) {
	t.Parallel()

	option := map[string]any{"type": "array"}
	scanner := func(opts ...string) map[string]any {
		props := map[string]any{"enabled": map[string]any{"type": "boolean"}}
		for _, o := range opts {
			props[o] = option
		}
		return map[string]any{"type": "object", "properties": props}
	}
	controls := map[string]map[string]any{
		"images": {"enabled": map[string]any{"type": "boolean"}, "trivy": scanner("pkgTypes")},
		"sca": {
			"trivyFs": scanner("pkgTypes", "dbRepository"),
			"grypeFs": scanner("byCve"),
			"mendSca": scanner("productToken"),
		},
		"licenses": {"deny": option, "trivyLicense": scanner("full")},
	}
	body := `config:
  controls:
    images:
      trivy:
        pkgTypes: [library]            # pkgTypes: here does not answer for trivyFs
    sca:
      trivyFs:
        dbRepository: [mirror]
      grypeFs:
        byCve: false
      # mendSca:
      #   productToken: 1a2b3c4d
    licenses:
      trivyLicense:
        enabled: true
`
	got := missingScannerOptions(controls, body)
	want := []string{"licenses.deny", "licenses.trivyLicense.full", "sca.trivyFs.pkgTypes"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("missing = %v, want %v", got, want)
	}
}

// controlSchemas is each control's block from the published schema, keyed by control name: its
// scanners and its own settings.
func controlSchemas(t *testing.T) map[string]map[string]any {
	t.Helper()
	raw, err := os.ReadFile("../../pkg/saga/draugr.saga.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	defs, _ := doc["$defs"].(map[string]any)
	controls := map[string]map[string]any{}
	for name, def := range defs {
		// Only the per-control blocks. Everything else in $defs is a descriptor field, which the
		// field guard already holds.
		control, ok := strings.CutPrefix(name, "control_")
		if !ok {
			continue
		}
		props, _ := def.(map[string]any)["properties"].(map[string]any)
		controls[control] = props
	}
	if len(controls) == 0 {
		t.Fatal("the schema declares no control blocks, so this guard has been checking nothing")
	}
	return controls
}

// missingScannerOptions lists what body does not write under config.controls, as
// control.key or control.scanner.option. A key under a control is a scanner when its schema
// declares properties, and each of those is required too; anything else is a setting of the
// control's own. `enabled` is exempt at both levels: every control and scanner takes it, and a
// reader meets it on the first one.
func missingScannerOptions(controls map[string]map[string]any, body string) []string {
	written := keyPaths(body)
	var missing []string
	for control, keys := range controls {
		for key, node := range keys {
			if key == "enabled" {
				continue
			}
			path := "config.controls." + control + "." + key
			if !written[path] {
				missing = append(missing, control+"."+key)
				continue
			}
			def, _ := node.(map[string]any)
			opts, _ := def["properties"].(map[string]any)
			for opt := range opts {
				if opt != "enabled" && !written[path+"."+opt] {
					missing = append(missing, control+"."+key+"."+opt)
				}
			}
		}
	}
	sort.Strings(missing)
	return missing
}

// keyLine matches a line that writes a YAML key, live or commented out: indentation, then an
// optional comment marker with the space after it, then the indentation inside the comment, then
// the key and the colon that ends it. A word followed by a colon inside a sentence does not match,
// because the colon must end the line or be followed by a space and the key must open the line.
var keyLine = regexp.MustCompile(`^( *)(?:# ?( *))?([A-Za-z][A-Za-z0-9_-]*):(?:[\t ]|$)`)

// keyPaths is every dotted path body writes as a key, commented lines included, because a reader
// copies a commented block as readily as a live one. A commented key's depth is measured inside the
// comment, so `#   enabled: true` under `# mendSca:` nests the way the uncommented block would.
// List items are skipped rather than followed: nothing this guard asks for sits inside a list.
func keyPaths(body string) map[string]bool {
	type frame struct {
		indent int
		key    string
	}
	var stack []frame
	paths := map[string]bool{}
	for line := range strings.SplitSeq(body, "\n") {
		m := keyLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		indent := len(m[1]) + len(m[2])
		for len(stack) > 0 && stack[len(stack)-1].indent >= indent {
			stack = stack[:len(stack)-1]
		}
		stack = append(stack, frame{indent, m[3]})
		keys := make([]string, len(stack))
		for i, f := range stack {
			keys[i] = f.key
		}
		paths[strings.Join(keys, ".")] = true
	}
	return paths
}
