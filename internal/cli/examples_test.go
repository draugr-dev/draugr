package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

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
	// Fragments live beside the descriptor that collects them and also one directory down, which
	// is the shape a real repository has — so both are checked. A fragment is a descriptor a user
	// copies too.
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
		t.Fatal("no descriptors found under examples/ — either they moved, or their suffix " +
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
		t.Fatal("no descriptors found under examples/ — this guard has been checking nothing")
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			model, err := saga.LoadFile(path)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			for _, d := range model.Deprecations() {
				t.Errorf("%s", d)
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
		// Written as a key, not merely mentioned. A commented-out key counts — several options are
		// only ever shown that way, and a reader copies a commented line as readily as a live one
		// — but a name inside an English sentence does not. Prose satisfying this guard is how it
		// would come to pass while the field it names appears nowhere anybody could copy.
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
		t.Fatal("no examples read — this guard has been checking nothing")
	}
	return b.String()
}
