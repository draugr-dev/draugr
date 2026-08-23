package cli

import (
	"path/filepath"
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
	fragments, err := filepath.Glob("../../examples/*.saga-fragment.yaml")
	if err != nil {
		t.Fatalf("glob fragments: %v", err)
	}
	paths = append(paths, fragments...)

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
