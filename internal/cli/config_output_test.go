package cli

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/config"
)

// TestOutputOptionsFromLetsFlagsWin covers the rule that makes a configured default safe: it is a
// default, and typing a flag overrides it.
func TestOutputOptionsFromLetsFlagsWin(t *testing.T) {
	cfg := config.OutputSettings{View: "findings", Evidence: true, Top: 25}

	// Nothing typed: the file decides.
	opts := scanOptions{setFlags: map[string]bool{}}
	outputOptionsFrom(&opts, cfg)
	if opts.view != "findings" || !opts.evidence || opts.top != 25 {
		t.Errorf("the configured preferences were not applied: %+v", opts)
	}

	// Typed: the command line decides, including when what was typed is the zero value. A typed flag
	// cannot be told from an untyped one by its value, which is why the check is whether it was
	// typed. `--top 0` means show everything, and a configured cap must not override it.
	typed := scanOptions{
		view:     "actions",
		top:      0,
		setFlags: map[string]bool{"view": true, "evidence": true, "top": true},
	}
	outputOptionsFrom(&typed, cfg)
	if typed.view != "actions" {
		t.Errorf("a configured view overrode the one that was typed: %q", typed.view)
	}
	if typed.evidence {
		t.Error("a configured evidence:true overrode --evidence=false")
	}
	if typed.top != 0 {
		t.Errorf("a configured cap overrode an explicit --top 0: %d", typed.top)
	}
}

// TestOutputOptionsFromIgnoresAnEmptyFile: a file that says nothing about rendering leaves the
// built-in defaults alone rather than zeroing them.
func TestOutputOptionsFromIgnoresAnEmptyFile(t *testing.T) {
	opts := scanOptions{view: "actions", top: 10, setFlags: map[string]bool{}}
	outputOptionsFrom(&opts, config.OutputSettings{})
	if opts.view != "actions" || opts.top != 10 {
		t.Errorf("an empty config changed the defaults: %+v", opts)
	}
}
