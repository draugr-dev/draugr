package cli

import (
	"strings"
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

// --view settles what the report shows, and folds in the two flags it replaces. They were one
// question asked twice, so the rule is that the one the caller typed deliberately wins.
func TestResolveViewFoldsInTheFlagsItReplaces(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts scanOptions
		want string
	}{
		{"nothing typed keeps the default", scanOptions{view: "findings"}, "findings"},
		{"--group action", scanOptions{view: "findings", group: "action"}, "actions"},
		{"--group none", scanOptions{view: "findings", group: "none"}, "findings"},
		{"--compact", scanOptions{view: "findings", compact: true}, "compact"},
		{"an explicit --view beats either", scanOptions{
			view: "actions", compact: true, group: "none",
			setFlags: map[string]bool{"view": true},
		}, "actions"},
		// A caller building the options directly, or a test, gets the default rather than an error
		// about a flag it never set.
		{"unset is not mistyped", scanOptions{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := tc.opts
			if opts.setFlags == nil {
				opts.setFlags = map[string]bool{}
			}
			if err := resolveView(&opts); err != nil {
				t.Fatalf("resolveView: %v", err)
			}
			if opts.view != tc.want {
				t.Errorf("view = %q, want %q", opts.view, tc.want)
			}
		})
	}
}

// A mistyped value renders a report nobody asked for and says nothing about it, so it is an error
// that names what to write instead.
func TestResolveViewRefusesWhatItCannotRender(t *testing.T) {
	opts := scanOptions{view: "summary", setFlags: map[string]bool{}}
	err := resolveView(&opts)
	if err == nil {
		t.Fatal("a view Draugr cannot render was accepted")
	}
	for _, want := range []string{"findings", "actions", "compact"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to name %q", err, want)
		}
	}
	// The same for the flag it replaced, which still has to say what it will not do.
	old := scanOptions{view: "findings", group: "grouped", setFlags: map[string]bool{}}
	if err := resolveView(&old); err == nil || !strings.Contains(err.Error(), "--view") {
		t.Errorf("error = %v, want it to point at --view", err)
	}
}
