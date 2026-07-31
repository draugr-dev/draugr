package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/draugr-dev/draugr/pkg/saga"
)

// scanModel resolves a scan target into a Saga model. An empty target means the current
// directory. A directory target is scanned zero-config with a synthesized Saga (the
// zeroConfigControls over that repo); a file target is loaded as a Saga descriptor. Returns whether the
// model was synthesized so the caller can note it.
func scanModel(target string) (m *saga.Model, synthesized bool, err error) {
	if target == "" {
		target = "."
	}
	if info, statErr := os.Stat(target); statErr == nil && info.IsDir() {
		// A directory holding a descriptor is not a directory to scan zero-config. Everything
		// in that file — the controls chosen, the components declared, the exposure and
		// criticality that drive prioritization — would otherwise be discarded in favour of
		// four defaults, and nothing in the output would say so.
		//
		// Deliberately not a fallback: if the descriptor is there but unreadable, that is an
		// error. Falling back would reproduce the bug this exists to fix, with an extra step —
		// the reason a descriptor was skipped has to be reported, never shrugged at.
		if path := descriptorIn(target); path != "" {
			m, err = loadSaga(path)
			return m, false, err
		}
		return syntheticSaga(target), true, nil
	}
	m, err = loadSaga(target)
	return m, false, err
}

// DescriptorName is the file `draugr init` writes and `scan` looks for in a directory.
const DescriptorName = "draugr.saga.yaml"

// descriptorIn returns the descriptor in dir, or "" when there is none.
func descriptorIn(dir string) string {
	path := filepath.Join(dir, DescriptorName)
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		return path
	}
	return ""
}

// zeroConfigControls are the controls a zero-config scan enables: the repository-based ones,
// which need nothing but the directory in front of them. This is the single source of truth —
// the help text and the run notice render it rather than restating it, so adding a control here
// can't leave stale prose behind.
var zeroConfigControls = []string{"sca", "secrets", "sast", "iac"}

// ZeroConfigControls lists those controls in a readable form, e.g. "sca, secrets, sast, and iac".
func ZeroConfigControls(conjunction string) string {
	switch len(zeroConfigControls) {
	case 0:
		return ""
	case 1:
		return zeroConfigControls[0]
	}
	head := zeroConfigControls[:len(zeroConfigControls)-1]
	tail := zeroConfigControls[len(zeroConfigControls)-1]
	if conjunction == "" {
		return strings.Join(zeroConfigControls, ", ")
	}
	return strings.Join(head, ", ") + ", " + conjunction + " " + tail
}

// syntheticSaga builds the default zero-config Saga: one component scanning the given directory
// with the repository-based controls. Used when `draugr scan` is pointed at a directory.
func syntheticSaga(dir string) *saga.Model {
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = dir
	}
	name := filepath.Base(abs)
	if name == "" || name == "." || name == string(filepath.Separator) {
		name = "repo"
	}
	return &saga.Model{
		Release: saga.Release{Name: name, Version: "0.0.0"},
		Config:  saga.Config{Controllers: zeroConfigControllers()},
		Components: []saga.Component{{
			Name:         name,
			Repositories: []saga.Repository{{URL: abs}},
		}},
	}
}

// loadSaga loads a Saga for a command that needs it, presenting any parse/validation failure
// with consistent, actionable context: which file was bad, every problem (Validate aggregates
// them), and a nudge to `draugr validate`. Commands should use this instead of saga.LoadFile
// directly so a bad descriptor reads the same everywhere. (`draugr validate` itself calls
// saga.LoadFile directly — it *is* the check, so the hint would be circular.)
func loadSaga(path string) (*saga.Model, error) {
	model, err := saga.LoadFile(path)
	if err != nil {
		// Indent the underlying (possibly multi-line, aggregated) error under the summary.
		detail := strings.ReplaceAll(err.Error(), "\n", "\n  ")
		return nil, fmt.Errorf("%q is not a valid Saga:\n  %s\nrun `draugr validate %s` to check the descriptor",
			path, detail, path)
	}
	return model, nil
}

// zeroConfigControllers enables each zero-config control in a fresh settings map.
func zeroConfigControllers() map[string]saga.ControllerSettings {
	out := make(map[string]saga.ControllerSettings, len(zeroConfigControls))
	for _, name := range zeroConfigControls {
		out[name] = saga.ControllerSettings{"enabled": true}
	}
	return out
}
