package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/draugr-dev/draugr/pkg/saga"
)

// scanModel resolves a scan target into a Saga model. An empty target means the current
// directory. A directory target is scanned zero-config with a synthesized Saga (sca/secrets/
// sast/iac over that repo); a file target is loaded as a Saga descriptor. Returns whether the
// model was synthesized so the caller can note it.
func scanModel(target string) (m *saga.Model, synthesized bool, err error) {
	if target == "" {
		target = "."
	}
	if info, statErr := os.Stat(target); statErr == nil && info.IsDir() {
		return syntheticSaga(target), true, nil
	}
	m, err = loadSaga(target)
	return m, false, err
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
		Config: saga.Config{Controllers: map[string]saga.ControllerSettings{
			"sca":     {"enabled": true},
			"secrets": {"enabled": true},
			"sast":    {"enabled": true},
			"iac":     {"enabled": true},
		}},
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
