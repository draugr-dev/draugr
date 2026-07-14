package cli

import (
	"fmt"
	"strings"

	"github.com/draugr-dev/draugr/pkg/saga"
)

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
