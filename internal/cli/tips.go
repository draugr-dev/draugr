package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// printScanTips writes contextual, one-line hints after a console scan — small nudges that help
// someone new to security get more out of Draugr. Tips are advisory and never affect the verdict.
// They are suppressed by --no-tips or the DRAUGR_NO_TIPS environment variable, and only shown when
// there are findings to contextualize.
func printScanTips(w io.Writer, model *saga.Model, run engine.Result, noTips bool) {
	if noTips || tipsDisabled() || model == nil {
		return
	}
	if !hasFindings(run) {
		return
	}
	if !usesRiskClassification(model) {
		_, _ = fmt.Fprint(w, "\nTip: no components set exposure/criticality, so priorities use severity "+
			"alone. Run `draugr classify` to make P1–P4 reflect real risk.\n")
	}
}

// tipsDisabled reports whether tips are globally turned off via the environment.
func tipsDisabled() bool { return os.Getenv("DRAUGR_NO_TIPS") != "" }

// usesRiskClassification reports whether any component declares an exposure or criticality — the
// inputs that make priority ranking risk-aware rather than severity-only.
func usesRiskClassification(model *saga.Model) bool {
	for _, c := range model.Components {
		if c.Exposure != "" || c.Criticality != "" {
			return true
		}
	}
	return false
}

// hasFindings reports whether the run produced at least one finding across all controls.
func hasFindings(run engine.Result) bool {
	for _, cr := range run.Controls {
		if len(cr.Report.Results) > 0 {
			return true
		}
	}
	return false
}
