package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/draugr-dev/draugr/internal/scanpolicy"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// resolveGate settles which of the two questions this run is asking, from the flags and the
// descriptor.
//
// A run has one gate. Severity rates a flaw in the abstract; priority folds in what the descriptor
// says about the component it was found in. Answering both leaves a verdict with two possible
// reasons and nothing on the page saying which one produced it.
//
// Three rules, in order:
//
//   - A flag chooses the mode and replaces whatever the descriptor chose. `--fail-on critical`
//     against a descriptor that gates on priority is somebody saying "this run, judge the
//     scanner's number" — not a contradiction to refuse. The descriptor is the standing policy and
//     the flag is this run, which is the precedence every other scan setting uses.
//   - Both flags together is refused, for the reason the descriptor refuses both: one of them
//     would be doing nothing, and the person who passed it would have no way to tell which.
//   - Otherwise the descriptor decides, and validation has already refused one that sets both.
//   - Otherwise the default: the priority band. The ranking this product computes is the one it
//     should be judged by, and a tool whose default gate is the number a scanner printed has its
//     central claim switched off until somebody configures it.
func resolveGate(flagFailOn sarif.Severity, flagPriority string, gate *saga.GateConfig) (sarif.Severity, string, error) {
	switch {
	case flagFailOn != "" && flagPriority != "":
		return "", "", errBothGates
	case flagFailOn != "":
		return flagFailOn, "", nil
	case flagPriority != "":
		return "", flagPriority, nil
	}
	if gate != nil {
		if gate.FailOn != "" {
			// Unparseable cannot reach here: validation runs first and refuses it. Dropped rather
			// than guessed at, which would be a threshold nobody chose.
			if sev, err := sarif.ParseSeverity(gate.FailOn); err == nil {
				return sev, "", nil
			}
		}
		if gate.FailOnPriority != "" {
			return "", gate.FailOnPriority, nil
		}
	}
	return "", defaultGateBand, nil
}

// errBothGates is what somebody passing both flags is told. It names the choice rather than the
// mistake: they wanted both, and what they have to decide is which question they are asking.
var errBothGates = errors.New(
	"--fail-on and --fail-on-priority are two different gates and a run has one. " +
		"--fail-on judges a finding's own severity; --fail-on-priority judges the band it lands " +
		"in for this component, which is the default")

// defaultGateBand is the band a run fails on when nothing names a gate. Kept beside the resolution
// rather than read from norn so the CLI's own tests state it, and held to norn's by
// TestTheDefaultBandIsTheOneNornApplies.
const defaultGateBand = "P1"

// reportUnreachableGate says when the band this run gates on is one the descriptor's own
// classifications cannot produce.
//
// Refused when no component can reach it, because the gate is then inert for the whole run: every
// scan passes it, including one carrying an actively exploited critical vulnerability, and the
// output is identical to a gate that worked and found nothing. Somebody who set this asked for the
// strictest gate the product offers, and silence is the opposite of the answer.
//
// Reported and continued when only some components are affected. That is an ordinary descriptor —
// a restricted internal tool beside a public API — and the run is still meaningful for the rest.
func reportUnreachableGate(out io.Writer, model *saga.Model, band string) error {
	unreachable := scanpolicy.Unreachable(*model, band)
	if len(unreachable) == 0 {
		return nil
	}
	var b strings.Builder
	if len(unreachable) == len(model.Components) {
		fmt.Fprintf(&b, "this gate cannot fire: no component here can produce %s.\n", band)
	} else {
		fmt.Fprintf(&b, "%d of %s cannot produce %s, so this gate does not judge them:\n",
			len(unreachable), plural(len(model.Components), "component"), band)
	}
	for _, line := range unreachable {
		fmt.Fprintf(&b, "  %s\n", line)
	}
	// What to do, not only what is wrong. All three are real answers and which one is right is a
	// question about the application, not about the descriptor.
	b.WriteString("Gate on a band they can reach, classify them for what they are, " +
		"or set config.gate.failOn to judge severity instead.")

	if len(unreachable) == len(model.Components) {
		return errors.New(b.String())
	}
	_, _ = fmt.Fprintln(out, b.String())
	return nil
}
