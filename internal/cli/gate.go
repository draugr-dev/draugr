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
func resolveGate(flagFailOn, flagPriority string, gate *saga.GateConfig) (sarif.Severity, string, error) {
	// The deprecated spelling still resolves, so a pipeline that predates the merge keeps working.
	// Refused beside the normalized one for the reason the descriptor refuses the pair: one of
	// them would be doing nothing and the person who passed it could not tell which.
	if flagFailOn != "" && flagPriority != "" {
		return "", "", errBothGates
	}
	chosen := flagFailOn
	if chosen == "" {
		chosen = flagPriority
	}
	kind, value, err := saga.ParseGate(chosen)
	if err != nil {
		return "", "", fmt.Errorf("--fail-on: %w", err)
	}
	if kind == saga.GateNone {
		// Nothing on the command line, so the descriptor's standing policy, in whichever spelling
		// it used.
		kind, value = gate.Resolved()
	}
	switch kind {
	case saga.GateSeverity:
		return sarif.Severity(value), "", nil
	case saga.GatePriority:
		return "", value, nil
	}
	// Nothing named anywhere. The band, because the ranking this product computes is the one it
	// should be judged by.
	return "", defaultGateBand, nil
}

// errBothGates is what somebody passing both flags is told. It names the choice rather than the
// mistake: they wanted both, and what they have to decide is which question they are asking.
var errBothGates = errors.New(
	"--fail-on and --fail-on-priority are two spellings of one decision and a run has one gate. " +
		"--fail-on now takes either vocabulary: a band (P1-P4) or a severity " +
		"(critical, high, medium, low)")

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

// resolveDiffGate is resolveGate for the differential gate, which asks the same question about a
// smaller set: what the change introduced rather than what the repository carries.
//
// No default here, and that is the difference. An absent gate on `scan` means the run is still
// judged, on the band; an absent one here means the diff is reported and decides nothing, which is
// what the two scans either side of a `draugr diff` are for.
func resolveDiffGate(flagFailOn, flagPriority string) (sarif.Severity, string, error) {
	if flagFailOn != "" && flagPriority != "" {
		return "", "", errBothDiffGates
	}
	chosen := flagFailOn
	if chosen == "" {
		chosen = flagPriority
	}
	kind, value, err := saga.ParseGate(chosen)
	if err != nil {
		return "", "", fmt.Errorf("--fail-on-new: %w", err)
	}
	if kind == saga.GateSeverity {
		return sarif.Severity(value), "", nil
	}
	return "", value, nil
}

var errBothDiffGates = errors.New(
	"--fail-on-new and --fail-on-new-priority are two spellings of one decision and a run has " +
		"one gate. --fail-on-new now takes either vocabulary: a band (P1-P4) or a severity " +
		"(critical, high, medium, low)")
