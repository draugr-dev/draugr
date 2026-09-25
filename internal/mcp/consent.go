package mcp

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/draugr-dev/draugr/internal/english"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/publish"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// scanPlan is what a scan will do, read from the descriptor before anything runs: the controls and
// components it covers, and everything it does beyond reading a local copy.
type scanPlan struct {
	controls   []string
	components int
	// effects is one line per effect a planned scanner declares, naming the scanner and the kind.
	effects []string
	// live names the planned scanners that send traffic to a declared host.
	live []string
	// delivery is one line per publisher, and offMachine the ones that send the report elsewhere.
	delivery   []string
	offMachine []string
}

// planScan reads what a scan of model would do.
//
// Everything needed is already in the loaded descriptor: the plan names the controls and
// components, the scanner registry declares each scanner's effects, and the publisher registry says
// which destinations are this machine.
func planScan(reg *engine.Registry, model *saga.Model) (scanPlan, error) {
	planned, err := engine.New(reg).Plan(*model)
	if err != nil {
		return scanPlan{}, err
	}
	controls := map[string]bool{}
	components := map[string]bool{}
	scanners := map[string]bool{}
	live := map[string]bool{}
	for _, pj := range planned {
		controls[pj.Control] = true
		if pj.Component != "" {
			components[pj.Component] = true
		}
		scanners[pj.Job.Scanner] = true
		// A host target is a running service somebody operates, not an artifact sitting on disk.
		if pj.Job.Target != nil && pj.Job.Target.Kind() == plugin.TargetHost {
			live[pj.Job.Scanner] = true
		}
	}
	p := scanPlan{
		controls:   sortedSet(controls),
		components: len(components),
		live:       sortedSet(live),
		delivery:   deliveryLines(model),
	}
	for _, name := range sortedSet(scanners) {
		sc, ok := reg.Scanner(name)
		if !ok {
			continue
		}
		for _, e := range sc.Info().Effects {
			p.effects = append(p.effects, fmt.Sprintf("%s (%s): %s", name, e.Kind, e.Detail))
		}
	}
	for i, pub := range model.Config.Publishers {
		if !publish.Local(pub.Kind) {
			p.offMachine = append(p.offMachine, p.delivery[i])
		}
	}
	return p, nil
}

// needsApproval reports whether mode requires somebody to agree to this scan before it runs.
//
// It reads the plan and the mode and nothing else, so the decision is the same whichever way the
// answer is then obtained: an elicitation, or a host that authorizes the caller by its own means.
func needsApproval(mode ScanMode, p scanPlan) bool {
	switch mode {
	case ScanAlways:
		return false
	case ScanEffects:
		return len(p.effects) > 0 || len(p.offMachine) > 0
	default:
		return true
	}
}

// reasons lists what makes this scan more than a local read, for a refusal that has no prompt to
// carry them.
func (p scanPlan) reasons() []string {
	out := slices.Clone(p.effects)
	for _, d := range p.offMachine {
		out = append(out, "delivers results to "+d)
	}
	return out
}

// describeScan says what this scan will do, for the person being asked to approve it.
//
// The point of asking is informed consent, and the person answering is usually not the person who
// wrote the descriptor, an assistant produced it, and a human is deciding whether to proceed. A
// message that reads the same for every descriptor asks them to approve something it has not
// described.
//
// The two ends of the range differ in kind, not degree. Five read-only controls over a checkout
// read files and fetch a vulnerability database. `dast` against a declared host sends probing
// traffic at a live service, which is why Draugr never enables it on anyone's behalf. A single
// sentence covering both. "runs external scanners, and uses the network". Is true of each and
// tells a reader nothing about which one they are agreeing to.
func describeScan(p scanPlan, path string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Draugr wants to scan %s.\n", path)

	if len(p.controls) == 0 {
		b.WriteString("\nNo control is enabled, so this scan would examine nothing.")
		return b.String()
	}
	fmt.Fprintf(&b, "\nControls: %s", strings.Join(p.controls, ", "))
	if p.components > 0 {
		fmt.Fprintf(&b, ", over %s", english.Count(p.components, "component"))
	}
	b.WriteString(".\n")

	// Effects before the reassurance, so a reader who stops after two lines has stopped on the
	// part that matters.
	if len(p.effects) > 0 {
		b.WriteString("\nThese do more than read:\n")
		for _, e := range p.effects {
			b.WriteString("  " + e + "\n")
		}
	}

	if len(p.live) > 0 {
		fmt.Fprintf(&b, "\nThis sends traffic to a live service you have declared: %s. "+
			"Only approve it for a host you are authorized to probe.\n",
			strings.Join(p.live, ", "))
	}

	if len(p.delivery) > 0 {
		b.WriteString("\nResults will be delivered to:\n")
		for _, line := range p.delivery {
			b.WriteString("  " + line + "\n")
		}
	}

	b.WriteString("\nRepositories are checked out into a temporary directory, and external " +
		"scanners run against that copy; your working tree is not modified.")
	return b.String()
}

// deliveryLines names each publisher the descriptor declares, because delivery is an effect on
// the user's machine and on third parties, and approving a scan is not the same as approving an
// upload. A file publisher writes a directory; a code-scanning publisher sends the findings to
// somebody else's service. Those deserve to be told apart before the fact, not after.
//
// Unindented: the same list is returned to the caller as structured data, where leading spaces
// are noise, and the prompt indents it when it renders.
func deliveryLines(model *saga.Model) []string {
	out := make([]string, 0, len(model.Config.Publishers))
	for _, p := range model.Config.Publishers {
		switch {
		case p.Dir != "":
			out = append(out, fmt.Sprintf("%s: %s", p.Kind, p.Dir))
		case p.Repo != "":
			out = append(out, fmt.Sprintf("%s: %s", p.Kind, p.Repo))
		default:
			out = append(out, p.Kind)
		}
	}
	return out
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
