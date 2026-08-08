package mcp

import (
	"fmt"
	"sort"
	"strings"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// describeScan says what this scan will do, for the person being asked to approve it.
//
// The point of asking is informed consent, and the person answering is usually not the person who
// wrote the descriptor — an assistant produced it, and a human is deciding whether to proceed. A
// message that reads the same for every descriptor asks them to approve something it has not
// described.
//
// The two ends of the range differ in kind, not degree. Five read-only controls over a checkout
// read files and fetch a vulnerability database. `dast` against a declared host sends probing
// traffic at a live service, which is why Draugr never enables it on anyone's behalf. A single
// sentence covering both — "runs external scanners, and uses the network" — is true of each and
// tells a reader nothing about which one they are agreeing to.
//
// Everything needed is already in the loaded descriptor: the plan names the controls and
// components, and the scanner registry declares each scanner's effects.
func describeScan(reg *engine.Registry, model *saga.Model, path string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Draugr wants to scan %s.\n", path)

	planned, _ := engine.New(reg).Plan(*model)
	controls := map[string]bool{}
	components := map[string]bool{}
	scanners := map[string]bool{}
	livePlan := map[string]bool{}
	for _, pj := range planned {
		controls[pj.Control] = true
		if pj.Component != "" {
			components[pj.Component] = true
		}
		scanners[pj.Job.Scanner] = true
		// A host target is a running service somebody operates, not an artifact sitting on disk.
		// That distinction is the one a reader most needs and the one the old message erased.
		if pj.Job.Target != nil && pj.Job.Target.Kind() == plugin.TargetHost {
			livePlan[pj.Job.Scanner] = true
		}
	}

	if len(controls) == 0 {
		b.WriteString("\nNo control is enabled, so this scan would examine nothing.")
		return b.String()
	}
	fmt.Fprintf(&b, "\nControls: %s", strings.Join(sortedSet(controls), ", "))
	if n := len(components); n > 0 {
		fmt.Fprintf(&b, " — over %s", plural(n, "component", "components"))
	}
	b.WriteString(".\n")

	// Effects before the reassurance, so a reader who stops after two lines has stopped on the
	// part that matters.
	var effects []string
	for _, name := range sortedSet(scanners) {
		sc, ok := reg.Scanner(name)
		if !ok {
			continue
		}
		for _, e := range sc.Info().Effects {
			effects = append(effects, fmt.Sprintf("  %s (%s): %s", name, e.Kind, e.Detail))
		}
	}
	if len(effects) > 0 {
		b.WriteString("\nThese do more than read:\n")
		b.WriteString(strings.Join(effects, "\n"))
		b.WriteString("\n")
	}

	if len(livePlan) > 0 {
		fmt.Fprintf(&b, "\nThis sends traffic to a live service you have declared: %s. "+
			"Only approve it for a host you are authorised to probe.\n",
			strings.Join(sortedSet(livePlan), ", "))
	}

	if d := deliveryLines(model); len(d) > 0 {
		b.WriteString("\nResults will be delivered to:\n")
		for _, line := range d {
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

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}
