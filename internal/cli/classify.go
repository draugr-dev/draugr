package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/tui"
)

func newClassifyCommand() *cobra.Command {
	var opts classifyOptions
	cmd := &cobra.Command{
		Use:   "classify [saga.yaml | directory]",
		Short: "Set component exposure and criticality via a guided wizard",
		Long: "Ask a few questions about each component and write its risk classification\n" +
			"(exposure + criticality) back into the Saga. These drive finding prioritization.\n" +
			"By default only unclassified components are asked about; use --all to redo every one,\n" +
			"or --components to pick which ones.\n\n" +
			"With no argument, uses the descriptor in the current directory.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := ""
			if len(args) == 1 {
				target = args[0]
			}
			return runClassify(target, opts, cmd.InOrStdin(), cmd.OutOrStdout())
		},
	}
	cmd.Flags().BoolVar(&opts.all, "all", false, "re-classify every component, not just unclassified ones")
	cmd.Flags().StringSliceVar(&opts.components, "components", nil,
		"only these components, by name (comma-separated or repeated); implies --all for them")
	return cmd
}

// classifyOptions is what the wizard was asked to cover.
type classifyOptions struct {
	// all re-asks about components that already carry a classification.
	all bool
	// components restricts the wizard to these names.
	components []string
}

// runClassify loads the Saga, asks about each component needing classification, and writes
// the exposure/criticality back into the file (preserving comments and formatting).
func runClassify(target string, opts classifyOptions, in io.Reader, out io.Writer) error {
	// Found the same way `draugr scan` finds it, because a reader who has just run `draugr scan .`
	// has no reason to think the next command needs the filename spelled out.
	path, found, err := resolveDescriptor(target, "classify")
	if err != nil {
		return err
	}
	if !found {
		// A scan can synthesize a descriptor; classification cannot. Exposure and criticality are
		// judgements about a component, and there is no file to record them in or read them back
		// from.
		return fmt.Errorf("no %s in %s — run `draugr init` to write one", sagaGlob, dirOf(target))
	}

	model, err := loadSaga(path)
	if err != nil {
		return err
	}
	if len(model.Components) == 0 {
		_, _ = fmt.Fprintln(out, "No components to classify.")
		return nil
	}
	selected, err := selectComponents(model.Components, opts.components)
	if err != nil {
		return err
	}

	sc := bufio.NewScanner(in)
	class := map[string]saga.Classification{}
	for _, comp := range model.Components {
		if !selected[comp.Name] {
			continue
		}
		// Naming a component is itself the instruction to redo it: someone who typed the name is
		// asking about that component, and answering "already classified" to a question they asked
		// explicitly would leave them reaching for --all and reclassifying everything else too.
		if !opts.all && len(opts.components) == 0 && comp.Exposure.Value != "" && comp.Criticality.Value != "" {
			continue
		}
		_, _ = fmt.Fprintf(out, "\nComponent: %s\n", comp.Name)
		exposure := askExposure(sc, out)
		criticality := askCriticality(sc, out)
		class[comp.Name] = saga.Classification{Exposure: exposure, Criticality: criticality}
		_, _ = fmt.Fprintf(out, "  → %s: exposure=%s, criticality=%s\n", comp.Name, exposure, criticality)
	}

	if len(class) == 0 {
		_, _ = fmt.Fprintln(out, "All components are already classified (use --all to redo them).")
		return nil
	}

	data, err := os.ReadFile(path) // #nosec G304 -- operator-provided path
	if err != nil {
		return err
	}
	updated, err := saga.WriteClassifications(data, class)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, updated, 0o600); err != nil { // #nosec G703 -- operator-provided saga path
		return err
	}
	_, _ = fmt.Fprintf(out, "\nClassified %d component(s) in %s.\n", len(class), path)
	return nil
}

// dirOf names the directory a target refers to, for a message about what is not in it.
func dirOf(target string) string {
	if target == "" {
		return "."
	}
	return target
}

// selectComponents resolves --components into the set to ask about, or every component when the
// flag was not given.
//
// A name that matches nothing is an error, not a skip. The whole point of the flag is to classify
// one component out of many, so a typo silently classifying none — and reporting "all components
// are already classified" — would answer a question that was never asked.
func selectComponents(components []saga.Component, want []string) (map[string]bool, error) {
	selected := map[string]bool{}
	if len(want) == 0 {
		for _, c := range components {
			selected[c.Name] = true
		}
		return selected, nil
	}
	known := map[string]bool{}
	for _, c := range components {
		known[c.Name] = true
	}
	var unknown []string
	for _, name := range want {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if !known[name] {
			unknown = append(unknown, name)
			continue
		}
		selected[name] = true
	}
	if len(unknown) > 0 {
		names := make([]string, 0, len(known))
		for n := range known {
			names = append(names, quoted(n))
		}
		sort.Strings(names)
		msg := fmt.Sprintf("no component named %s — the Saga has %s",
			list(quotedAll(unknown)), list(names))
		if len(unknown) == 1 {
			if near := nearestName(unknown[0], known); near != "" {
				msg = fmt.Sprintf("no component named %q — did you mean %q?", unknown[0], near)
			}
		}
		return nil, errors.New(msg)
	}
	return selected, nil
}

// quoted wraps a name in quotes. Component names can contain spaces and hyphens, so an unquoted
// list of them is ambiguous about where one ends.
func quoted(s string) string { return `"` + s + `"` }

// quotedAll quotes every name in a list.
func quotedAll(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = quoted(n)
	}
	return out
}

// choice is one option a wizard question offers.
type choice struct {
	// value is what gets written into the descriptor.
	value string
	// label is the value as the reader sees it, colored by rank.
	label string
	// gloss says what the value means without assuming a stack.
	gloss string
	// style ranks the option in the console's existing severity palette, so the weight of an
	// answer is visible while it is being chosen rather than only afterwards in a report.
	style tui.Style
}

// exposureChoices are the reachability levels, most exposed first.
//
// The wording deliberately names no platform. "Is its network access restricted (namespace /
// network policy)?" is answerable if you run Kubernetes and a guess otherwise — and Draugr
// classifies repositories and images too. The question underneath is who can reach this, so that
// is the question asked; a cluster is one way to arrange the answer and belongs in an example.
var exposureChoices = []choice{
	{string(saga.ExposurePublic), "public", "anyone on the internet can reach it, no sign-in", tui.StyleCritical},
	{string(saga.ExposureAuthenticated), "authenticated", "on the internet, but behind a login", tui.StyleHigh},
	{string(saga.ExposureInternal), "internal", "only from inside your own network or VPN", tui.StyleMedium},
	{string(saga.ExposureRestricted), "restricted", "inside your network and locked down further — an allowlist, a private link, its own segment", tui.StyleLow},
}

// criticalityChoices are the impact levels, most critical first.
var criticalityChoices = []choice{
	{string(saga.CriticalityCritical), "critical", "an outage or data loss for the business", tui.StyleCritical},
	{string(saga.CriticalityImportant), "important", "degraded service, but no outage", tui.StyleMedium},
	{string(saga.CriticalitySupporting), "supporting", "limited impact, easily worked around", tui.StyleLow},
}

// askExposure asks who can reach the component.
func askExposure(sc *bufio.Scanner, out io.Writer) saga.Exposure {
	return saga.Exposure(ask(sc, out, "Exposure — who can reach it?", exposureChoices,
		string(saga.ExposureInternal)))
}

// askCriticality asks what happens if the component fails.
func askCriticality(sc *bufio.Scanner, out io.Writer) saga.Criticality {
	return saga.Criticality(ask(sc, out, "Criticality — what happens if it fails or is breached?",
		criticalityChoices, string(saga.CriticalityImportant)))
}

// ask presents a numbered list and returns the chosen value.
//
// One interaction for both questions. Exposure used to be a tree of yes/no questions and
// criticality a numbered list, so a reader switched modes halfway through a wizard whose whole
// point is to be quick — and switching is where quick becomes careful.
//
// A numbered list also shows the whole ladder at once, which a decision tree cannot: someone
// answering "no, not public" never saw that "restricted" was a rung below "internal".
func ask(sc *bufio.Scanner, out io.Writer, question string, choices []choice, fallback string) string {
	col := tui.For(out)
	_, _ = fmt.Fprintf(out, "  %s\n", question)
	for i, c := range choices {
		// Padded before painting: color codes have no width on screen but plenty in a string,
		// so %-14s over an already-painted label aligns the escapes rather than the words.
		_, _ = fmt.Fprintf(out, "    %d) %s %s\n",
			i+1,
			col.Paint(c.style, fmt.Sprintf("%-14s", c.label)),
			col.Paint(tui.StyleMuted, c.gloss))
	}
	for {
		_, _ = fmt.Fprintf(out, "  Choose [1-%d]: ", len(choices))
		line, ok := readLine(sc)
		if n, err := strconv.Atoi(strings.TrimSpace(line)); err == nil && n >= 1 && n <= len(choices) {
			return choices[n-1].value
		}
		if !ok {
			// No more input — a piped or truncated session. The middle of the ladder is the
			// honest guess: neither hiding risk nor inventing it.
			return fallback
		}
		_, _ = fmt.Fprintf(out, "  Please enter a number from 1 to %d.\n", len(choices))
	}
}

// readLine reads one line, reporting whether input remained (false at EOF).
func readLine(sc *bufio.Scanner) (string, bool) {
	if sc.Scan() {
		return sc.Text(), true
	}
	return "", false
}
