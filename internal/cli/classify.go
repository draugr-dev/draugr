package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/tui"
)

func newClassifyCommand() *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:   "classify <saga.yaml>",
		Short: "Set component exposure and criticality via a guided wizard",
		Long: "Ask a few questions about each component and write its risk classification\n" +
			"(exposure + criticality) back into the Saga. These drive finding prioritization.\n" +
			"By default only unclassified components are asked about; use --all to redo every one.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runClassify(args[0], all, cmd.InOrStdin(), cmd.OutOrStdout())
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "re-classify every component, not just unclassified ones")
	return cmd
}

// runClassify loads the Saga, asks about each component needing classification, and writes
// the exposure/criticality back into the file (preserving comments and formatting).
func runClassify(path string, all bool, in io.Reader, out io.Writer) error {
	model, err := loadSaga(path)
	if err != nil {
		return err
	}
	if len(model.Components) == 0 {
		_, _ = fmt.Fprintln(out, "No components to classify.")
		return nil
	}

	sc := bufio.NewScanner(in)
	class := map[string]saga.Classification{}
	for _, comp := range model.Components {
		if !all && comp.Exposure != "" && comp.Criticality != "" {
			continue // already classified
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

	data, err := os.ReadFile(path) //nolint:gosec // operator-provided path
	if err != nil {
		return err
	}
	updated, err := saga.WriteClassifications(data, class)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, updated, 0o600); err != nil { //nolint:gosec // operator-provided saga path
		return err
	}
	_, _ = fmt.Fprintf(out, "\nClassified %d component(s) in %s.\n", len(class), path)
	return nil
}

// choice is one option a wizard question offers.
type choice struct {
	// value is what gets written into the descriptor.
	value string
	// label is the value as the reader sees it, coloured by rank.
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
		// Padded before painting: colour codes have no width on screen but plenty in a string,
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
