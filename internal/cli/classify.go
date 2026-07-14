package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/pkg/saga"
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

// askExposure walks the exposure decision tree and returns the derived level.
func askExposure(sc *bufio.Scanner, out io.Writer) saga.Exposure {
	_, _ = fmt.Fprintln(out, "  Exposure — how reachable is it?")
	if askYesNo(sc, out, "  Reachable from the public internet?") {
		if askYesNo(sc, out, "  Does it require authentication?") {
			return saga.ExposureAuthenticated
		}
		return saga.ExposurePublic
	}
	if askYesNo(sc, out, "  Is its network access restricted (namespace / network policy)?") {
		return saga.ExposureRestricted
	}
	return saga.ExposureInternal
}

// askCriticality asks the impact question and returns the derived level.
func askCriticality(sc *bufio.Scanner, out io.Writer) saga.Criticality {
	_, _ = fmt.Fprintln(out, "  Criticality — impact if it fails or is compromised?")
	_, _ = fmt.Fprintln(out, "    1) outage or data loss   2) degraded, no outage   3) limited impact")
	for {
		_, _ = fmt.Fprint(out, "  Choose [1-3]: ")
		line, ok := readLine(sc)
		switch strings.TrimSpace(line) {
		case "1":
			return saga.CriticalityCritical
		case "2":
			return saga.CriticalityImportant
		case "3":
			return saga.CriticalitySupporting
		}
		if !ok {
			return saga.CriticalityImportant // no more input: sane middle default
		}
		_, _ = fmt.Fprintln(out, "  Please enter 1, 2, or 3.")
	}
}

// askYesNo prompts and returns true for an affirmative answer (default no).
func askYesNo(sc *bufio.Scanner, out io.Writer, prompt string) bool {
	_, _ = fmt.Fprintf(out, "%s [y/N] ", prompt)
	line, _ := readLine(sc)
	ans := strings.ToLower(strings.TrimSpace(line))
	return ans == "y" || ans == "yes"
}

// readLine reads one line, reporting whether input remained (false at EOF).
func readLine(sc *bufio.Scanner) (string, bool) {
	if sc.Scan() {
		return sc.Text(), true
	}
	return "", false
}
