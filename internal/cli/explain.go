package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// defaultSARIFNames are where a scan leaves its evidence, tried in order.
//
// So that `draugr explain <rule>` works straight after a scan that wrote somewhere ordinary,
// which is the moment somebody wants it. Naming the file explicitly is always available and never
// required for the common case.
var defaultSARIFNames = []string{
	"results.sarif",
	filepath.Join("draugr-out", "results.sarif"),
	filepath.Join(".draugr-out", "results.sarif"),
}

// newExplainCommand builds `draugr explain`.
//
// A finding's identifier and one truncated line is enough to rank it and not enough to decide
// anything. What a reader needs next — what the check means and what to change — is already in
// the report: scanners publish remediation text and Draugr records it. Without somewhere to read
// it, the identifier sends people to whatever a search engine offers, and for a benchmark that
// means a registration form in front of a PDF.
func newExplainCommand() *cobra.Command {
	var reportPath string
	cmd := &cobra.Command{
		Use:   "explain <rule-id>",
		Short: "Show what a finding means and how to fix it, from a scan's own report",
		Long: "Print a rule's description, the remediation its scanner published, and where the\n" +
			"scan found it.\n\n" +
			"Reads the SARIF a scan wrote with -o. The rule id can be given in full, or by the\n" +
			"part that is unambiguous — `4.3.1` finds `kube-bench/cis/4.3.1`.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runExplain(cmd.OutOrStdout(), args[0], reportPath)
		},
	}
	cmd.Flags().StringVarP(&reportPath, "report", "r", "",
		"the results.sarif to read (default: results.sarif, or draugr-out/results.sarif)")
	return cmd
}

// runExplain finds the rule and prints what is known about it.
func runExplain(w io.Writer, query, reportPath string) error {
	path, err := findSARIF(reportPath)
	if err != nil {
		return err
	}
	// #nosec G304 -- the report to read is the argument of this command; a reader who can run
	// draugr can already read their own files, and refusing a path they typed would make the
	// command useless for the case it exists for.
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	report, err := sarif.FromSARIF(data)
	if err != nil {
		return fmt.Errorf("%s is not a SARIF report: %w", path, err)
	}

	id, rule, err := matchRule(report, query)
	if err != nil {
		return err
	}
	writeExplanation(w, report, id, rule)
	return nil
}

// findSARIF resolves which report to read, and says what it looked for when there is none.
func findSARIF(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	for _, name := range defaultSARIFNames {
		if _, err := os.Stat(name); err == nil {
			return name, nil
		}
	}
	return "", fmt.Errorf("no scan report here — looked for %s. "+
		"Run a scan with -o <dir>, or name one with --report",
		strings.Join(defaultSARIFNames, ", "))
}

// matchRule finds the rule a query names.
//
// Exactly first, then by suffix, because a reader retypes the part that identifies the check
// rather than the namespace in front of it. An ambiguous abbreviation lists what it could have
// meant instead of choosing: picking one would explain a rule the reader did not ask about, and
// they would have no way to tell.
func matchRule(report sarif.Report, query string) (string, sarif.Rule, error) {
	if rule, ok := report.Rules[query]; ok {
		return query, rule, nil
	}
	var matched []string
	for id := range report.Rules {
		if strings.HasSuffix(id, "/"+query) || strings.EqualFold(id, query) {
			matched = append(matched, id)
		}
	}
	sort.Strings(matched)
	switch len(matched) {
	case 0:
		return "", sarif.Rule{}, fmt.Errorf("no rule %q in this report — "+
			"the id is the one in the Rule column, and only rules this scan reported are here", query)
	case 1:
		return matched[0], report.Rules[matched[0]], nil
	default:
		return "", sarif.Rule{}, fmt.Errorf("%q matches %s — name one of them",
			query, strings.Join(matched, ", "))
	}
}

// writeExplanation prints what is known about a rule, in the order a reader asks it.
func writeExplanation(w io.Writer, report sarif.Report, id string, rule sarif.Rule) {
	col := tui.For(w)

	_, _ = fmt.Fprintf(w, "%s\n", col.Paint(tui.StyleAccent, id))
	if d := strings.TrimSpace(rule.ShortDescription); d != "" {
		_, _ = fmt.Fprintf(w, "%s\n", d)
	}

	// The remediation first among the details, because it is the reason to run this at all.
	if fix := strings.TrimSpace(rule.FullDescription); fix != "" && fix != rule.ShortDescription {
		_, _ = fmt.Fprintf(w, "\n%s\n", col.Paint(tui.StyleMuted, "How to fix"))
		for _, line := range strings.Split(fix, "\n") {
			_, _ = fmt.Fprintf(w, "  %s\n", strings.TrimSpace(line))
		}
	}

	if where := findingsFor(report, id); len(where) > 0 {
		_, _ = fmt.Fprintf(w, "\n%s\n", col.Paint(tui.StyleMuted, "Found in"))
		for _, line := range where {
			_, _ = fmt.Fprintf(w, "  %s\n", line)
		}
	}

	if rule.HelpURI != "" {
		_, _ = fmt.Fprintf(w, "\n%s\n  %s\n", col.Paint(tui.StyleMuted, "Reference"), rule.HelpURI)
	}
}

// findingsFor lists where this rule fired, deduplicated and capped.
//
// A rule that fired in forty places is answered by the first few and a count: the reader is here
// to understand the check, and the full list is in the report they are reading this from.
func findingsFor(report sarif.Report, id string) []string {
	const most = 5
	seen := map[string]bool{}
	var out []string
	total := 0
	for _, res := range report.Results {
		if res.RuleID != id || res.Location.URI == "" || seen[res.Location.URI] {
			continue
		}
		seen[res.Location.URI] = true
		total++
		if len(out) < most {
			out = append(out, res.Location.URI)
		}
	}
	if total > most {
		out = append(out, fmt.Sprintf("and %d more", total-most))
	}
	return out
}
