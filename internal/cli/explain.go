package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// defaultSARIFNames are where a scan leaves its evidence, tried in order.
//
// So that `draugr explain <rule>` works straight after a scan that wrote somewhere ordinary,
// which is the moment somebody wants it. Naming the file explicitly is always available and never
// required for the common case.
var defaultSARIFNames = []string{
	filepath.Join(".draugr", "out", "results.sarif"),
	"results.sarif",
	// The names Draugr recommended before everything it writes moved under .draugr/, still read
	// so that a pipeline or a habit built on them keeps working.
	filepath.Join("draugr-out", "results.sarif"),
	filepath.Join(".draugr-out", "results.sarif"),
}

// newExplainCommand builds `draugr explain`.
//
// A finding's identifier and one truncated line is enough to rank it and not enough to decide
// anything. What a reader needs next. What the check means and what to change. Is already in the
// report: scanners publish remediation text and Draugr records it. Without somewhere to read it,
// the identifier sends people to whatever a search engine offers, and for a benchmark that means
// a registration form in front of a PDF.
func newExplainCommand() *cobra.Command {
	var reportPath string
	cmd := &cobra.Command{
		Use:   "explain <rule-id>",
		Short: "Show what a finding means and how to fix it, from a scan's own report",
		Long: "Print a rule's description, the remediation its scanner published, and where the\n" +
			"scan found it.\n\n" +
			"Reads the SARIF a scan wrote with -o, and names the file it read. Name the rule by its full id, by its trailing\n" +
			"segments (`4.3.1` finds `kube-bench/cis/4.3.1`), or by the name a row prints\n" +
			"(`missing-user` finds `dockerfile.security.missing-user.missing-user`).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runExplain(cmd.OutOrStdout(), args[0], reportPath)
		},
	}
	cmd.Flags().StringVarP(&reportPath, "report", "r", "",
		"the results.sarif to read, or the directory a scan wrote with -o (default: the first that exists of "+
			strings.Join(defaultSARIFNames, ", ")+")")
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
		return fmt.Errorf("%s: %w", path, err)
	}

	id, rule, err := matchRule(report, query)
	if err != nil {
		return err
	}
	writeExplanation(w, report, id, rule)
	writeSource(w, path)
	return nil
}

// writeSource names the report the answer came from, and when it was written.
//
// A checkout can hold more than one: a report committed under .draugr/out by a publisher, and the
// one the scan just wrote somewhere else. explain reads the first it finds, and an answer from
// last week's report looks as current as one from a minute ago unless it says which it read.
func writeSource(w io.Writer, path string) {
	col := tui.For(w)
	line := path
	if info, err := os.Stat(path); err == nil {
		line += " · written " + info.ModTime().UTC().Format("2006-01-02 15:04 UTC")
	}
	_, _ = fmt.Fprintf(w, "\n%s\n  %s\n", col.Paint(tui.StyleMuted, "REPORT"), line)
}

// findSARIF resolves which report to read, and says what it looked for when there is none.
//
// A directory is the one a scan wrote with -o, and its results.sarif is read: that is the name the
// scan gives the file, and the directory is what a reader typed to the scan.
func findSARIF(explicit string) (string, error) {
	if explicit != "" {
		info, err := os.Stat(explicit)
		if err != nil || !info.IsDir() {
			return explicit, nil
		}
		path := filepath.Join(explicit, "results.sarif")
		if _, err := os.Stat(path); err != nil {
			return "", fmt.Errorf("no results.sarif in %s; a scan writes it with -o %s unless --report leaves sarif out", explicit, explicit)
		}
		return path, nil
	}
	for _, name := range defaultSARIFNames {
		if _, err := os.Stat(name); err == nil {
			return name, nil
		}
	}
	return "", fmt.Errorf("no scan report here, looked for %s. "+
		"Run a scan with -o .draugr/out, or name the directory a scan wrote with --report <dir>",
		strings.Join(defaultSARIFNames, ", "))
}

// matchRule finds the rule a query names.
//
// Exactly first, then by suffix, because a reader retypes the part that identifies the check
// rather than the namespace in front of it. An ambiguous abbreviation lists what it could have
// meant instead of choosing: picking one would explain a rule the reader did not ask about, and
// they would have no way to tell.
func matchRule(rep sarif.Report, query string) (string, sarif.Rule, error) {
	if rule, ok := rep.Rules[query]; ok {
		return query, rule, nil
	}
	var matched []string
	for id := range rep.Rules {
		if strings.HasSuffix(id, "/"+query) || strings.EqualFold(id, query) || report.NamesRule(id, query) {
			matched = append(matched, id)
		}
	}
	sort.Strings(matched)
	switch len(matched) {
	case 0:
		return "", sarif.Rule{}, fmt.Errorf("no rule %q in this report, which holds only the rules this scan reported. "+
			"Give its id or the name a row prints", query)
	case 1:
		return matched[0], rep.Rules[matched[0]], nil
	default:
		return "", sarif.Rule{}, fmt.Errorf("%q matches %s. Name one of them",
			query, strings.Join(matched, ", "))
	}
}

// writeExplanation prints what is known about a rule, in the order a reader asks it.
func writeExplanation(w io.Writer, report sarif.Report, id string, rule sarif.Rule) {
	col := tui.For(w)

	_, _ = fmt.Fprintf(w, "%s\n", col.Paint(tui.StyleAccent, id))
	// A description naming the rule's own id is a scanner filling the field. Semgrep's reads
	// "Semgrep Finding: <id>", and the detail below it says more.
	if d := strings.TrimSpace(rule.ShortDescription); d != "" && !strings.Contains(d, id) {
		// A title stating what a passing resource looks like reads, under a failed check, as a
		// pass. The findings' own sentence says what failed instead, as the report does, and only
		// where every finding says the same: one resource's sentence printed for several would be
		// wrong about the rest.
		if titlesPassingState(report, id) {
			if said := sameMessage(report, id); said != "" {
				_, _ = fmt.Fprintf(w, "%s\n", said)
			}
		} else {
			_, _ = fmt.Fprintf(w, "%s\n", d)
		}
	}

	// `fullDescription` is whatever the scanner chose to put in it. Most scanners describe the flaw,
	// or the practice the rule exists to enforce, and that is DETAIL. A few put the remediation
	// there, and that is FIX: a heading promising remediation over a sentence explaining the problem,
	// or the other way round, teaches a reader that the labels here are decorative. Which scanners
	// write which is a list, fixDescriptions, read from the scanner each finding names.
	//
	// Wrapped to the terminal, because a scanner writes a paragraph as one line, and at 80 columns
	// the terminal would break it mid-word with no indent.
	if detail := strings.TrimSpace(rule.FullDescription); detail != "" && detail != rule.ShortDescription {
		title := "DETAIL"
		if fixDescriptions[toolOf(report, id)] {
			title = "FIX"
		}
		_, _ = fmt.Fprintf(w, "\n%s\n", col.Paint(tui.StyleMuted, title))
		for _, line := range strings.Split(detail, "\n") {
			for _, part := range wrapDescription(strings.TrimSpace(line), tui.Columns(w)-2) {
				_, _ = fmt.Fprintf(w, "  %s\n", terminalText(col, part))
			}
		}
	}

	if where := findingsFor(report, id); len(where) > 0 {
		_, _ = fmt.Fprintf(w, "\n%s\n", col.Paint(tui.StyleMuted, "LOCATION"))
		for _, line := range where {
			_, _ = fmt.Fprintf(w, "  %s\n", line)
		}
	}

	if rule.HelpURI != "" {
		_, _ = fmt.Fprintf(w, "\n%s\n  %s\n", col.Paint(tui.StyleMuted, "REFERENCE"), rule.HelpURI)
	}
}

// passingStateTitles are the scanners whose rule description is the check's title, which states
// what a passing resource looks like: Prowler's "EBS default encryption is enabled" for a check
// that fails where it is not.
var passingStateTitles = map[string]bool{"prowler": true}

// titlesPassingState reports whether the rule's findings came from a scanner whose rule description
// states the passing condition.
func titlesPassingState(report sarif.Report, id string) bool {
	for _, res := range report.Results {
		if res.RuleID == id {
			return passingStateTitles[res.Tool]
		}
	}
	return false
}

// sameMessage is the message every finding of the rule carries, or "" where they differ or there
// are none.
func sameMessage(report sarif.Report, id string) string {
	said := ""
	for _, res := range report.Results {
		if res.RuleID != id {
			continue
		}
		m := strings.TrimSpace(res.Message)
		if said != "" && m != said {
			return ""
		}
		said = m
	}
	return said
}

// fixDescriptions are the scanners whose rule description is the remediation: Prowler's
// recommendation, kube-bench's remedy and the CIS benchmark's remediation draugr-k8s-policies
// carries.
var fixDescriptions = map[string]bool{
	"prowler": true, "kube-bench": true, "kube-bench-job": true, "draugr-k8s-policies": true,
}

// toolOf is the scanner the rule's findings name, "" where the report holds none of them.
func toolOf(report sarif.Report, id string) string {
	for _, res := range report.Results {
		if res.RuleID == id {
			return res.Tool
		}
	}
	return ""
}

// wrapDescription breaks one line of a description into lines no wider than width once its Markdown
// is rendered, and keeps the line whole where width is not positive, a file or a pipe. A strong span
// broken across lines is closed at the end of one and opened again on the next, so each line renders
// on its own.
func wrapDescription(line string, width int) []string {
	words := strings.Fields(line)
	if width <= 0 || len(words) == 0 {
		return []string{line}
	}
	plain := tui.Plain()
	var parts []string
	cur := ""
	for _, word := range words {
		next := word
		if cur != "" {
			next = cur + " " + word
		}
		if cur != "" && utf8.RuneCountInString(terminalText(plain, next)) > width {
			parts = append(parts, cur)
			next = word
		}
		cur = next
	}
	parts = append(parts, cur)
	open := false
	for i, p := range parts {
		stillOpen := open != (strings.Count(p, "**")%2 == 1)
		if open {
			p = "**" + p
		}
		if stillOpen {
			p += "**"
		}
		parts[i], open = p, stillOpen
	}
	return parts
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

// Markdown a scanner writes into a rule's description, as a terminal should show it. Prowler writes
// its recommendation in Markdown, and Semgrep and gosec put code in backticks, and a terminal prints
// the markup as it is: `**least privilege**` with its asterisks.
var (
	mdStrong  = regexp.MustCompile(`\*\*([^*]+)\*\*|__([^_]+)__`)
	mdCode    = regexp.MustCompile("`([^`]+)`")
	mdLink    = regexp.MustCompile(`\[([^\]]+)\]\(([^)\s]+)\)`)
	mdHeading = regexp.MustCompile(`^#{1,6}\s+`)
)

// terminalText is one line of a description with its Markdown rendered for a terminal: strong text
// in bold where the terminal shows color and plain otherwise, code without its backticks, a link as
// its text and its address, and a heading without its marks. A list item keeps its "- ", which a
// terminal reads as well as Markdown does.
func terminalText(col tui.Painter, line string) string {
	line = mdHeading.ReplaceAllString(line, "")
	line = mdLink.ReplaceAllString(line, "$1 ($2)")
	line = mdCode.ReplaceAllString(line, "$1")
	return mdStrong.ReplaceAllStringFunc(line, func(m string) string {
		sub := mdStrong.FindStringSubmatch(m)
		return col.Paint(tui.StyleStrong, sub[1]+sub[2])
	})
}
