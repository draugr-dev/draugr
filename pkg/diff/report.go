package diff

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/draugr-dev/draugr/pkg/sarif"

	"github.com/draugr-dev/draugr/pkg/tui"
)

// Formats lists the diff output formats, sorted.
func Formats() []string { return []string{"console", "json", "markdown", "sarif"} }

// Render writes the diff in the named format. Unknown formats error.
func Render(w io.Writer, format string, r Result) error {
	switch format {
	case "", "console":
		return renderConsole(w, r)
	case "markdown":
		return renderMarkdown(w, r)
	case "json":
		return renderJSON(w, r)
	case "sarif":
		return renderSARIF(w, r)
	default:
		return fmt.Errorf("unknown diff format %q (available: %v)", format, Formats())
	}
}

// renderSARIF writes the new findings, and only those, as a SARIF report.
//
// For code scanning on a pull request. An upload of the whole repository annotates a reviewer with
// hundreds of findings the branch did not cause, and the ones it did are indistinguishable among
// them — which is how a review surface stops being read. This is the answer to the question a pull
// request actually asks.
//
// Fixed and unchanged are deliberately absent rather than empty. A fixed finding is no longer
// there to annotate, and an unchanged one is the pre-existing noise this exists to remove; a
// consumer wanting the whole picture has the head scan's own report.
func renderSARIF(w io.Writer, r Result) error {
	// With the rules those findings cite. Without them a code-scanning alert arrives as a bare
	// identifier: no description, and whatever link can be guessed from the id's shape rather than
	// the advisory the scanner actually named.
	rules := map[string]sarif.Rule{}
	for _, f := range r.New {
		if rule, ok := r.Rules[f.RuleID]; ok {
			rules[f.RuleID] = rule
		}
	}
	rep := sarif.Report{Tool: "draugr-diff", Results: r.New, Rules: rules}
	data, err := rep.MarshalSARIF()
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// headline summarizes the delta in one line, e.g.
// "2 new (1 critical, 1 high), 3 fixed, 5 unchanged".
//
// Only the bands that occur are named. A run with nothing critical should not have to read past
// "0 critical" to find the number that is not zero.
func headline(r Result) string {
	c := countSeverities(r.New)
	var parts []string
	for _, b := range []struct {
		name string
		n    int
	}{{"critical", c.Critical}, {"high", c.High}, {"medium", c.Medium}, {"low", c.Low}} {
		if b.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", b.n, b.name))
		}
	}
	bands := ""
	if len(parts) > 0 {
		bands = " (" + strings.Join(parts, ", ") + ")"
	}
	return fmt.Sprintf("%d new%s, %d fixed, %d unchanged",
		len(r.New), bands, len(r.Fixed), len(r.Unchanged))
}

func loc(f string, line int) string {
	if f == "" {
		return "-"
	}
	if line > 0 {
		return fmt.Sprintf("%s:%d", f, line)
	}
	return f
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// --- console ---

func renderConsole(w io.Writer, r Result) error {
	col := tui.For(w)

	// A diff's headline is its verdict: new findings are the thing to act on, and a clean
	// diff deserves to look clean.
	headlineStyle := tui.StylePass
	if len(r.New) > 0 {
		headlineStyle = tui.StyleFail
	}
	_, _ = fmt.Fprintf(w, "Draugr diff — %s\n", col.Paint(headlineStyle, headline(r)))

	np, fp := countPriorities(r.New), countPriorities(r.Fixed)
	if np != (PriorityCounts{}) || fp != (PriorityCounts{}) {
		_, _ = fmt.Fprintf(w, "New priorities:   P1 %d  P2 %d  P3 %d  P4 %d\n", np.P1, np.P2, np.P3, np.P4)
		_, _ = fmt.Fprintf(w, "Fixed priorities: P1 %d  P2 %d  P3 %d  P4 %d\n", fp.P1, fp.P2, fp.P3, fp.P4)
	}
	_, _ = fmt.Fprintln(w)

	if len(r.New) == 0 && len(r.Fixed) == 0 {
		_, _ = fmt.Fprintln(w, col.Paint(tui.StylePass, "No change in the finding footprint. ✓"))
		return nil
	}

	withComponent := anyComponent(r.New, r.Fixed)
	if len(r.New) > 0 {
		_, _ = fmt.Fprintf(w, "New (%d):\n", len(r.New))
		renderDiffFindings(w, col, "+", tui.StyleFail, r.New, withComponent, r.HelpURI)
		_, _ = fmt.Fprintln(w)
	}
	if len(r.Fixed) > 0 {
		_, _ = fmt.Fprintf(w, "Fixed (%d):\n", len(r.Fixed))
		renderDiffFindings(w, col, "-", tui.StylePass, r.Fixed, withComponent, r.HelpURI)
	}
	return nil
}

// renderDiffFindings lists findings under a sign, using the same table the scan report uses so
// a diff and a scan read alike.
func renderDiffFindings(w io.Writer, col tui.Painter, sign string, style tui.Style, fs []sarif.Result, showComponent bool, help func(string) string) {
	t := tui.NewTable(col).Indent("  ")
	for _, f := range fs {
		cells := []tui.Cell{
			// The sign and the priority travel together — both answer "what is this finding
			// in this diff" — so they share a cell and the spacing stays tight.
			tui.Styled(style, sign+" "+dash(f.Priority)),
			// Severity, not Level. A scan reports critical/high/medium/low; printing the SARIF
			// wire value here made the same finding read as "error" in a diff and "critical" in
			// the report it came from, and left a reader translating between two vocabularies to
			// decide whether a pull request had made things worse.
			tui.PlainCell(string(f.Severity(""))),
			ruleCell(f.RuleID, help(f.RuleID)),
		}
		if showComponent {
			cells = append(cells, tui.PlainCell(dash(f.Component)))
		}
		cells = append(cells, tui.Styled(tui.StyleMuted, loc(f.Location.URI, f.Location.StartLine)))
		t.Row(cells...)
	}
	t.Render(w)
}

// anyComponent reports whether any finding in either list names one.
//
// Shown only when there is something to say. A single-component project would get a column
// repeating itself, which is the rule the scan report already follows.
//
// It matters most here: a pull-request comment is the multi-component case — one PR touches one
// service in a monorepo, and the first question is whether the finding is yours. Without it two
// components sharing a dependency produce rows identical in every visible column, and a reviewer
// reasonably reads the second as the tool repeating itself.
func anyComponent(lists ...[]sarif.Result) bool {
	for _, fs := range lists {
		for _, f := range fs {
			if f.Component != "" {
				return true
			}
		}
	}
	return false
}

// --- markdown ---

func renderMarkdown(w io.Writer, r Result) error {
	_, _ = fmt.Fprintf(w, "## Draugr diff\n\n**%s**\n\n", headline(r))

	if len(r.New) == 0 && len(r.Fixed) == 0 {
		_, _ = fmt.Fprintln(w, "No change in the finding footprint. ✓")
		return nil
	}

	withComponent := anyComponent(r.New, r.Fixed)
	if len(r.New) > 0 {
		_, _ = fmt.Fprintf(w, "### 🔺 New (%d)\n\n", len(r.New))
		mdTable(w, r.New, withComponent, r.HelpURI)
		_, _ = fmt.Fprintln(w)
	}
	if len(r.Fixed) > 0 {
		_, _ = fmt.Fprintf(w, "### ✅ Fixed (%d)\n\n", len(r.Fixed))
		mdTable(w, r.Fixed, withComponent, r.HelpURI)
	}
	return nil
}

// ruleCell renders a rule id, linked to what the scanner published about it where the terminal
// supports it. The URL costs no width, which is what makes it usable in a table this wide — the
// scan report's findings table does the same, so the two read alike.
func ruleCell(ruleID, helpURI string) tui.Cell {
	return tui.Cell{Text: ruleID, URL: helpURI}
}

func mdTable(w io.Writer, rs []sarif.Result, showComponent bool, help func(string) string) {
	// Component before Location, as in the scan report: a path answers "where inside", and the
	// reader of a monorepo pull request needs "which one" first.
	if showComponent {
		_, _ = fmt.Fprintln(w, "| Priority | Severity | Rule | Tool | Component | Location |")
		_, _ = fmt.Fprintln(w, "|---|---|---|---|---|---|")
	} else {
		_, _ = fmt.Fprintln(w, "| Priority | Severity | Rule | Tool | Location |")
		_, _ = fmt.Fprintln(w, "|---|---|---|---|---|")
	}
	for _, f := range rs {
		component := ""
		if showComponent {
			component = " " + dash(f.Component) + " |"
		}
		// Linked to what the scanner published about it — Trivy's advisory page for a CVE, the
		// rule's documentation for a static-analysis finding. A reader deciding whether a new
		// finding matters is one click from the answer rather than one search.
		rule := "`" + f.RuleID + "`"
		if u := help(f.RuleID); u != "" {
			rule = "[" + rule + "](" + u + ")"
		}
		_, _ = fmt.Fprintf(w, "| %s | %s | %s | %s |%s %s |\n",
			dash(f.Priority), f.Severity(""), rule, dash(f.Tool), component,
			loc(f.Location.URI, f.Location.StartLine))
	}
}

// --- json ---

type jsonDiff struct {
	Summary jsonSummary    `json:"summary"`
	New     []sarif.Result `json:"new"`
	Fixed   []sarif.Result `json:"fixed"`
}

type jsonSummary struct {
	New       int `json:"new"`
	Fixed     int `json:"fixed"`
	Unchanged int `json:"unchanged"`

	NewBySeverity   SeverityCounts `json:"newBySeverity"`
	FixedBySeverity SeverityCounts `json:"fixedBySeverity"`
	NewByPriority   PriorityCounts `json:"newByPriority"`
	FixedByPriority PriorityCounts `json:"fixedByPriority"`
}

func renderJSON(w io.Writer, r Result) error {
	doc := jsonDiff{
		Summary: jsonSummary{
			New: len(r.New), Fixed: len(r.Fixed), Unchanged: len(r.Unchanged),
			NewBySeverity: countSeverities(r.New), FixedBySeverity: countSeverities(r.Fixed),
			NewByPriority: countPriorities(r.New), FixedByPriority: countPriorities(r.Fixed),
		},
		New:   r.New,
		Fixed: r.Fixed,
	}
	if doc.New == nil {
		doc.New = []sarif.Result{}
	}
	if doc.Fixed == nil {
		doc.Fixed = []sarif.Result{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
