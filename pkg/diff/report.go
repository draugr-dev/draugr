package diff

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// Formats lists the diff output formats, sorted.
func Formats() []string { return []string{"console", "json", "markdown"} }

// Render writes the diff in the named format. Unknown formats error.
func Render(w io.Writer, format string, r Result) error {
	switch format {
	case "", "console":
		return renderConsole(w, r)
	case "markdown":
		return renderMarkdown(w, r)
	case "json":
		return renderJSON(w, r)
	default:
		return fmt.Errorf("unknown diff format %q (available: %v)", format, Formats())
	}
}

// headline summarizes the delta in one line, e.g. "2 new (1 error), 3 fixed, 5 unchanged".
func headline(r Result) string {
	nl := countLevels(r.New)
	return fmt.Sprintf("%d new (%d error, %d warning, %d note), %d fixed, %d unchanged",
		len(r.New), nl.Error, nl.Warning, nl.Note, len(r.Fixed), len(r.Unchanged))
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
	_, _ = fmt.Fprintf(w, "Draugr diff — %s\n", headline(r))

	np, fp := countPriorities(r.New), countPriorities(r.Fixed)
	if np != (PriorityCounts{}) || fp != (PriorityCounts{}) {
		_, _ = fmt.Fprintf(w, "New priorities:   P1 %d  P2 %d  P3 %d  P4 %d\n", np.P1, np.P2, np.P3, np.P4)
		_, _ = fmt.Fprintf(w, "Fixed priorities: P1 %d  P2 %d  P3 %d  P4 %d\n", fp.P1, fp.P2, fp.P3, fp.P4)
	}
	_, _ = fmt.Fprintln(w)

	if len(r.New) == 0 && len(r.Fixed) == 0 {
		_, _ = fmt.Fprintln(w, "No change in the finding footprint. ✓")
		return nil
	}

	if len(r.New) > 0 {
		_, _ = fmt.Fprintf(w, "New (%d):\n", len(r.New))
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		for _, f := range r.New {
			_, _ = fmt.Fprintf(tw, "  + %s\t%s\t%s\t%s\n", dash(f.Priority), f.Level, f.RuleID, loc(f.Location.URI, f.Location.StartLine))
		}
		_ = tw.Flush()
		_, _ = fmt.Fprintln(w)
	}
	if len(r.Fixed) > 0 {
		_, _ = fmt.Fprintf(w, "Fixed (%d):\n", len(r.Fixed))
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		for _, f := range r.Fixed {
			_, _ = fmt.Fprintf(tw, "  - %s\t%s\t%s\t%s\n", dash(f.Priority), f.Level, f.RuleID, loc(f.Location.URI, f.Location.StartLine))
		}
		_ = tw.Flush()
	}
	return nil
}

// --- markdown ---

func renderMarkdown(w io.Writer, r Result) error {
	_, _ = fmt.Fprintf(w, "## Draugr diff\n\n**%s**\n\n", headline(r))

	if len(r.New) == 0 && len(r.Fixed) == 0 {
		_, _ = fmt.Fprintln(w, "No change in the finding footprint. ✓")
		return nil
	}

	if len(r.New) > 0 {
		_, _ = fmt.Fprintf(w, "### 🔺 New (%d)\n\n", len(r.New))
		mdTable(w, r.New)
		_, _ = fmt.Fprintln(w)
	}
	if len(r.Fixed) > 0 {
		_, _ = fmt.Fprintf(w, "### ✅ Fixed (%d)\n\n", len(r.Fixed))
		mdTable(w, r.Fixed)
	}
	return nil
}

func mdTable(w io.Writer, rs []sarif.Result) {
	_, _ = fmt.Fprintln(w, "| Priority | Severity | Rule | Tool | Location |")
	_, _ = fmt.Fprintln(w, "|---|---|---|---|---|")
	for _, f := range rs {
		_, _ = fmt.Fprintf(w, "| %s | %s | `%s` | %s | %s |\n",
			dash(f.Priority), f.Level, f.RuleID, dash(f.Tool), loc(f.Location.URI, f.Location.StartLine))
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

	NewByLevel      LevelCounts    `json:"newByLevel"`
	FixedByLevel    LevelCounts    `json:"fixedByLevel"`
	NewByPriority   PriorityCounts `json:"newByPriority"`
	FixedByPriority PriorityCounts `json:"fixedByPriority"`
}

func renderJSON(w io.Writer, r Result) error {
	doc := jsonDiff{
		Summary: jsonSummary{
			New: len(r.New), Fixed: len(r.Fixed), Unchanged: len(r.Unchanged),
			NewByLevel: countLevels(r.New), FixedByLevel: countLevels(r.Fixed),
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
