package cli

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/draugr-dev/draugr/internal/inventory"
	"github.com/draugr-dev/draugr/internal/scaffold"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// foundRow is one kind of file found, where, and what a descriptor for the tree does with it.
//
// One list for `draugr init`'s FOUND block and for the FOUND section of a scan with no descriptor,
// which say the same thing about the same tree in the two places a reader meets it.
type foundRow struct {
	kind, where string
	// on are the controls and scanners the scaffold turns on for these files, by the names the
	// registry gives them.
	on []string
	// commented is the block the scaffold writes commented out for these files, and off the
	// control that block would turn on, which a scan with no descriptor leaves off.
	commented, off string
}

// initSays is what init's FOUND block says the scaffold does with the files.
func (r foundRow) initSays() string { return dotJoin(r.on, r.commented, ", commented") }

// scanSays is what a scan's FOUND section says the run did with them.
func (r foundRow) scanSays() string { return dotJoin(r.on, r.off, " off") }

// dotJoin joins what was turned on, and then the block left off with its suffix, where there is
// one.
func dotJoin(on []string, left, suffix string) string {
	parts := slices.Clone(on)
	if left != "" {
		parts = append(parts, left+suffix)
	}
	return strings.Join(parts, " · ")
}

func foundRows(t inventory.Tree) []foundRow {
	var rows []foundRow
	byEco := map[string][]string{}
	var ecos []string
	for _, f := range t.Dependencies {
		if _, ok := byEco[f.Ecosystem]; !ok {
			ecos = append(ecos, f.Ecosystem)
		}
		byEco[f.Ecosystem] = append(byEco[f.Ecosystem], f.Path)
	}
	goScanners := []string{"gosec", "govulncheck"}
	for _, e := range ecos {
		if e == "go" {
			// Every go.mod, including one that requires nothing and so is not a dependency.
			rows = append(rows, foundRow{kind: e, where: scaffold.PathList(scaffold.GoModules(t)),
				on: append([]string{"sca"}, goScanners...)})
			continue
		}
		rows = append(rows, foundRow{kind: e, where: scaffold.PathList(byEco[e]), on: []string{"sca"}})
	}
	if _, ok := byEco["go"]; !ok && len(t.Go) > 0 {
		// A go.mod with no requirements gives sca nothing to read, and the Go controls their code.
		rows = append(rows, foundRow{kind: "go", where: scaffold.PathList(scaffold.GoModules(t)), on: goScanners})
	}
	if len(t.VendoredJS) > 0 {
		rows = append(rows, foundRow{kind: "copied JavaScript", where: scaffold.PathList(t.VendoredJS), on: []string{"retirejs"}})
	}
	if len(t.TrivyByPattern) > 0 {
		rows = append(rows, foundRow{kind: "read by a file pattern",
			where: scaffold.PathList(scaffold.FilePaths(t.TrivyByPattern)), on: []string{"trivy-fs filePatterns"}})
	}
	if len(t.TrivyUnread) > 0 {
		rows = append(rows, foundRow{kind: "read by Grype only",
			where: scaffold.PathList(scaffold.FilePaths(t.TrivyUnread)), on: []string{"grype-fs"}})
	}
	iac := []string{"iac"}
	if len(t.Terraform) > 0 {
		rows = append(rows, foundRow{kind: "Terraform", where: scaffold.PathList(t.Terraform), on: iac})
	}
	if len(t.Helm) > 0 {
		rows = append(rows, foundRow{kind: "Helm", where: scaffold.PathList(t.Helm), on: iac})
	}
	if len(t.Kubernetes) > 0 {
		rows = append(rows, foundRow{kind: "Kubernetes", where: scaffold.PathList(t.Kubernetes), on: iac})
	}
	if len(t.Dockerfiles) > 0 {
		rows = append(rows, foundRow{kind: "Dockerfile", where: scaffold.PathList(t.Dockerfiles), on: iac,
			commented: "images", off: "images"})
	}
	if len(t.OpenAPI) > 0 {
		// The scaffold comments out a host whose spec is this document, and dast is the control that
		// reads a host's spec.
		rows = append(rows, foundRow{kind: "OpenAPI", where: scaffold.PathList(t.OpenAPI),
			commented: "hosts spec", off: "dast"})
	}
	return rows
}

// foundFiles are the files of every row that turned scanner on, as one list.
func foundFiles(rows []foundRow, scanner string) string {
	var where []string
	for _, r := range rows {
		if slices.Contains(r.on, scanner) {
			where = append(where, r.where)
		}
	}
	return strings.Join(where, " · ")
}

// unreadNote says what the Unread section lists, in the words a scan's own section uses.
const initUnreadNote = "dependency files no scanner can take packages from · their packages will not be checked"

// writeInitSummary prints what init wrote and what needs a person.
func writeInitSummary(w io.Writer, col tui.Painter, t inventory.Tree, opts initOptions) {
	out := opts.output
	_, _ = fmt.Fprintf(w, "%s wrote %s\n", col.Paint(tui.StylePass, "✓"), out)
	if opts.perDirectory && len(t.Parts) == 0 {
		_, _ = fmt.Fprintf(w, "  --per-directory: no directory below the root holds its own dependency file · wrote one component\n")
	}
	_, _ = fmt.Fprintln(w)

	if rows := foundRows(t); len(rows) > 0 {
		_, _ = fmt.Fprintln(w, col.Paint(tui.StyleMuted, "FOUND"))
		tbl := tui.NewTable(col).Indent("  ")
		for _, r := range rows {
			tbl.Row(tui.PlainCell(r.kind), tui.PlainCell(r.where), tui.Styled(tui.StyleMuted, r.initSays()))
		}
		tbl.Render(w)
		_, _ = fmt.Fprintln(w)
	}
	if len(t.Unresolved) > 0 {
		_, _ = fmt.Fprintln(w, col.Paint(tui.StyleMuted, "UNREAD")+"  "+col.Paint(tui.StyleMuted, initUnreadNote))
		width := 0
		for _, u := range t.Unresolved {
			width = max(width, len(u.Path))
		}
		for _, u := range t.Unresolved {
			_, _ = fmt.Fprintf(w, "  %-*s  %s\n", width, u.Path, col.Paint(tui.StyleMuted, string(u.Reason)))
		}
		_, _ = fmt.Fprintln(w)
	}
	_, _ = fmt.Fprintf(w, "Next:\n  draugr doctor %s   # check the scanners it needs\n  draugr scan %s\n", out, out)
}
