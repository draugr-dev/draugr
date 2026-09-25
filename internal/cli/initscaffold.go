package cli

import (
	"fmt"
	"io"

	"github.com/draugr-dev/draugr/internal/inventory"
	"github.com/draugr-dev/draugr/internal/scaffold"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// foundRow is one kind of thing found, where, and what it enabled.
type foundRow struct{ kind, where, enables string }

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
	for _, e := range ecos {
		if e == "go" {
			// Every go.mod, including one that requires nothing and so is not a dependency.
			rows = append(rows, foundRow{e, scaffold.PathList(scaffold.GoModules(t)), "sca · gosec · govulncheck"})
			continue
		}
		rows = append(rows, foundRow{e, scaffold.PathList(byEco[e]), "sca"})
	}
	if _, ok := byEco["go"]; !ok && len(t.Go) > 0 {
		// A go.mod with no requirements gives sca nothing to read, and the Go controls their code.
		rows = append(rows, foundRow{"go", scaffold.PathList(scaffold.GoModules(t)), "gosec · govulncheck"})
	}
	if len(t.VendoredJS) > 0 {
		rows = append(rows, foundRow{"copied JavaScript", scaffold.PathList(t.VendoredJS), "retirejs"})
	}
	if len(t.TrivyByPattern) > 0 {
		rows = append(rows, foundRow{"read by a file pattern", scaffold.PathList(scaffold.FilePaths(t.TrivyByPattern)), "trivy-fs filePatterns"})
	}
	if len(t.TrivyUnread) > 0 {
		rows = append(rows, foundRow{"read by Grype only", scaffold.PathList(scaffold.FilePaths(t.TrivyUnread)), "grype-fs"})
	}
	if len(t.Terraform) > 0 {
		rows = append(rows, foundRow{"Terraform", scaffold.PathList(t.Terraform), "iac"})
	}
	if len(t.Helm) > 0 {
		rows = append(rows, foundRow{"Helm", scaffold.PathList(t.Helm), "iac"})
	}
	if len(t.Kubernetes) > 0 {
		rows = append(rows, foundRow{"Kubernetes", scaffold.PathList(t.Kubernetes), "iac"})
	}
	if len(t.Dockerfiles) > 0 {
		rows = append(rows, foundRow{"Dockerfile", scaffold.PathList(t.Dockerfiles), "iac · images, commented"})
	}
	if len(t.OpenAPI) > 0 {
		rows = append(rows, foundRow{"OpenAPI", scaffold.PathList(t.OpenAPI), "hosts spec, commented"})
	}
	return rows
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
			tbl.Row(tui.PlainCell(r.kind), tui.PlainCell(r.where), tui.Styled(tui.StyleMuted, r.enables))
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
