package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/draugr-dev/draugr/pkg/tui"
)

// PublishedRun is a run a draugr-api server recorded: the server, the project and the run's id, and
// the address a person opens it at where the server gives one.
type PublishedRun struct {
	// Server is the endpoint the run was published to.
	Server string
	// Project and Run are the server's names for where the run went and for the run.
	Project, Run string
	// URL is the run's page, as the server gave it, and empty where it gave none. Draugr never builds
	// one: only the server knows where its pages are served.
	URL string
	// Duplicate is a run the server had already recorded, from an earlier attempt at the same job.
	Duplicate bool
}

// says is what stands beside the first column: the project, then the run's id beside its address, or
// the server beside its id.
func (r PublishedRun) says() string {
	parts := []string{r.Project, r.Server}
	if r.URL != "" {
		parts[1] = r.Run
	}
	if r.Duplicate {
		parts = append(parts, "recorded by an earlier attempt")
	}
	return strings.Join(parts, " · ")
}

// writePublished names each run a server recorded, after the reports the run wrote: both are where
// the rest of this run can be read. The first column is what a reader copies, the run's address, or
// its id where the server gave no address.
func writePublished(w io.Writer, col tui.Painter, d Data) {
	if len(d.Published) == 0 {
		return
	}
	t := tui.NewTable(col).Indent("  ").Fit(tui.Columns(w)).MoveLast()
	for _, r := range d.Published {
		first := tui.Cell{Text: r.Run}
		if r.URL != "" {
			first = tui.Cell{Text: r.URL, URL: r.URL}
		}
		t.Row(first, tui.Styled(cDim, r.says()))
	}
	_, _ = fmt.Fprintln(w, heading(col, "Published"))
	t.Render(w)
	_, _ = fmt.Fprintln(w)
}
