package report

import (
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// A vulnerability not scored yet ranks high, and the console row says why once, in the reasoning
// line where a scanner's rating is shown, rather than again at the end of the title, where it would
// take the room of the advisory's own words.
func TestTheConsoleSaysNotScoredYetOnce(t *testing.T) {
	f := finding{
		message: "golang.org/x/sys v0.1.0 → v0.2.0: a flaw nobody has scored" + sarif.MessageNotScoredYet,
		pkg:     &sarif.Package{Name: "golang.org/x/sys", Version: "v0.1.0", FixedVersion: "v0.2.0"},
		rating:  &sarif.Rating{Severity: sarif.SeverityHigh, Detail: sarif.NotScoredYet},
	}
	if got := findingTitle(f); got != "a flaw nobody has scored" {
		t.Errorf("title = %q", got)
	}
	var notes []string
	for _, p := range reasoning(tui.Painter{}, f) {
		notes = append(notes, p.plain)
	}
	if strings.Count(strings.Join(notes, " · "), sarif.NotScoredYet) != 1 {
		t.Errorf("reasoning = %q, want the label once", notes)
	}

	// A finding the label is not a rating of keeps its message whole.
	f.rating = nil
	if got := findingTitle(f); !strings.HasSuffix(got, sarif.MessageNotScoredYet) {
		t.Errorf("without the rating the title lost its words: %q", got)
	}
}
