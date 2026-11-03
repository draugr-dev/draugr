package report

import (
	"regexp"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
)

// A control whose scans left files unread says how many on its own row, in every report that draws
// one, counted over both components; a control with none says nothing more.
func TestControlRowCountsItsUnreadFiles(t *testing.T) {
	d := everyCaveatData()
	d.Verdict.Controls = append(d.Verdict.Controls, norn.ControlOutcome{Control: "licenses", Verdict: norn.Pass})
	d.Run.Inputs = append(d.Run.Inputs, engine.InputCoverage{Component: "edge", Control: "sca",
		Unread: []engine.UnreadInput{
			{Repository: "./edge", Path: "rs/Cargo.lock", Reason: "no packages read"},
			{Repository: "./edge", Path: "web/package.json", Reason: "no lockfile"},
		}})

	console := renderWith(t, consoleReporter{}, d)
	if !regexp.MustCompile(`(?m)^  sca\s+pass\s+no findings · 3 files unread$`).MatchString(console) {
		t.Errorf("console sca row does not count its 3 unread files:\n%s", console)
	}
	if !regexp.MustCompile(`(?m)^  licenses\s+pass\s+no findings$`).MatchString(console) {
		t.Errorf("console licenses row should say nothing of unread files:\n%s", console)
	}

	md := renderWith(t, markdownReporter{}, d)
	if !strings.Contains(md, "| sca | pass · 3 files unread |") {
		t.Errorf("markdown sca row does not count its unread files:\n%s", md)
	}
	if !strings.Contains(md, "| licenses | pass |") {
		t.Errorf("markdown licenses row should say nothing of unread files:\n%s", md)
	}

	html := renderHTML(t, d)
	// Once, under sca, and not under licenses.
	if n := strings.Count(html, `<span class="ctl-none">3 files unread</span>`); n != 1 {
		t.Errorf("HTML control rows carry the sca note %d times, want 1", n)
	}
	if n := strings.Count(html, `unread</span>`); n != 1 {
		t.Errorf("HTML control rows carry %d unread notes, want 1 (sca's)", n)
	}
}
