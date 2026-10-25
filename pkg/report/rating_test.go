package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// ratedSemgrep is the dangerous-system-call result Semgrep 1.182.1 reports on draugr-demo's
// app/app.py, rated from the rule's impact and likelihood.
func ratedSemgrep() sarif.Result {
	return sarif.Result{
		Tool: "semgrep", RuleID: "python.lang.security.dangerous-system-call.dangerous-system-call",
		Level: sarif.LevelError, Priority: "P1",
		Message: "Found user-controlled data used in a system call. This could allow a malicious actor to " +
			"execute commands. Use the 'subprocess' module instead, which is easier to use without " +
			"accidentally exposing a command injection vulnerability.",
		Location: sarif.Location{URI: "app/app.py", StartLine: 16},
		Rating: &sarif.Rating{
			Severity: sarif.SeverityCritical, Detail: "impact high · likelihood high",
			Fields: map[string]string{"impact": "HIGH", "likelihood": "HIGH", "confidence": "MEDIUM", "subcategory": "vuln"},
		},
	}
}

// blockLines renders findings as the default view does, one string per line, without color.
func blockLines(t *testing.T, fs ...finding) []string {
	t.Helper()
	var buf bytes.Buffer
	renderFixFirstBlocks(&buf, tui.Plain(), fs, blobLinker{})
	return strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
}

// The severity column shows the rating's band, and the evidence line says what the scanner said,
// so the two can be checked against each other where the reader is looking.
func TestTheRatingIsOnTheEvidenceLine(t *testing.T) {
	lines := blockLines(t, findingOf("sast", sarif.Report{}, ratedSemgrep()))
	if len(lines) != 3 {
		t.Fatalf("got %d lines:\n%s", len(lines), strings.Join(lines, "\n"))
	}
	if !strings.HasPrefix(lines[0], "  P1  critical  ") {
		t.Errorf("head = %q, want the rating's critical beside the band", lines[0])
	}
	if want := "      app/app.py:16 · impact high · likelihood high"; lines[2] != want {
		t.Errorf("evidence line = %q\nwant %q", lines[2], want)
	}
}

// The rating is the first input to the band, so it leads what stands behind it, ahead of a second
// scanner's word or a control's floor.
func TestTheRatingLeadsTheReasoning(t *testing.T) {
	f := findingOf("sast", sarif.Report{}, ratedSemgrep())
	f.priorityFloor = "a control's floor"
	parts := reasoning(tui.Plain(), f)
	if len(parts) != 2 || parts[0].plain != "impact high · likelihood high" || parts[1].plain != "a control's floor" {
		t.Errorf("reasoning = %+v", parts)
	}
}

// A finding the level rated says nothing more than it did.
func TestAnUnratedFindingCarriesNoRatingNote(t *testing.T) {
	res := ratedSemgrep()
	res.Rating = nil
	lines := blockLines(t, findingOf("sast", sarif.Report{}, res))
	if !strings.HasPrefix(lines[0], "  P1  high      ") {
		t.Errorf("head = %q, want error's high", lines[0])
	}
	if want := "      app/app.py:16"; lines[2] != want {
		t.Errorf("evidence line = %q, want the location alone", lines[2])
	}
}
