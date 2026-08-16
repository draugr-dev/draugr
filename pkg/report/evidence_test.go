package report

import (
	"bytes"
	"strings"
	"testing"
)

// TestEvidenceFormatCarriesProvenanceWithoutTheFindings covers what the document is for.
//
// It answers "can I trust this run", not "what did it find". Duplicating hundreds of findings
// into it would make it unreadable for its own purpose, and they are already in the report and
// the SARIF written beside it.
func TestEvidenceFormatCarriesProvenanceWithoutTheFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := (evidenceReporter{}).Render(&buf, goldenFullData()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	for _, want := range []string{
		"Draugr evidence", // says what it is
		"Ran 11 jobs",     // what it cost
		"Verdict:",        // and what it stands behind
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the evidence is missing %q:\n%s", want, out)
		}
	}
	// Not a second copy of the findings.
	if strings.Contains(out, "Fix first") {
		t.Error("the evidence document duplicated the fix list")
	}
	if strings.Contains(out, "CVE-2019-20477") {
		t.Error("the evidence document listed findings, which belong in the report beside it")
	}
}

// TestEvidenceAndTheModeAgree: the two deliveries render from one function, so they cannot drift
// into disagreeing about what a run did. Checked both ways — a one-directional comparison passes
// happily while one side quietly carries a block the other does not.
func TestEvidenceAndTheModeAgree(t *testing.T) {
	d := goldenFullData()

	var doc bytes.Buffer
	if err := (evidenceReporter{}).Render(&doc, d); err != nil {
		t.Fatal(err)
	}
	d.Evidence = true
	var console bytes.Buffer
	if err := (consoleReporter{}).Render(&console, d); err != nil {
		t.Fatal(err)
	}

	// Every provenance line the document carries has to be in the console mode too.
	for _, line := range strings.Split(doc.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Draugr evidence") ||
			strings.HasPrefix(line, "Generated") || strings.HasPrefix(line, "Verdict:") {
			continue
		}
		if !strings.Contains(console.String(), line) {
			t.Errorf("the document says %q and the mode does not", line)
		}
	}

	// And the other way. Anything the mode shows and the default view does not is provenance,
	// so it belongs in the document as well — this is the direction that catches a block wired
	// into one delivery and not the other.
	var plain bytes.Buffer
	d.Evidence = false
	if err := (consoleReporter{}).Render(&plain, d); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(console.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(plain.String(), line) {
			continue
		}
		if !strings.Contains(doc.String(), line) {
			t.Errorf("--evidence shows %q and the document does not", line)
		}
	}
}

// TestDefaultViewOmitsTheEvidence is the other half: without the flag, the blocks that answer a
// question the reader has not asked are not on the screen competing with the one they have.
func TestDefaultViewOmitsTheEvidence(t *testing.T) {
	var buf bytes.Buffer
	if err := (consoleReporter{}).Render(&buf, goldenGroupedData()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	// The tool build rides along in "Measured against", which stays because it carries coverage.
	// Splitting a line that reads "trivy 0.69.3 — policy deny copyleft" into a provenance half
	// and a coverage half would cost more than the version string does.
	for _, unwanted := range []string{"Ran 11 jobs", "4 from cache"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("the default view still carries %q", unwanted)
		}
	}
	// What must never be hidden. A control that could not run, and what the ones that did run
	// were measured against — which carries what they did *not* cover, and a partial scan
	// reading as a complete one is the failure that block exists to prevent.
	if !strings.Contains(out, "did not run") {
		t.Error("the default view dropped the control that could not run")
	}
	if !strings.Contains(out, "Measured against") {
		t.Error("the default view dropped what each control was measured against")
	}
}
