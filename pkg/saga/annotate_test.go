package saga

import (
	"strings"
	"testing"
)

const annotateDoc = `release:
  name: app
  version: "1"
components:
  - name: front
    exposure:
      value: public
    images:
      - image: repo/a:1
  - name: back
    exposure:
      value: internal
      reason: an earlier survey said so
  - name: decided
    exposure:
      value: restricted
`

// The evidence has to reach the file, because the file is where the value is reviewed — and it
// has to reach the rule rather than a comment beside it, because a comment does not survive the
// descriptor being merged and re-serialized before a run is published.
func TestAnnotateExposuresPutsTheReasonBesideTheValue(t *testing.T) {
	out, err := AnnotateExposures([]byte(annotateDoc), map[string]string{
		"front": "an Ingress routes into it",
		"back":  "no Ingress, external Service or NetworkPolicy found",
	})
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	for _, want := range []string{
		"reason: an Ingress routes into it",
		"reason: no Ingress, external Service or NetworkPolicy found",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q:\n%s", want, got)
		}
	}
	// A reason already there is replaced rather than left beside the new one.
	if strings.Contains(got, "an earlier survey said so") {
		t.Errorf("kept a stale reason:\n%s", got)
	}
	// A value somebody decided is not a guess, and a reason would describe it as one.
	m, err := Load([]byte(got))
	if err != nil {
		t.Fatalf("annotated document no longer parses: %v\n%s", err, got)
	}
	for _, c := range m.Components {
		if c.Name == "decided" && c.Exposure.Reason != "" {
			t.Errorf("annotated an exposure nobody proposed: %q", c.Exposure.Reason)
		}
	}
}

// Re-encoding through the node tree normalizes formatting, so a document with nothing to say must
// come back exactly as it went in rather than reindented for no reason.
func TestAnnotateExposuresLeavesADocumentItHasNothingToSayAbout(t *testing.T) {
	for name, reasons := range map[string]map[string]string{
		"no reasons at all":        nil,
		"reasons for other things": {"nobody": "…"},
	} {
		out, err := AnnotateExposures([]byte(annotateDoc), reasons)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if string(out) != annotateDoc {
			t.Errorf("%s: document was rewritten:\n%s", name, out)
		}
	}
}

func TestAnnotateExposuresRejectsWhatIsNotYAML(t *testing.T) {
	if _, err := AnnotateExposures([]byte("\tnot: [yaml"), map[string]string{"a": "b"}); err == nil {
		t.Error("expected a parse error")
	}
}
