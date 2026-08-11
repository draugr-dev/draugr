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
    exposure: public
    images:
      - image: repo/a:1
  - name: back
    exposure: internal
  - name: decided
    exposure: restricted
`

// The reason has to reach the file, because the file is where the value is reviewed. A survey
// names its guesses on the way out, but that is a terminal that scrolls, and the person who opens
// the descriptor later may not be the one who ran the command.
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
		"exposure: public # an Ingress routes into it",
		"exposure: internal # no Ingress, external Service or NetworkPolicy found",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q:\n%s", want, got)
		}
	}
	// A value somebody decided is not a guess, and a comment would say otherwise.
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, "restricted") && strings.Contains(line, "#") {
			t.Errorf("annotated an exposure nobody proposed: %q", line)
		}
	}
	// Still a descriptor.
	if _, err := Load([]byte(got)); err != nil {
		t.Errorf("annotated document no longer parses: %v\n%s", err, got)
	}
}

// Re-encoding through the node tree normalises formatting, so a document with nothing to say must
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
