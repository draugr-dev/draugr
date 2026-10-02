package saga

import (
	"strings"
	"testing"
)

const annotateDoc = `project: app
release:
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

const signersDoc = `project: p
release:
  version: "1"
config:
  controls:
    provenance:
      enabled: true
      signers:
        - name: acme-ci
          images: ["ghcr.io/acme/*"]
          github:
            repository: acme/ci-workflows
            workflow: .github/workflows/build.yml
        - name: hand-written
          images: ["cgr.dev/chainguard/*"]
          github:
            repository: chainguard-images/images
            workflow: .github/workflows/release.yaml
components:
  - name: api
`

// A signer a survey read from a signature says which image it came from, beside its name. One
// somebody wrote by hand is left alone, because a comment would describe it as something found.
func TestAnnotateSignersSaysWhichSignatureEachCameFrom(t *testing.T) {
	out, err := AnnotateSigners([]byte(signersDoc), map[string]string{
		"acme-ci": "read from the signature on ghcr.io/acme/api:1.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	if !strings.Contains(got, "- name: acme-ci # read from the signature on ghcr.io/acme/api:1.0") {
		t.Errorf("the surveyed signer carries no reason:\n%s", got)
	}
	if strings.Contains(got, "hand-written #") {
		t.Errorf("a hand-written signer was annotated:\n%s", got)
	}
	if _, err := Load([]byte(got)); err != nil {
		t.Errorf("annotated document no longer parses: %v\n%s", err, got)
	}
}

// Nothing to say means the document comes back byte for byte, whatever is missing from it.
func TestAnnotateSignersLeavesADocumentItHasNothingToSayAbout(t *testing.T) {
	reasons := map[string]string{"acme-ci": "read from a signature"}
	for name, doc := range map[string]string{
		"no reasons":            "",
		"empty document":        "",
		"no config":             "project: p\n",
		"no controls":           "config:\n  gate: {failOn: P1}\n",
		"no provenance":         "config:\n  controls:\n    sca: {enabled: true}\n",
		"no signers":            "config:\n  controls:\n    provenance: {enabled: true}\n",
		"signers not a list":    "config:\n  controls:\n    provenance:\n      signers: {name: acme-ci}\n",
		"a signer with no name": "config:\n  controls:\n    provenance:\n      signers:\n        - images: [x]\n        - plain\n",
		"no matching signer":    "config:\n  controls:\n    provenance:\n      signers:\n        - name: someone-else\n",
	} {
		r := reasons
		if name == "no reasons" {
			doc, r = signersDoc, nil
		}
		out, err := AnnotateSigners([]byte(doc), r)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if string(out) != doc {
			t.Errorf("%s: document was rewritten:\n%s", name, out)
		}
	}
	if _, err := AnnotateSigners([]byte("\tnot: [yaml"), reasons); err == nil {
		t.Error("expected a parse error")
	}
}
