package config

import (
	"strings"
	"testing"
)

func TestSetPreservesComments(t *testing.T) {
	// The whole reason this edits a node tree. A `config set` that deleted the explanation
	// somebody wrote beside a pin teaches people not to use it, and they go back to hand-editing
	// the file the command exists to keep valid.
	doc := `# Our pinned toolchain — do not bump without the platform team.
tools:
  # Trivy 0.69 is the last release verified against our air-gapped mirror.
  trivy:
    version: "0.69.3"
`
	out, err := Set([]byte(doc), "tools.trivy.version", "0.70.0")
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	for _, want := range []string{"do not bump without the platform team", "air-gapped mirror"} {
		if !strings.Contains(got, want) {
			t.Errorf("comment lost:\n%s", got)
		}
	}
	if !strings.Contains(got, "0.70.0") {
		t.Errorf("value not set:\n%s", got)
	}
}

func TestSetCreatesNestedPaths(t *testing.T) {
	out, err := Set(nil, "controllers.sca.mend.policy", "corp-default")
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := Get(out, "controllers.sca.mend.policy"); !ok || v != "corp-default" {
		t.Errorf("round trip failed: %q %v\n%s", v, ok, out)
	}
}

func TestSetKeepsVersionsAsStrings(t *testing.T) {
	// "0.69.3" is not a number, and a config that quietly turned `enabled: true` into the string
	// "true" would be a different setting wearing the same name.
	out, _ := Set(nil, "tools.trivy.version", "0.69.3")
	if !strings.Contains(string(out), `"0.69.3"`) && !strings.Contains(string(out), "0.69.3") {
		t.Errorf("version mangled:\n%s", out)
	}
	out, _ = Set(nil, "controllers.sast.gosec.enabled", "true")
	if !strings.Contains(string(out), "enabled: true") {
		t.Errorf("boolean written as a string:\n%s", out)
	}
	out, _ = Set(nil, "controllers.sca.trivyFs.timeout", "30")
	if !strings.Contains(string(out), "timeout: 30") {
		t.Errorf("integer written as a string:\n%s", out)
	}
}

func TestUnsetPrunesEmptyMappings(t *testing.T) {
	// A `mend` block left behind with nothing in it is not the same file as one that never
	// mentioned mend, and the difference surfaces later as a scanner configured with nothing.
	doc, _ := Set(nil, "controllers.sca.mend.policy", "strict")
	out, err := Unset(doc, "controllers.sca.mend.policy")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "mend") {
		t.Errorf("empty mapping left behind:\n%s", out)
	}
	if strings.Contains(string(out), "controllers") {
		t.Errorf("pruning did not reach the top:\n%s", out)
	}
}

func TestUnsetLeavesSiblings(t *testing.T) {
	doc, _ := Set(nil, "tools.trivy.version", "1")
	doc, _ = Set(doc, "tools.gitleaks.version", "2")
	out, _ := Unset(doc, "tools.trivy.version")
	if strings.Contains(string(out), "trivy") {
		t.Errorf("trivy survived:\n%s", out)
	}
	if !strings.Contains(string(out), "gitleaks") {
		t.Errorf("gitleaks removed too:\n%s", out)
	}
}

func TestEditRejectsBadKeys(t *testing.T) {
	for _, k := range []string{"", "   ", "tools..version", ".tools"} {
		if _, err := Set(nil, k, "x"); err == nil {
			t.Errorf("key %q accepted", k)
		}
	}
}

func TestSetRefusesBrokenYAML(t *testing.T) {
	// Editing a file we cannot parse would rewrite it from an empty tree, silently discarding
	// whatever the user had. Refusing sends them to `config validate`, which says what is wrong.
	if _, err := Set([]byte("tools:\n\ttrivy: bad tab\n"), "tools.trivy.version", "1"); err == nil {
		t.Error("a broken document was edited rather than refused")
	}
}

func TestSetProducesAParseableConfig(t *testing.T) {
	// The guarantee that makes `set` a recovery tool: what it writes always loads.
	doc, _ := Set(nil, "tools.trivy.version", "0.69.3")
	doc, _ = Set(doc, "controllers.sca.mend.apiUrl", "https://mend.corp")
	f, err := Parse(doc, "generated")
	if err != nil {
		t.Fatalf("what Set wrote does not load: %v\n%s", err, doc)
	}
	if f.Tools["trivy"].Version != "0.69.3" {
		t.Errorf("parsed back wrong: %+v", f)
	}
}
