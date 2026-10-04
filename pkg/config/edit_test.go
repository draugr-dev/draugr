package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestSetPreservesComments(t *testing.T) {
	// The whole reason this edits a node tree. A `config set` that deleted the explanation
	// somebody wrote beside a pin teaches people not to use it, and they go back to hand-editing
	// the file the command exists to keep valid.
	doc := `# Our pinned toolchain. Do not bump without the platform team.
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
	for _, want := range []string{"Do not bump without the platform team", "air-gapped mirror"} {
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
	// A version stays a string where it reads as a number, because "1.10" written bare loads back as
	// the float 1.1. A config that quietly turned `enabled: true` into the string "true" would be a
	// different setting wearing the same name.
	for _, tc := range []struct {
		key, value string
		want       any
	}{
		{"tools.trivy.version", "0.69.3", "0.69.3"},
		{"tools.trivy.version", "1.10", "1.10"},
		{"controllers.sast.gosec.enabled", "true", true},
		{"controllers.sca.trivyFs.timeout", "30", 30},
	} {
		out := mustSet(t, nil, tc.key, tc.value)
		if got := loaded(t, out, tc.key); got != tc.want {
			t.Errorf("%s=%s loads back as %#v, want %#v:\n%s", tc.key, tc.value, got, tc.want, out)
		}
	}
}

func TestUnsetPrunesEmptyMappings(t *testing.T) {
	// A `mend` block left behind with nothing in it is not the same file as one that never
	// mentioned mend, and the difference surfaces later as a scanner configured with nothing.
	doc := mustSet(t, nil, "controllers.sca.mend.policy", "strict")
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
	doc := mustSet(t, nil, "tools.trivy.version", "1")
	doc = mustSet(t, doc, "tools.gitleaks.version", "2")
	out, err := Unset(doc, "tools.trivy.version")
	if err != nil {
		t.Fatal(err)
	}
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
	doc := mustSet(t, nil, "tools.trivy.version", "0.69.3")
	doc = mustSet(t, doc, "controllers.sca.mend.apiUrl", "https://mend.corp")
	f, err := Parse(doc, "generated")
	if err != nil {
		t.Fatalf("what Set wrote does not load: %v\n%s", err, doc)
	}
	if f.Tools["trivy"].Version != "0.69.3" {
		t.Errorf("parsed back wrong: %+v", f)
	}
}

// mustSet is Set for a test whose subject is what comes after it. A Set that failed would hand
// back nothing, and an assertion that a key is absent passes against nothing.
func mustSet(t *testing.T, doc []byte, key, value string) []byte {
	t.Helper()
	out, err := Set(doc, key, value)
	if err != nil {
		t.Fatalf("Set(%q, %q): %v", key, value, err)
	}
	return out
}

// loaded is the value at a dotted key once the document is loaded as plain YAML, typed the way
// any YAML reader would type it.
func loaded(t *testing.T, doc []byte, key string) any {
	t.Helper()
	var v any
	if err := yaml.Unmarshal(doc, &v); err != nil {
		t.Fatalf("what Set wrote is not YAML: %v\n%s", err, doc)
	}
	for _, seg := range strings.Split(key, ".") {
		m, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("%s: no mapping at %q:\n%s", key, seg, doc)
		}
		v = m[seg]
	}
	return v
}
