package config

import (
	"errors"
	"reflect"
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
	out, err := Set(nil, "controls.sca.mend.policy", "corp-default")
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := Get(out, "controls.sca.mend.policy"); !ok || v != "corp-default" {
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
		{"controls.sast.gosec.enabled", "true", true},
		{"controls.sca.trivyFs.timeout", "30", 30},
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
	doc := mustSet(t, nil, "controls.sca.mend.policy", "strict")
	out, err := Unset(doc, "controls.sca.mend.policy")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "mend") {
		t.Errorf("empty mapping left behind:\n%s", out)
	}
	if strings.Contains(string(out), "controls") {
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
	doc = mustSet(t, doc, "controls.sca.mend.apiUrl", "https://mend.corp")
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

func TestUnsetRefusesAnAbsentKey(t *testing.T) {
	// No document comes back, so a caller has nothing to write: an empty file created by removing
	// a key from nowhere would then make `config init` refuse to write the starter.
	for name, doc := range map[string][]byte{
		"no file":      nil,
		"other keys":   mustSet(t, nil, "tools.trivy.version", "1"),
		"parent only":  mustSet(t, nil, "output.top", "5"),
		"scalar above": []byte("output: compact\n"),
	} {
		out, err := Unset(doc, "output.view")
		var notSet *NotSetError
		if !errors.As(err, &notSet) || notSet.Key != "output.view" {
			t.Errorf("%s: err = %v, want a *NotSetError for output.view", name, err)
		}
		if out != nil {
			t.Errorf("%s: a document came back for an absent key:\n%s", name, out)
		}
	}
	if got := (&NotSetError{Key: "output.view"}).Error(); got != `"output.view" is not set` {
		t.Errorf("Error() = %q", got)
	}
}

func TestUnsetReportsAFileItCannotParse(t *testing.T) {
	if _, err := Unset([]byte("tools:\n\ttrivy: bad tab\n"), "tools.trivy"); err == nil {
		t.Error("a broken document was edited rather than refused")
	}
	if _, err := Unset(nil, "tools..version"); err == nil {
		t.Error("a key with an empty segment was accepted")
	}
}

func TestUnsetFindsEitherSpellingOfControls(t *testing.T) {
	// Both spellings load as one section, so a key read from `config show` as controls.… removes
	// the setting a file still writes under controllers, and the other way round.
	for _, tc := range []struct{ written, removed string }{
		{"controllers.sast.semgrep.config", "controls.sast.semgrep.config"},
		{"controls.sast.semgrep.config", "controllers.sast.semgrep.config"},
	} {
		doc := mustSet(t, nil, tc.written, "p/ci")
		out, err := Unset(doc, tc.removed)
		if err != nil {
			t.Fatalf("Unset(%s) of a file holding %s: %v", tc.removed, tc.written, err)
		}
		if strings.Contains(string(out), "semgrep") {
			t.Errorf("Unset(%s) left %s behind:\n%s", tc.removed, tc.written, out)
		}
	}
	if _, err := Unset(mustSet(t, nil, "tools.trivy.version", "1"), "controls.sast"); err == nil {
		t.Error("a control set under neither spelling was reported removed")
	}
}

func TestUnsetKeepsACommentedSection(t *testing.T) {
	// The starter explains each section in a comment above it. Removing the last key under one
	// keeps the section as {}, which configures nothing, rather than deleting the explanation.
	doc := []byte("# Control defaults.\ncontrols:\n  sast:\n    semgrep:\n      config: p/ci\ntools:\n  trivy:\n    version: \"1\"\n")
	out, err := Unset(doc, "controls.sast.semgrep.config")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "# Control defaults.\ncontrols: {}\n") {
		t.Errorf("the commented section was not kept as {}:\n%s", out)
	}
	if strings.Contains(string(out), "sast") {
		t.Errorf("an emptied control was left behind, which would enable it:\n%s", out)
	}
	// An uncommented section is pruned as before.
	out, err = Unset(out, "tools.trivy.version")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "tools") {
		t.Errorf("an emptied, uncommented section was kept:\n%s", out)
	}
	// Removing the commented section itself removes it.
	if out, err = Unset(doc, "controls"); err != nil || strings.Contains(string(out), "controls") {
		t.Errorf("Unset(controls) = %v:\n%s", err, out)
	}
	// An absent key under a commented section is still absent.
	if _, err := Unset(doc, "controls.sca"); err == nil {
		t.Error("an absent key under a commented section was reported removed")
	}
}

func TestSetOpensAnEmptyFlowMapping(t *testing.T) {
	// `controls: {}` is how a starter says "nothing here yet". The first key written into it goes
	// on its own line, not as {sast: {semgrep: …}} beside the comments around it.
	for name, doc := range map[string]string{
		"section": "# Defaults.\ncontrols: {}\n",
		"root":    "{}\n",
	} {
		out := string(mustSet(t, []byte(doc), "controls.sast.semgrep.config", "p/owasp-top-ten"))
		if strings.Contains(out, "{") {
			t.Errorf("%s: flow style survived:\n%s", name, out)
		}
		if !strings.Contains(out, "controls:\n  sast:\n    semgrep:\n      config: p/owasp-top-ten\n") {
			t.Errorf("%s: not written as a block:\n%s", name, out)
		}
	}
	// A flow mapping that already holds keys keeps the style somebody chose for it.
	out := string(mustSet(t, []byte("tools:\n  trivy: {version: \"1\"}\n"), "tools.trivy.version", "0.70.0"))
	if !strings.Contains(out, "trivy: {version: 0.70.0}") {
		t.Errorf("a populated flow mapping was rewritten:\n%s", out)
	}
}

func TestSetWritesFlowValues(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  any
	}{
		{"[library]", []any{"library"}},
		{"[library, os]", []any{"library", "os"}},
		{"[]", []any{}},
		{"{config: p/ci, timeout: 30}", map[string]any{"config": "p/ci", "timeout": 30}},
		// Only the first character decides, so a URL, a value holding ": " and one with a bracket
		// further in stay one string.
		{"https://draugr.acme.example:8443/x", "https://draugr.acme.example:8443/x"},
		{"a: b", "a: b"},
		{"p/[x]", "p/[x]"},
	} {
		out := mustSet(t, nil, "controls.sca.trivyFs.pkgTypes", tc.value)
		if got := loaded(t, out, "controls.sca.trivyFs.pkgTypes"); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%q loads back as %#v, want %#v:\n%s", tc.value, got, tc.want, out)
		}
	}
	if out := string(mustSet(t, nil, "controls.sca.trivyFs.pkgTypes", "[library, os]")); !strings.Contains(out, "pkgTypes: [library, os]\n") {
		t.Errorf("a list is not written as typed:\n%s", out)
	}
}

func TestSetReplacesAScalarWithAListKeepingItsComment(t *testing.T) {
	doc := []byte("controls:\n  sca:\n    trivyFs:\n      pkgTypes: library # what we ship\n")
	out := string(mustSet(t, doc, "controls.sca.trivyFs.pkgTypes", "[library, os]"))
	if !strings.Contains(out, "pkgTypes: [library, os] # what we ship") {
		t.Errorf("value or comment lost:\n%s", out)
	}
	out = string(mustSet(t, []byte(out), "controls.sca.trivyFs.pkgTypes", "library"))
	if !strings.Contains(out, "pkgTypes: library # what we ship") {
		t.Errorf("a list was not replaced by a scalar:\n%s", out)
	}
}

func TestSetRefusesAMalformedFlowValue(t *testing.T) {
	for value, want := range map[string]string{
		"[library":     `"[library" starts with "[", so it is read as a YAML list and is not one; write a list as [a, b]`,
		"[a] trailing": `"[a] trailing" starts with "[", so it is read as a YAML list and is not one; write a list as [a, b]`,
		"{config":      `"{config" starts with "{", so it is read as a YAML mapping and is not one; write a mapping as {key: value}`,
		"{a: 1} [b]":   `"{a: 1} [b]" starts with "{", so it is read as a YAML mapping and is not one; write a mapping as {key: value}`,
	} {
		_, err := Set(nil, "controls.sca.trivyFs.pkgTypes", value)
		if err == nil || err.Error() != want {
			t.Errorf("Set(%q) = %v, want %q", value, err, want)
		}
	}
}
