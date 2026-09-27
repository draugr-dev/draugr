package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

// The resolved output claims to be a valid descriptor with provenance in comments, which is what
// lets it be committed, diffed and scanned across an air gap. Each half of that claim is checked.
func TestValidateResolvedMergesFragmentsIntoAValidDescriptor(t *testing.T) {
	dir := t.TempDir()
	root := writeSagaAt(t, dir, "draugr.saga.yaml", validSaga+`fragments:
  - path: "**/draugr.saga-fragment.yaml"
`)
	writeSagaAt(t, filepath.Join(dir, "svc"), "draugr.saga-fragment.yaml", `components:
  - name: api
    images:
      - image: alpine:3.20
`)

	cmd := newValidateCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--resolved", root})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("validate --resolved: %v", err)
	}
	got := out.String()

	for _, want := range []string{
		"# root:     " + root,
		"# fragment: " + filepath.Join(dir, "svc", "draugr.saga-fragment.yaml"),
		"name: web",
		"name: api",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("resolved output lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "no fragments") {
		t.Errorf("a descriptor with a fragment was described as standing alone:\n%s", got)
	}
	// The references are spent. Left in, a scan of the output would merge the fragment twice.
	if strings.Contains(got, "\nfragments:") {
		t.Errorf("the resolved output still names its fragments:\n%s", got)
	}

	flat := writeSagaAt(t, t.TempDir(), "resolved.saga.yaml", got)
	var check bytes.Buffer
	if err := runValidate([]string{flat}, &check); err != nil {
		t.Errorf("the resolved output is not a valid descriptor: %v\n%s", err, check.String())
	}
}

func TestValidateResolvedSaysWhenNothingWasMerged(t *testing.T) {
	var out bytes.Buffer
	if err := runResolved([]string{writeSaga(t, validSaga)}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "(no fragments, this descriptor stands alone)") {
		t.Errorf("a standalone descriptor should say so:\n%s", out.String())
	}
}

// The output is one descriptor, and several concatenated would not be one.
func TestValidateResolvedTakesExactlyOneDescriptor(t *testing.T) {
	dir := t.TempDir()
	writeSagaAt(t, dir, "a.saga.yaml", validSaga)
	writeSagaAt(t, dir, "b.saga.yaml", validSaga)
	err := runResolved([]string{filepath.Join(dir, "*.saga.yaml")}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "2 matched") {
		t.Errorf("two descriptors = %v, want an error naming the count", err)
	}

	t.Chdir(t.TempDir())
	if err := runResolved(nil, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "no Saga files found") {
		t.Errorf("no descriptor = %v, want an error saying none was found", err)
	}
}

// A descriptor that does not resolve prints nothing, rather than half a document.
func TestValidateResolvedRefusesAnInvalidDescriptor(t *testing.T) {
	var out bytes.Buffer
	if err := runResolved([]string{writeSaga(t, invalidSaga)}, &out); err == nil {
		t.Error("an invalid descriptor should be an error")
	}
	if out.Len() != 0 {
		t.Errorf("an invalid descriptor printed %q", out.String())
	}
}

// One mark per note, whatever it spans: a continuation line wearing its own mark reads as a second
// remark about something else.
func TestWriteExplanationsMarksEachNoteOnce(t *testing.T) {
	var out bytes.Buffer
	writeExplanations(&out, []string{"iac: component \"web\" evaluates\ntrivyConfig.namespaces: [a, b]", "one line"})
	want := "  · iac: component \"web\" evaluates\n    trivyConfig.namespaces: [a, b]\n  · one line\n"
	if out.String() != want {
		t.Errorf("got\n%q\nwant\n%q", out.String(), want)
	}
}
