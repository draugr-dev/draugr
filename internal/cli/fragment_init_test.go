package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
)

func TestInitFragmentWritesAValidFragmentNamedAfterItsDirectory(t *testing.T) {
	dir := t.TempDir()
	comp := filepath.Join(dir, "services", "payments")
	if err := os.MkdirAll(comp, 0o750); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	opts := initOptions{fragment: true, output: filepath.Join(comp, "draugr.saga-fragment.yaml")}
	if err := runInit(comp, opts, &out); err != nil {
		t.Fatalf("runInit: %v", err)
	}
	data, err := os.ReadFile(opts.output) //nolint:gosec // test-controlled path
	if err != nil {
		t.Fatal(err)
	}
	frag, err := saga.LoadFragment(data, opts.output)
	if err != nil {
		t.Fatalf("the scaffolded fragment does not validate: %v", err)
	}
	// The name is the one field that has to match across a component's fragments for them to
	// merge, which is the whole reason it is inferred rather than left as a placeholder.
	if len(frag.Components) != 1 || frag.Components[0].Name != "payments" {
		t.Errorf("components = %+v, want one named for the directory", frag.Components)
	}
	if !strings.Contains(string(data), saga.FragmentSchemaURL) {
		t.Error("the modeline should point at the fragment schema, not the Saga's")
	}
	// A fragment cannot be scanned, so the next step must not say to scan it.
	if strings.Contains(out.String(), "draugr scan") {
		t.Errorf("next steps should not point at scan for a fragment:\n%s", out.String())
	}
}

func TestIsFragmentFile(t *testing.T) {
	for _, name := range []string{"draugr.saga-fragment.yaml", "azure.saga-fragment.yml"} {
		if !IsFragmentFile(name) {
			t.Errorf("%q should be a fragment", name)
		}
	}
	// The suffix has to be distinguishable from a Saga's, or editors apply the wrong schema.
	for _, name := range []string{"draugr.saga.yaml", ".saga.yaml", "notes.yaml"} {
		if IsFragmentFile(name) {
			t.Errorf("%q should not be a fragment", name)
		}
	}
}
