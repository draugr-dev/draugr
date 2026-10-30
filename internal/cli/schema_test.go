package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSchemaCommandPrintsToStdout(t *testing.T) {
	var stdout bytes.Buffer
	cmd := newSchemaCommand()
	cmd.SetOut(&stdout)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("schema output is not JSON: %v", err)
	}
	if doc["title"] != "Draugr Saga" {
		t.Errorf("unexpected schema: %v", doc["title"])
	}
}

func TestSchemaCommandWritesFile(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "s.json")
	var stderr bytes.Buffer
	cmd := newSchemaCommand()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"-o", out})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out) // #nosec G304 -- test reads a file under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(data) {
		t.Error("written schema is not valid JSON")
	}
	// The hint must be pasteable; an absolute path must not gain a "./" prefix.
	if !strings.Contains(stderr.String(), "$schema="+out) {
		t.Errorf("hint should reference the absolute path verbatim: %q", stderr.String())
	}
}

// runSchema runs `draugr schema` with args and returns what it printed to stdout and stderr.
func runSchema(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd := newSchemaCommand()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

func TestSchemaCommandSelectsTheDocument(t *testing.T) {
	for flag, title := range map[string]string{
		"--fragment":    "Draugr Saga fragment",
		"--config-file": "Draugr configuration",
	} {
		out, _, err := runSchema(t, flag)
		if err != nil {
			t.Fatalf("%s: %v", flag, err)
		}
		var doc map[string]any
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("%s: output is not JSON: %v", flag, err)
		}
		if doc["title"] != title {
			t.Errorf("%s printed %v, want %q", flag, doc["title"], title)
		}
	}
	out, _, err := runSchema(t, "--fragment", "--config-file")
	if want := "--fragment and --config-file select different schemas; pass one"; err == nil || err.Error() != want {
		t.Errorf("--fragment with --config-file: err = %v, want %q", err, want)
	}
	if strings.Contains(out, `"$schema"`) {
		t.Errorf("--fragment with --config-file printed a schema anyway:\n%.80s", out)
	}
}

func TestSchemaCommandNamesTheFileItIsFor(t *testing.T) {
	out := filepath.Join(t.TempDir(), "config.schema.json")
	_, stderr, err := runSchema(t, "--config-file", "-o", out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr, "reference it from draugr.config.yaml with:") {
		t.Errorf("the hint does not name the config file: %q", stderr)
	}
	data, err := os.ReadFile(out) // #nosec G304 -- test reads a file under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"title": "Draugr configuration"`) {
		t.Error("-o with --config-file did not write the config schema")
	}
}

func TestSchemaCommandReportsAFileItCannotWrite(t *testing.T) {
	if _, _, err := runSchema(t, "-o", filepath.Join(t.TempDir(), "missing", "s.json")); err == nil {
		t.Error("a path in a directory that does not exist was accepted")
	}
}

func TestSchemaRefPrefixesRelativePaths(t *testing.T) {
	cases := map[string]string{
		"s.json":      "./s.json",
		"./s.json":    "./s.json",
		"../s.json":   "../s.json",
		"/tmp/s.json": "/tmp/s.json",
		"dir/s.json":  "./dir/s.json",
	}
	for in, want := range cases {
		if got := schemaRef(in); got != want {
			t.Errorf("schemaRef(%q) = %q, want %q", in, got, want)
		}
	}
}
