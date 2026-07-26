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
	data, err := os.ReadFile(out) //nolint:gosec // test reads a file under t.TempDir()
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
