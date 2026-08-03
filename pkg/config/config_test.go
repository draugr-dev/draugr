package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseRejectsUnknownKeys(t *testing.T) {
	// A misspelled setting that is silently dropped is one somebody believes is in force — and
	// this file exists to make behaviour uniform, so a typo that quietly opts one machine out
	// defeats the point of having it.
	_, err := Parse([]byte("toolz:\n  trivy:\n    version: \"1\"\n"), "x.yaml")
	if err == nil {
		t.Fatal("an unknown top-level key was accepted")
	}
	// The error has to name the way out; a config that fails is only safe if fixing it is easy.
	if !strings.Contains(err.Error(), "draugr config") {
		t.Errorf("error offers no recovery: %v", err)
	}
}

func TestParseEmptyIsValid(t *testing.T) {
	// A file that says nothing overrides nothing. Treating it as broken would make `touch` a
	// way to break a machine.
	for _, in := range []string{"", "\n", "# just a comment\n"} {
		if _, err := Parse([]byte(in), "x.yaml"); err != nil {
			t.Errorf("%q: %v", in, err)
		}
	}
}

func TestLoadLayersHomeUnderProject(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".draugr"), 0o750); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(home, ".draugr", "config.yaml"),
		"tools:\n  trivy: { version: \"0.60.0\" }\n  gitleaks: { version: \"8.0.0\" }\n")

	proj := t.TempDir()
	write(t, filepath.Join(proj, FileName), "tools:\n  trivy: { version: \"0.69.3\" }\n")

	got, err := Load("", proj)
	if err != nil {
		t.Fatal(err)
	}
	// The project has an opinion about trivy and none about gitleaks.
	if got.File.Tools["trivy"].Version != "0.69.3" {
		t.Errorf("project did not win: %+v", got.File.Tools)
	}
	if got.File.Tools["gitleaks"].Version != "8.0.0" {
		t.Errorf("home value was lost: %+v", got.File.Tools)
	}
	if len(got.Sources) != 2 {
		t.Errorf("expected both files recorded, got %d", len(got.Sources))
	}
}

func TestLoadExplicitReplacesRatherThanLayers(t *testing.T) {
	// Explicit means explicit: a runner image naming a config expects that config, not that one
	// layered over whatever happens to be in the working directory.
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".draugr"), 0o750); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(home, ".draugr", "config.yaml"), "tools:\n  gitleaks: { version: \"8.0.0\" }\n")

	proj := t.TempDir()
	write(t, filepath.Join(proj, FileName), "tools:\n  trivy: { version: \"0.1.0\" }\n")
	only := filepath.Join(proj, "other.yaml")
	write(t, only, "tools:\n  trivy: { version: \"9.9.9\" }\n")

	got, err := Load(only, proj)
	if err != nil {
		t.Fatal(err)
	}
	if got.File.Tools["trivy"].Version != "9.9.9" {
		t.Errorf("explicit file not used: %+v", got.File.Tools)
	}
	if _, ok := got.File.Tools["gitleaks"]; ok {
		t.Error("explicit config was layered over the discovered ones")
	}
}

func TestLoadEnvVar(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	path := filepath.Join(dir, "from-env.yaml")
	write(t, path, "tools:\n  trivy: { version: \"7.7.7\" }\n")
	t.Setenv(EnvVar, path)

	got, err := Load("", dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.File.Tools["trivy"].Version != "7.7.7" {
		t.Errorf("%s ignored: %+v", EnvVar, got.File.Tools)
	}
}

func TestLoadMissingFilesAreFine(t *testing.T) {
	// A machine with no configuration is the normal case, not an error.
	t.Setenv("HOME", t.TempDir())
	got, err := Load("", t.TempDir())
	if err != nil || len(got.Sources) != 0 {
		t.Errorf("got %+v, %v", got, err)
	}
}

func TestLoadNamedFileMustExist(t *testing.T) {
	// Naming a file that is not there is a mistake worth reporting: the caller believes settings
	// are in force that are not.
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml"), t.TempDir()); err == nil {
		t.Error("a missing explicit config was accepted")
	}
}

func TestDeepMergeOverridesOnlyNamedKeys(t *testing.T) {
	base := map[string]any{"mend": map[string]any{"apiUrl": "https://corp", "policy": "strict"}}
	over := map[string]any{"mend": map[string]any{"policy": "relaxed"}}

	got := DeepMerge(base, over)
	mend, _ := asSettings(got["mend"])
	if mend["policy"] != "relaxed" {
		t.Errorf("override lost: %+v", mend)
	}
	if mend["apiUrl"] != "https://corp" {
		t.Errorf("inherited key lost: %+v", mend)
	}
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
