package tools

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// installed writes a fake binary into binDir and records it, as an install would.
func installed(t *testing.T, binDir, tool, version string, body []byte) string {
	t.Helper()
	if err := os.MkdirAll(binDir, 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(binDir, tool)
	if err := os.WriteFile(path, body, 0o700); err != nil { //nolint:gosec // a fake binary in a temp dir
		t.Fatal(err)
	}
	sum, err := fileSHA256(path)
	if err != nil {
		t.Fatal(err)
	}
	m := loadManifest(binDir)
	m[tool] = installRecord{Version: version, BinarySHA256: sum}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath(binDir), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAttestVouchesForWhatDraugrInstalled(t *testing.T) {
	binDir := filepath.Join(t.TempDir(), "bin")
	path := installed(t, binDir, "trivy", "0.69.3", []byte("#!/bin/sh\n"))

	a := Attest("trivy", path, "0.69.3", binDir)
	if !a.Level.Vouched() {
		t.Fatalf("a binary Draugr installed was not attested: %+v", a)
	}
	if a.Reason != "" {
		t.Errorf("attested but gave a reason: %q", a.Reason)
	}
}

func TestAttestDeclinesWhatItDidNotInstall(t *testing.T) {
	binDir := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
		t.Fatal(err)
	}

	cases := map[string]Attestation{
		// Somewhere else on PATH: the operator brought it, which is allowed and unattested.
		"elsewhere on PATH": Attest("trivy", "/usr/local/bin/trivy", "0.69.3", binDir),
		// Not found at all.
		"absent": Attest("trivy", "", "", binDir),
	}
	for name, a := range cases {
		if a.Level.Vouched() {
			t.Errorf("%s: attested when it should not be", name)
		}
		if a.Reason == "" {
			t.Errorf("%s: declined without saying why", name)
		}
	}
}

func TestAttestNoticesAChangedBinary(t *testing.T) {
	// The hash check is what makes "attested" a claim about a file rather than about a path.
	binDir := filepath.Join(t.TempDir(), "bin")
	path := installed(t, binDir, "trivy", "0.69.3", []byte("original"))
	if err := os.WriteFile(path, []byte("something else"), 0o700); err != nil { //nolint:gosec // temp dir
		t.Fatal(err)
	}

	a := Attest("trivy", path, "0.69.3", binDir)
	if a.Level.Vouched() {
		t.Error("a replaced binary was still attested")
	}
	if a.Reason != "changed since Draugr installed it" {
		t.Errorf("reason = %q", a.Reason)
	}
}

func TestAttestNoticesAnUnrecordedBinary(t *testing.T) {
	// In the right directory but never recorded, dropped there by something else.
	binDir := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(binDir, "trivy")
	if err := os.WriteFile(path, []byte("x"), 0o700); err != nil { //nolint:gosec // temp dir
		t.Fatal(err)
	}

	a := Attest("trivy", path, "", binDir)
	if a.Level.Vouched() {
		t.Error("an unrecorded binary was attested")
	}
}

func TestAttestFallsBackToTheRecordedVersion(t *testing.T) {
	// A tool that will not report its version is still attested. Draugr knows what it installed even
	// when the binary declines to say.
	binDir := filepath.Join(t.TempDir(), "bin")
	path := installed(t, binDir, "gitleaks", "8.30.1", []byte("x"))

	a := Attest("gitleaks", path, "", binDir)
	if !a.Level.Vouched() || a.Version != "8.30.1" {
		t.Errorf("got %+v", a)
	}
}

// Everything external reads the same, and the distinction the report needs is carried elsewhere.
//
// Whether Draugr could have installed a tool is real and it changes what somebody does, which is
// why it decides whether a scan offers the command. It does not change where the binary came from,
// and this fills a column of exactly that, so two wordings there were two ways of saying one fact.
// `TestTheUnverifiedToolTipNamesWhatToInstall` holds the half that acts on the distinction.
func TestEverythingExternalSaysWhereItCameFrom(t *testing.T) {
	t.Parallel()
	for _, tool := range []string{
		"trivy",   // Draugr distributes it, as a release archive.
		"semgrep", // And this one, as a Python package.
		"mend",    // And not this one.
	} {
		t.Run(tool, func(t *testing.T) {
			t.Parallel()
			got := DescribeFor(LevelExternal, tool)
			if got != "not installed by Draugr" {
				t.Errorf("DescribeFor(external, %s) = %q", tool, got)
			}
			// A command in a value is a command in the wrong column, whichever tool it names.
			if strings.Contains(got, "draugr ") {
				t.Errorf("DescribeFor(external, %s) = %q, which is an instruction", tool, got)
			}
		})
	}
	// An installed tool is still described by how it was checked, which is the fact for that one.
	if got := DescribeFor(LevelPinned, "trivy"); !strings.Contains(got, "installed by Draugr") {
		t.Errorf("DescribeFor(pinned, trivy) = %q", got)
	}
}

// TestAttestFoundResolvesFromPath covers the entry point the CLI actually calls.
//
// Attest itself is tested against explicit paths; this is the thin layer that finds them, and its
// two swallowed errors are decisions rather than accidents: an unresolvable home directory or a
// tool that is not on PATH must produce an honest attestation, not a failure. A tool Draugr did
// not install is `external`, which is the truthful answer and the one `tools list` shows.
func TestAttestFoundResolvesFromPath(t *testing.T) {
	dir := t.TempDir()
	tool := filepath.Join(dir, "pretend-scanner")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil { // #nosec G306 -- must execute
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	got := AttestFound("pretend-scanner", "1.2.3")
	if got.Path != tool {
		t.Errorf("path = %q, want the copy found on PATH %q", got.Path, tool)
	}
	if got.Level != LevelExternal {
		t.Errorf("level = %q, want %q for a tool Draugr did not install", got.Level, LevelExternal)
	}
	if got.Version != "1.2.3" {
		t.Errorf("version = %q, want the one supplied", got.Version)
	}

	missing := AttestFound("definitely-not-a-real-tool", "")
	if missing.Path != "" {
		t.Errorf("a missing tool should have no path, got %q", missing.Path)
	}
	if missing.Reason != "not found" {
		t.Errorf("reason = %q, want %q", missing.Reason, "not found")
	}
}
