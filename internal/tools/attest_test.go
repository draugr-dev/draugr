package tools

import (
	"encoding/json"
	"os"
	"path/filepath"
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
	// In the right directory but never recorded — dropped there by something else.
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
	// A tool that will not report its version is still attested — Draugr knows what it installed
	// even when the binary declines to say.
	binDir := filepath.Join(t.TempDir(), "bin")
	path := installed(t, binDir, "gitleaks", "8.30.1", []byte("x"))

	a := Attest("gitleaks", path, "", binDir)
	if !a.Level.Vouched() || a.Version != "8.30.1" {
		t.Errorf("got %+v", a)
	}
}
