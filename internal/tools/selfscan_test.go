package tools

import (
	"bytes"
	"os"
	"regexp"
	"testing"
)

// TestSelfscanPinsMatchManifest enforces the single source of truth: the tool versions the
// self-scan CI validates against MUST equal the versions `draugr tools install` ships. If they
// drift (someone bumps one but not the other), this fails — so "what we test" always equals
// "what we install".
func TestSelfscanPinsMatchManifest(t *testing.T) {
	const workflow = "../../.github/workflows/selfscan.yml"
	data, err := os.ReadFile(workflow)
	if err != nil {
		t.Fatalf("read %s: %v", workflow, err)
	}
	yaml := string(data)

	field := func(key string) string {
		m := regexp.MustCompile(key + `:\s*"([^"]+)"`).FindStringSubmatch(yaml)
		if m == nil {
			t.Fatalf("%s not found in %s", key, workflow)
		}
		return m[1]
	}

	trivy, _ := Spec("trivy")
	gitleaks, _ := Spec("gitleaks")
	gosec, _ := Spec("gosec")

	cases := []struct{ name, got, want string }{
		{"trivy version", field("TRIVY_VERSION"), trivy.Version},
		{"gitleaks version", field("GITLEAKS_VERSION"), gitleaks.Version},
		{"gitleaks sha256", field("GITLEAKS_SHA256"), gitleaks.Assets["linux/amd64"].SHA256},
		{"semgrep version", field("SEMGREP_VERSION"), SemgrepVersion()},
		{"gosec version", field("GOSEC_VERSION"), gosec.Version},
		{"gosec sha256", field("GOSEC_SHA256"), gosec.Assets["linux/amd64"].SHA256},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s drift: selfscan.yml has %q, manifest has %q — keep them in sync",
				c.name, c.got, c.want)
		}
	}
}

// TestSelfscanInstallsEveryScannerItsDescriptorEnables catches the gap the version pins above
// cannot: a scanner enabled in the descriptor that the runner never installs.
//
// Nothing about it looks wrong. The descriptor is valid, the scanner is registered, the pins
// agree, and every unit test passes. The scan then reports the control as an error — which is
// the design working, a missing scanner is not a pass — and the default branch goes red for a
// reason that is about the runner rather than about the code.
//
// Deliberately a shallow check: it asks whether the workflow mentions the tool at all, not how it
// installs it. A test that understood installation would have to be rewritten every time one
// changed, and the thing worth catching is the omission.
func TestSelfscanInstallsEveryScannerItsDescriptorEnables(t *testing.T) {
	workflow, err := os.ReadFile("../../.github/workflows/selfscan.yml")
	if err != nil {
		t.Fatalf("read workflow: %v", err)
	}
	descriptor, err := os.ReadFile("../../.draugr/self.saga.yaml")
	if err != nil {
		t.Fatalf("read descriptor: %v", err)
	}

	// Every tool Draugr can install, so the check follows the manifest rather than a list here
	// that would go stale the moment a scanner was added.
	for _, name := range Installable() {
		spec, ok := Spec(name)
		if !ok {
			continue
		}
		// Named in the descriptor's scanner blocks (camelCase keys, so match the binary loosely).
		if !bytes.Contains(descriptor, []byte(name)) {
			continue
		}
		if !bytes.Contains(workflow, []byte(spec.Binary)) {
			t.Errorf("%s is enabled in .draugr/self.saga.yaml but selfscan.yml never mentions "+
				"%q — the scan will report the control as an error, and main goes red for a "+
				"reason that is not about the code", name, spec.Binary)
		}
	}
}
