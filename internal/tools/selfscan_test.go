package tools

import (
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

	cases := []struct{ name, got, want string }{
		{"trivy version", field("TRIVY_VERSION"), trivy.Version},
		{"gitleaks version", field("GITLEAKS_VERSION"), gitleaks.Version},
		{"gitleaks sha256", field("GITLEAKS_SHA256"), gitleaks.Assets["linux/amd64"].SHA256},
		{"semgrep version", field("SEMGREP_VERSION"), SemgrepVersion()},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s drift: selfscan.yml has %q, manifest has %q — keep them in sync",
				c.name, c.got, c.want)
		}
	}
}
