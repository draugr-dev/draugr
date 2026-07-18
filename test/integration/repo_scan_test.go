//go:build integration

package integration

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// TestZeroConfigRepoScanWithRealScanners exercises the path unit tests can only stub: a real
// `draugr scan <dir>` (zero-config, no Saga) over a git checkout, running the actual
// repository scanners. It proves, against real tool output, the things that only manifest end
// to end:
//   - checkout → scanner exec → SARIF normalization for the repo-based controls;
//   - findings carry **repo-relative** paths, not the temp-checkout prefix (#188);
//   - each rule is tagged with its originating **scanner** (#190);
//   - the human report shows **priorities + severity bands**.
//
// Gitleaks (offline, regex-based) is the reliable producer and is required; Trivy/Semgrep
// enrich the scan when present. Exact CVEs/counts are never asserted (they drift with tool and
// DB versions) — only the invariants above.
func TestZeroConfigRepoScanWithRealScanners(t *testing.T) {
	if _, err := exec.LookPath("gitleaks"); err != nil {
		t.Skip("gitleaks not on PATH; this integration test needs a real repo scanner")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}

	repo := newVulnRepo(t)

	out := t.TempDir()
	cmd := exec.Command(draugrBin(t), "scan", repo, "--output", out, "--log-level", "warn")
	combined, err := cmd.CombinedOutput()
	// Non-zero exit is expected (a leaked key trips the gate); artifacts are written first.
	t.Logf("draugr scan %s exit=%v\n%s", repo, err, combined)

	// --- console: priorities + severity bands (not raw SARIF levels) ---
	console := string(combined)
	if !strings.Contains(console, "Priorities:") {
		t.Errorf("console output missing the Priorities line:\n%s", console)
	}
	if !containsAny(console, "critical", "high", "medium", "low") {
		t.Errorf("console output missing any severity band:\n%s", console)
	}

	// --- SARIF invariants ---
	data, err := os.ReadFile(filepath.Join(out, "results.sarif")) //nolint:gosec // test temp path
	if err != nil {
		t.Fatal(err)
	}
	report, err := sarif.FromSARIF(data)
	if err != nil {
		t.Fatalf("results.sarif is not valid SARIF: %v", err)
	}
	if report.Tool != "Draugr" {
		t.Errorf("SARIF tool = %q, want the single Draugr driver", report.Tool)
	}
	if len(report.Results) == 0 {
		t.Fatal("expected real scanner findings, got 0 results")
	}
	// Paths must be repo-relative — never the absolute temp-checkout prefix (#188).
	for _, r := range report.Results {
		uri := r.Location.URI
		if uri == "" {
			continue
		}
		if strings.HasPrefix(uri, "/") || strings.Contains(uri, "draugr-repo-") {
			t.Errorf("finding path is not repo-relative: %q", uri)
		}
	}
	// At least one rule is tagged with its originating scanner (#190).
	if tags := scannerTags(t, data); len(tags) == 0 {
		t.Error("expected at least one rule tagged scanner:<name>")
	} else {
		t.Logf("scanner tags observed: %v", tags)
	}
}

// newVulnRepo writes a tiny intentionally-vulnerable project into a fresh git repo and returns
// its path. A leaked private key guarantees a Gitleaks finding; the manifest/code/Dockerfile
// give Trivy and Semgrep something to find when they're installed.
func newVulnRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("requirements.txt", "Flask==0.12.2\nrequests==2.19.1\n")
	write("app.py", "import os\n\n\ndef run(cmd):\n    return os.popen('ping ' + cmd).read()\n")
	write("Dockerfile", "FROM python:3.8\nCOPY . /app\n")
	write("id_rsa", "-----BEGIN RSA PRIVATE KEY-----\n"+
		"MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Q\n"+
		"uKUpWnIg9pQ0j0J7bqDKT7f7fEXAMPLEfakekeymaterialnotrealABCDEF0000\n"+
		"-----END RSA PRIVATE KEY-----\n")

	for _, args := range [][]string{
		{"init", "--quiet"},
		{"config", "user.email", "test@draugr.dev"},
		{"config", "user.name", "test"},
		{"add", "."},
		{"commit", "--quiet", "-m", "fixture"},
	} {
		c := exec.Command("git", args...)
		c.Dir = dir
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	return dir
}

// scannerTags collects the distinct scanner:<name> tags across the SARIF rules.
func scannerTags(t *testing.T, data []byte) []string {
	t.Helper()
	var log struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						Properties struct {
							Tags []string `json:"tags"`
						} `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("parse SARIF for tags: %v", err)
	}
	seen := map[string]bool{}
	var out []string
	for _, run := range log.Runs {
		for _, rule := range run.Tool.Driver.Rules {
			for _, tag := range rule.Properties.Tags {
				if strings.HasPrefix(tag, "scanner:") && !seen[tag] {
					seen[tag] = true
					out = append(out, tag)
				}
			}
		}
	}
	return out
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
