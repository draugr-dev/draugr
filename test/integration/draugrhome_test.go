//go:build integration

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestAReadOnlyHomeScansWithDraugrHome runs a scan the way a container with a read-only home runs
// one: HOME cannot be written and DRAUGR_HOME names a directory that can. Semgrep writes its
// settings and log, and Trivy its database and checks, as they run, and with DRAUGR_HOME set both
// go under it, so every control runs and the home directory is left as it was.
func TestAReadOnlyHomeScansWithDraugrHome(t *testing.T) {
	for _, tool := range []string{"git", "gitleaks", "semgrep", "trivy"} {
		requireTool(t, tool, "the scan runs the repository scanners with a read-only home")
	}
	if os.Geteuid() == 0 {
		t.Skip("root writes through permission bits, so the home would not be read-only")
	}
	repo := newVulnRepo(t)
	home, draugrHome := t.TempDir(), t.TempDir()
	if err := os.Chmod(home, 0o555); err != nil { // #nosec G302 -- the test's own temp dir, made read-only on purpose
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(home, 0o755) }) // #nosec G302 -- writable again so the test can remove it

	out := t.TempDir()
	// #nosec G204 -- the binary under test, against a repository and directories in t.TempDir().
	cmd := exec.Command(draugrBin(t), "scan", repo, "--output", out, "--no-gate", "--log-level", "warn")
	cmd.Env = append(readOnlyHomeEnv(home), "DRAUGR_HOME="+draugrHome)
	combined, err := cmd.CombinedOutput()
	t.Logf("draugr scan exit=%v\n%s", err, combined)
	if err != nil {
		t.Fatalf("the scan did not complete with a read-only home and DRAUGR_HOME set: %v", err)
	}
	requireControlRan(t, out, "sast", "semgrep")
	requireControlRan(t, out, "sca", "trivy-fs")
	requireControlRan(t, out, "secrets", "gitleaks")

	for _, dir := range []string{"trivy", "semgrep"} {
		if _, err := os.Stat(filepath.Join(draugrHome, "data", dir)); err != nil {
			t.Errorf("nothing of %s's under DRAUGR_HOME/data: %v", dir, err)
		}
	}
	if entries, err := os.ReadDir(home); err != nil || len(entries) > 0 {
		t.Errorf("the home directory changed: %v %v", entries, err)
	}
}

// readOnlyHomeEnv is this process's environment with HOME at home and every variable that moves
// what a scanner writes unset, so the scan writes where DRAUGR_HOME and the tools' defaults say.
func readOnlyHomeEnv(home string) []string {
	moved := map[string]bool{
		"HOME": true, "DRAUGR_HOME": true, "XDG_CACHE_HOME": true, "XDG_CONFIG_HOME": true, "XDG_DATA_HOME": true,
		"TRIVY_CACHE_DIR": true, "GRYPE_DB_CACHE_DIR": true, "SYFT_CACHE_DIR": true, "TUF_ROOT": true,
		"SEMGREP_SETTINGS_FILE": true, "SEMGREP_LOG_FILE": true,
		"NUCLEI_CONFIG_DIR": true, "NUCLEI_TEMPLATES_DIR": true,
	}
	env := []string{"HOME=" + home}
	for _, kv := range os.Environ() {
		if name, _, _ := strings.Cut(kv, "="); !moved[name] {
			env = append(env, kv)
		}
	}
	return env
}
