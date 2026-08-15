package tools

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestEveryNodeToolHasPinsAtItsVersion is the npm form of the Python pins check.
//
// The drift it catches is the obvious one: bump the version constant, forget to regenerate the
// lockfile. Nothing fails at build time — the install resolves a different version from the one
// Draugr reports, and records it as `pinned` while the pins described something else. A wrong
// provenance claim is worse than none.
func TestEveryNodeToolHasPinsAtItsVersion(t *testing.T) {
	t.Parallel()

	for name, spec := range nodeInstallable {
		version, ok := nodeVersions[name]
		if !ok || version == "" {
			t.Errorf("%s is installable as an npm package but has no pinned version", name)
			continue
		}

		manifest, err := nodePins.ReadFile("nodepins/" + spec.Pins + ".package.json")
		if err != nil {
			t.Errorf("%s: no pinned manifest is built into this binary: %v", name, err)
			continue
		}
		var pkg struct {
			Dependencies map[string]string `json:"dependencies"`
		}
		if err := json.Unmarshal(manifest, &pkg); err != nil {
			t.Errorf("%s: the pinned manifest is not JSON: %v", name, err)
			continue
		}
		if got := pkg.Dependencies[spec.Package]; got != version {
			t.Errorf("%s: the manifest asks for %s@%s but the pinned version is %s — regenerate "+
				"the pins for %s", name, spec.Package, got, version, version)
		}

		lock, err := nodePins.ReadFile("nodepins/" + spec.Pins + ".package-lock.json")
		if err != nil {
			t.Errorf("%s: no pinned lockfile is built into this binary: %v", name, err)
			continue
		}
		assertLockfileIsFullyPinned(t, name, lock)
	}
}

// assertLockfileIsFullyPinned checks the property `npm ci` relies on.
//
// Every package must carry an integrity digest. One without is one npm fetches without checking,
// and the install would still be reported as `pinned` — the level is decided by whether `npm ci`
// succeeded, not by how much of the tree it actually verified.
func assertLockfileIsFullyPinned(t *testing.T, name string, lock []byte) {
	t.Helper()

	var doc struct {
		LockfileVersion int                       `json:"lockfileVersion"`
		Packages        map[string]map[string]any `json:"packages"`
	}
	if err := json.Unmarshal(lock, &doc); err != nil {
		t.Errorf("%s: the pinned lockfile is not JSON: %v", name, err)
		return
	}
	// `npm ci` needs a lockfile it understands; version 3 is what modern npm writes.
	if doc.LockfileVersion < 3 {
		t.Errorf("%s: lockfileVersion %d is older than npm ci expects", name, doc.LockfileVersion)
	}
	if len(doc.Packages) < 2 {
		t.Errorf("%s: the lockfile describes %d packages, which is too few to be a resolved tree",
			name, len(doc.Packages))
	}
	for path, entry := range doc.Packages {
		if path == "" {
			continue // the root project, which has no artifact to digest
		}
		integrity, _ := entry["integrity"].(string)
		if !strings.HasPrefix(integrity, "sha512-") && !strings.HasPrefix(integrity, "sha256-") {
			t.Errorf("%s: %s has no integrity digest, so npm would fetch it unchecked while the "+
				"install still reported itself pinned", name, path)
		}
	}
}

// TestNodeToolsAreInstallable stops the npm method from being invisible to everything that asks
// what Draugr can provision — doctor's advice, `tools list`, and the install plan all read these.
func TestNodeToolsAreInstallable(t *testing.T) {
	t.Parallel()

	for name := range nodeInstallable {
		if !Provisionable(name) {
			t.Errorf("%s is obtained from npm but Provisionable says otherwise, so callers will "+
				"tell people to install it themselves", name)
		}
		if !slices.Contains(Installable(), name) {
			t.Errorf("%s is missing from Installable(), so `tools install` will not offer it", name)
		}
	}
}

// TestLinkNodeCommandNamesTheInterpreter pins the difference between a shim that works and one
// that works only where Node happens to be on PATH.
//
// npm's own launcher begins `#!/usr/bin/env node`, which resolves against whatever PATH the scan
// runs with. A pipeline that provisions the tool and then runs with a trimmed PATH would get
// `env: 'node': No such file or directory` — the control reporting an error about the runtime
// rather than about the code.
func TestLinkNodeCommandNamesTheInterpreter(t *testing.T) {
	envDir := t.TempDir()
	binDir := filepath.Join(envDir, "node_modules", ".bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
		t.Fatal(err)
	}
	entry := filepath.Join(binDir, "retire")
	if err := os.WriteFile(entry, []byte("#!/usr/bin/env node\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	shim := filepath.Join(t.TempDir(), "retire")
	if err := linkNodeCommand(envDir, "retire", shim); err != nil {
		t.Skipf("no node on PATH to name: %v", err)
	}
	body, err := os.ReadFile(shim) // #nosec G304 -- a path this test just created
	if err != nil {
		t.Fatal(err)
	}
	script := string(body)
	if !strings.Contains(script, entry) {
		t.Errorf("the shim does not run the installed command: %s", script)
	}
	if !strings.Contains(script, "/node") {
		t.Errorf("the shim does not name an interpreter, so it depends on PATH: %s", script)
	}
	if strings.Contains(script, "env node") {
		t.Errorf("the shim defers to PATH for node: %s", script)
	}
	info, err := os.Stat(shim)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o100 == 0 {
		t.Errorf("the shim is not executable: %v", info.Mode())
	}
}

func TestLinkNodeCommandReportsAMissingCommand(t *testing.T) {
	envDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(envDir, "node_modules", ".bin"), 0o750); err != nil {
		t.Fatal(err)
	}
	err := linkNodeCommand(envDir, "retire", filepath.Join(t.TempDir(), "retire"))
	if err == nil {
		t.Fatal("a package that installed without its command should error rather than link nothing")
	}
	if !strings.Contains(err.Error(), "retire") {
		t.Errorf("the error should name the command: %v", err)
	}
}
