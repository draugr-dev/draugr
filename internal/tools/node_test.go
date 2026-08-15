package tools

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
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

// stubLookPath points execLookPath at a fake for one test, and restores it afterwards.
func stubLookPath(t *testing.T, fn func(string) (string, error)) {
	t.Helper()
	original := execLookPath
	execLookPath = fn
	t.Cleanup(func() { execLookPath = original })
}

// fakeNode writes an executable that prints what a `node --version` would, so the version gate can
// be tested against the answers that actually matter — too old, new enough, and unparseable —
// without depending on which Node happens to be installed on the machine running the tests.
func fakeNode(t *testing.T, output string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "node")
	script := "#!/bin/sh\necho " + strconv.Quote(output) + "\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil { // #nosec G306 -- must execute
		t.Fatal(err)
	}
	return path
}

func TestNodeVersionAndEnvDir(t *testing.T) {
	if got := NodeVersion("retire"); got != retireVersion {
		t.Errorf("NodeVersion(retire) = %q, want %q", got, retireVersion)
	}
	if got := NodeVersion("not-a-tool"); got != "" {
		t.Errorf("an unknown tool should have no pinned version, got %q", got)
	}
	if got := nodeEnvDir("/root", "retire"); got != filepath.Join("/root", "node", "retire") {
		t.Errorf("nodeEnvDir = %q", got)
	}
}

// TestNodeAtLeastReadsTheRuntimeVersion covers the gate that decides whether `npm ci` is even
// possible. Reporting a too-old Node as acceptable produces a failure inside npm instead of the
// message naming the real problem.
func TestNodeAtLeastReadsTheRuntimeVersion(t *testing.T) {
	for _, c := range []struct {
		name, output string
		ok           bool
		found        string
	}{
		{"new enough", "v22.11.0", true, "v22.11.0"},
		{"exactly the minimum", "v18.0.0", true, "v18.0.0"},
		{"too old", "v16.20.2", false, "v16.20.2"},
		{"unparseable", "banana", false, "banana"},
	} {
		t.Run(c.name, func(t *testing.T) {
			node := fakeNode(t, c.output)
			stubLookPath(t, func(string) (string, error) { return node, nil })

			ok, found := nodeAtLeast(t.Context(), minNodeMajor)
			if ok != c.ok || found != c.found {
				t.Errorf("nodeAtLeast = %v, %q; want %v, %q", ok, found, c.ok, c.found)
			}
		})
	}
}

func TestNodeAtLeastWithNoNode(t *testing.T) {
	stubLookPath(t, func(string) (string, error) { return "", exec.ErrNotFound })
	if ok, found := nodeAtLeast(t.Context(), minNodeMajor); ok || found != "not found" {
		t.Errorf("nodeAtLeast = %v, %q; want false, \"not found\"", ok, found)
	}
}

// TestFindNodeExplainsWhatToDo pins the two failures a user can actually act on. Both messages
// have to name a way forward: this is a tool Draugr can install, so "not found" alone would leave
// the reader with a missing scanner and no next step.
func TestFindNodeExplainsWhatToDo(t *testing.T) {
	t.Run("no npm", func(t *testing.T) {
		stubLookPath(t, func(string) (string, error) { return "", exec.ErrNotFound })
		_, err := findNode(t.Context())
		if err == nil {
			t.Fatal("a missing npm must be an error, not a silent skip")
		}
		if !strings.Contains(err.Error(), "npm install -g retire") {
			t.Errorf("the error should offer a way forward: %v", err)
		}
	})

	t.Run("node too old", func(t *testing.T) {
		node := fakeNode(t, "v16.20.2")
		stubLookPath(t, func(string) (string, error) { return node, nil })
		_, err := findNode(t.Context())
		if err == nil {
			t.Fatal("a Node too old for `npm ci` must be an error")
		}
		if !strings.Contains(err.Error(), "16") || !strings.Contains(err.Error(), "18") {
			t.Errorf("the error should name the version found and the one needed: %v", err)
		}
	})
}

func TestRunIn(t *testing.T) {
	dir := t.TempDir()
	if err := runIn(t.Context(), dir, "sh", "-c", "exit 0"); err != nil {
		t.Errorf("a successful command should not error: %v", err)
	}

	// A failure has to carry the tool's own output. `npm ci` explains itself well, and an exit
	// status alone would throw that away and leave the user with a number.
	err := runIn(t.Context(), dir, "sh", "-c", "echo something-went-wrong >&2; exit 1")
	if err == nil {
		t.Fatal("a failing command must error")
	}
	if !strings.Contains(err.Error(), "something-went-wrong") {
		t.Errorf("the error should carry the command's output: %v", err)
	}

	// Very long output is truncated rather than pasted whole into a report.
	err = runIn(t.Context(), dir, "sh", "-c", "head -c 5000 /dev/zero | tr '\\0' 'x'; exit 1")
	if err == nil {
		t.Fatal("a failing command must error")
	}
	if !strings.Contains(err.Error(), "…") {
		t.Errorf("output beyond the limit should be truncated: %d chars", len(err.Error()))
	}

	if err := runIn(t.Context(), dir, "definitely-not-a-real-command"); err == nil {
		t.Error("a command that cannot start must error")
	}
}

// TestInstallNodeRejectsAToolWithNoPins covers the guard that would otherwise install something
// unpinned while reporting it as pinned.
func TestInstallNodeRejectsAToolWithNoPins(t *testing.T) {
	node := fakeNode(t, "v22.11.0")
	stubLookPath(t, func(string) (string, error) { return node, nil })

	_, _, err := installNode(t.Context(), t.TempDir(), "ghost",
		NodeSpec{Package: "ghost", Pins: "ghost", Command: "ghost"}, "1.0.0")
	if err == nil {
		t.Fatal("a tool with no pins built in must not install")
	}
	if !strings.Contains(err.Error(), "pinned manifest") {
		t.Errorf("the error should name what is missing: %v", err)
	}
}

// fakeNPM writes a stand-in for npm that records how it was called and, on the subcommands named
// in succeed, produces the command the package would have installed.
//
// This keeps the whole install path testable without a network: what is being checked is Draugr's
// half of it — that the pins reach disk, that the invocation carries --ignore-scripts, that the
// shim is linked, and that the level reported matches which invocation actually worked.
func fakeNPM(t *testing.T, log string, succeed ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "npm")
	var cases string
	for _, sub := range succeed {
		cases += "  " + sub + ") mkdir -p node_modules/.bin && " +
			"printf '#!/usr/bin/env node\\n' > node_modules/.bin/retire && " +
			"chmod +x node_modules/.bin/retire; exit 0 ;;\n"
	}
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + strconv.Quote(log) + "\ncase \"$1\" in\n" +
		cases + "  *) echo 'npm refused' >&2; exit 1 ;;\nesac\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil { // #nosec G306 -- must execute
		t.Fatal(err)
	}
	return path
}

// stubNodeTools points execLookPath at the fake npm and a fake node.
func stubNodeTools(t *testing.T, npm string) {
	t.Helper()
	node := fakeNode(t, "v22.11.0")
	stubLookPath(t, func(name string) (string, error) {
		if name == "npm" {
			return npm, nil
		}
		return node, nil
	})
}

// TestInstallNodeUsesTheLockfileAndReportsPinned is the good path: `npm ci` succeeds, so every
// package was checked against a digest recorded in this binary and the install may say so.
func TestInstallNodeUsesTheLockfileAndReportsPinned(t *testing.T) {
	root := t.TempDir()
	log := filepath.Join(t.TempDir(), "calls")
	stubNodeTools(t, fakeNPM(t, log, "ci"))

	shim, level, err := installNode(t.Context(), root, "retire", nodeInstallable["retire"],
		retireVersion)
	if err != nil {
		t.Fatal(err)
	}
	if level != LevelPinned {
		t.Errorf("level = %q, want %q — `npm ci` verified the tree", level, LevelPinned)
	}
	if shim != filepath.Join(root, "bin", "retire") {
		t.Errorf("shim = %q", shim)
	}
	if _, err := os.Stat(shim); err != nil {
		t.Errorf("the shim was not written: %v", err)
	}

	// The pins have to reach disk, or `npm ci` would resolve against whatever was already there.
	envDir := nodeEnvDir(root, "retire")
	for _, name := range []string{"package.json", "package-lock.json"} {
		if _, err := os.Stat(filepath.Join(envDir, name)); err != nil {
			t.Errorf("%s was not written into the env: %v", name, err)
		}
	}

	calls, err := os.ReadFile(log) // #nosec G304 -- a path this test just created
	if err != nil {
		t.Fatal(err)
	}
	invocation := string(calls)
	if !strings.Contains(invocation, "ci") {
		t.Errorf("npm was not asked to install from the lockfile: %q", invocation)
	}
	// Without this an npm package runs arbitrary code during provisioning.
	if !strings.Contains(invocation, "--ignore-scripts") {
		t.Errorf("the install must disable package scripts: %q", invocation)
	}
}

// TestInstallNodeDropsToUnverifiedWhenTheLockfileDoesNotApply pins the honesty of the claim.
//
// The fallback exists so the tool stays installable where the pinned resolution does not apply.
// Reporting that install as pinned would describe verification that never happened.
func TestInstallNodeDropsToUnverifiedWhenTheLockfileDoesNotApply(t *testing.T) {
	root := t.TempDir()
	log := filepath.Join(t.TempDir(), "calls")
	stubNodeTools(t, fakeNPM(t, log, "install")) // `ci` fails, `install` works

	_, level, err := installNode(t.Context(), root, "retire", nodeInstallable["retire"],
		retireVersion)
	if err != nil {
		t.Fatal(err)
	}
	if level != LevelUnverified {
		t.Errorf("level = %q, want %q — nothing in this binary checked what was installed",
			level, LevelUnverified)
	}
	calls, err := os.ReadFile(log) // #nosec G304 -- a path this test just created
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(calls), "retire@"+retireVersion) {
		t.Errorf("the fallback should still ask for the pinned version: %q", calls)
	}
}

// TestInstallNodeFailsWhenNpmCannotInstall covers the case where neither invocation works: the
// error has to name the tool and version rather than leave a missing scanner and a bare exit code.
func TestInstallNodeFailsWhenNpmCannotInstall(t *testing.T) {
	log := filepath.Join(t.TempDir(), "calls")
	stubNodeTools(t, fakeNPM(t, log)) // nothing succeeds

	_, _, err := installNode(t.Context(), t.TempDir(), "retire", nodeInstallable["retire"],
		retireVersion)
	if err == nil {
		t.Fatal("an install where npm failed twice must error")
	}
	if !strings.Contains(err.Error(), "retire") {
		t.Errorf("the error should name the tool: %v", err)
	}
}

// TestInstallNodeToolRecordsWhatEndedUpOnPath covers the step between the install and everything
// that later asks what was installed.
//
// The attestation has to describe the shim, because the shim is the file a scan actually executes.
// Recording the package's own launcher instead would digest a file nothing runs, and `tools list`
// would report a version nobody could verify.
func TestInstallNodeToolRecordsWhatEndedUpOnPath(t *testing.T) {
	root := t.TempDir()
	destDir := filepath.Join(root, "bin")
	log := filepath.Join(t.TempDir(), "calls")
	stubNodeTools(t, fakeNPM(t, log, "ci"))

	// An empty version asks for the pinned one, which is how `tools install retire` arrives here.
	got, err := installNodeTool(t.Context(), "retire", "", destDir, nodeInstallable["retire"])
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != retireVersion {
		t.Errorf("version = %q, want the pinned %q", got.Version, retireVersion)
	}
	if got.Name != "retire" {
		t.Errorf("name = %q", got.Name)
	}
	if got.Path != filepath.Join(root, "bin", "retire") {
		t.Errorf("path = %q, want the shim on PATH", got.Path)
	}
	sum, err := fileSHA256(got.Path)
	if err != nil {
		t.Fatalf("the recorded path is not a readable file: %v", err)
	}
	if sum == "" {
		t.Error("the shim produced no digest, so nothing could attest it")
	}
}
