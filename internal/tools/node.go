package tools

import (
	"context"
	"embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// nodePins holds the pinned manifest and lockfile for every tool obtained from npm.
//
// Embedded so the pins travel in the binary. A lockfile fetched at install time is one an attacker
// who can reach the network can choose, which is the opposite of what pinning is for.
//
//go:embed nodepins/*.json
var nodePins embed.FS

// minNodeMajor is the oldest Node this install path uses. `npm ci` and lockfile version 3 both
// need a modern npm, which ships with Node 18 and later.
const minNodeMajor = 18

// NodeSpec describes a tool obtained as an npm package.
type NodeSpec struct {
	// Package is the name on npm.
	Package string
	// Pins names the generated pair under nodepins/, without the suffixes.
	Pins string
	// Command is the executable the package provides under node_modules/.bin.
	Command string
}

// nodeInstallable is the set of tools obtained as npm packages.
//
// retire.js publishes no release binaries at all — npm is the only way to get it — which is the
// same position Semgrep is in on PyPI, and the reason both are provisioned rather than left to the
// reader. A tool Draugr asks a control to run and then cannot obtain is a control that needs a
// separate installation story, and most people will simply not have the control.
var nodeInstallable = map[string]NodeSpec{
	"retire": {Package: "retire", Pins: "retire", Command: "retire"},
}

// nodeVersions pins each npm-packaged tool.
var nodeVersions = map[string]string{"retire": retireVersion}

// retireVersion is the pinned retire.js version. Keep it in step with nodepins/retire.*.json,
// which is generated for exactly this version.
const retireVersion = "5.4.3"

// NodeTool reports the spec for a tool obtained as an npm package.
func NodeTool(name string) (NodeSpec, bool) {
	spec, ok := nodeInstallable[name]
	return spec, ok
}

// NodeVersion is the pinned version of a tool obtained as an npm package.
func NodeVersion(name string) string { return nodeVersions[name] }

// nodeEnvDir is where a tool's package tree lives, under Draugr's own directory.
func nodeEnvDir(root, tool string) string { return filepath.Join(root, "node", tool) }

// installNode installs the tool's package tree and links its command onto PATH.
//
// Returns the shim's path and how well the install is known: LevelPinned when every package
// matched an integrity digest recorded in this binary, LevelUnverified when the lockfile did not
// apply and npm resolved freely instead. Reporting the first for the second would be a claim about
// evidence that was never gathered.
func installNode(ctx context.Context, root, tool string, spec NodeSpec, version string) (string, Level, error) {
	npm, err := findNode(ctx)
	if err != nil {
		return "", "", err
	}
	manifest, err := nodePins.ReadFile("nodepins/" + spec.Pins + ".package.json")
	if err != nil {
		return "", "", fmt.Errorf("%s: no pinned manifest is built into this Draugr: %w", tool, err)
	}
	lock, err := nodePins.ReadFile("nodepins/" + spec.Pins + ".package-lock.json")
	if err != nil {
		return "", "", fmt.Errorf("%s: no pinned lockfile is built into this Draugr: %w", tool, err)
	}

	envDir := nodeEnvDir(root, tool)
	// A fresh tree each time. Installing over an old one leaves whatever the previous version
	// pulled in, and the point of a pinned set is that what is on disk is what was pinned.
	if err := os.RemoveAll(envDir); err != nil {
		return "", "", fmt.Errorf("%s: clearing the old package tree: %w", tool, err)
	}
	if err := os.MkdirAll(envDir, 0o750); err != nil {
		return "", "", err
	}
	for name, body := range map[string][]byte{
		"package.json": manifest, "package-lock.json": lock,
	} {
		if err := os.WriteFile(filepath.Join(envDir, name), body, 0o600); err != nil {
			return "", "", err
		}
	}

	// `npm ci` installs strictly from the lockfile and verifies each package against the integrity
	// digest recorded there — the same guarantee pip's --require-hashes gives, and covering the
	// dependencies as well as the tool.
	//
	// --ignore-scripts because an npm package may run arbitrary code on install, and a
	// provisioning step that executes whatever a dependency author wrote is a supply-chain hole in
	// the middle of the thing meant to close one. retire.js needs none.
	level := LevelPinned
	err = runIn(ctx, envDir, npm, "ci", "--ignore-scripts", "--no-audit", "--no-fund", "--silent")
	if err != nil {
		// A lockfile records one resolution. Falling back keeps the tool installable where that
		// does not apply; dropping the level keeps the report honest, because nothing recorded in
		// this binary checked what was installed.
		level = LevelUnverified
		fallbackErr := runIn(ctx, envDir, npm, "install", "--ignore-scripts", "--no-audit",
			"--no-fund", "--silent", spec.Package+"@"+version)
		if fallbackErr != nil {
			return "", "", fmt.Errorf("%s: installing %s@%s: %w", tool, spec.Package, version, err)
		}
	}

	shim := filepath.Join(root, "bin", tool)
	if err := linkNodeCommand(envDir, spec.Command, shim); err != nil {
		return "", "", err
	}
	return shim, level, nil
}

// linkNodeCommand puts the package's command where Draugr's other binaries live.
//
// The shim names the interpreter by absolute path rather than deferring to npm's launcher, whose
// first line is `#!/usr/bin/env node`. That resolves against whatever PATH the scan runs with, so
// a pipeline that provisions the tool and then runs with a trimmed PATH gets `env: 'node': No such
// file or directory` — a control reporting an error about the runtime rather than about the code.
// The Python path is self-contained for the same reason, by way of the venv's own interpreter.
func linkNodeCommand(envDir, command, shim string) error {
	entry := filepath.Join(envDir, "node_modules", ".bin", command)
	if _, err := os.Stat(entry); err != nil {
		return fmt.Errorf("the package installed but provides no %q command: %w", command, err)
	}
	node, err := execLookPath("node")
	if err != nil {
		return fmt.Errorf("npm installed %s but no `node` is on PATH to run it: %w", command, err)
	}
	if node, err = filepath.Abs(node); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(shim), 0o750); err != nil {
		return err
	}
	script := "#!/bin/sh\nexec " + strconv.Quote(node) + " " + strconv.Quote(entry) + " \"$@\"\n"
	return os.WriteFile(shim, []byte(script), 0o700) // #nosec G306 -- a launcher has to be executable
}

// runIn is run, in a working directory — npm reads package.json from where it is invoked.
func runIn(ctx context.Context, dir, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- npm and the pins are Draugr's own
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if len(msg) > 2048 {
			msg = msg[:2048] + "…"
		}
		if msg == "" {
			return err
		}
		return fmt.Errorf("%w: %s", err, msg)
	}
	return nil
}

// findNode locates an npm new enough for `npm ci` and lockfile version 3, and returns its path.
//
// npm rather than node, because npm is what does the installing — and a Node without it, which
// some distribution packages produce, fails later and less clearly.
func findNode(ctx context.Context) (string, error) {
	npm, err := execLookPath("npm")
	if err != nil {
		return "", fmt.Errorf("retire.js is an npm package and no `npm` is on PATH — install "+
			"Node %d or newer, or install retire.js yourself with `npm install -g retire`",
			minNodeMajor)
	}
	if ok, found := nodeAtLeast(ctx, minNodeMajor); !ok {
		return "", fmt.Errorf("node %s is older than %d, which `npm ci` needs to install from a "+
			"lockfile — upgrade Node, or install retire.js yourself with `npm install -g retire`",
			found, minNodeMajor)
	}
	return npm, nil
}

// nodeAtLeast reports whether the Node on PATH is at least this major version, and what it is.
func nodeAtLeast(ctx context.Context, minMajor int) (bool, string) {
	node, err := execLookPath("node")
	if err != nil {
		return false, "not found"
	}
	out, err := exec.CommandContext(ctx, node, "--version").Output() // #nosec G204 -- node from PATH
	if err != nil {
		return false, "unknown"
	}
	// "v22.23.1"
	version := strings.TrimSpace(string(out))
	major, _, _ := strings.Cut(strings.TrimPrefix(version, "v"), ".")
	n, err := strconv.Atoi(major)
	if err != nil {
		return false, version
	}
	return n >= minMajor, version
}
