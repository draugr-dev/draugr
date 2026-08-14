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

// pythonPins holds the generated, hash-pinned requirement sets. Embedded so an install needs
// nothing beside the binary, and checked in so a bump is a diff somebody reads.
//
//go:embed pythonpins/*.txt
var pythonPins embed.FS

// minPythonMinor is the oldest Python 3 minor Draugr will build a venv with.
//
// Semgrep declares `requires_python >=3.10`. Building the venv with something older produces a
// resolution failure deep in pip's output, where the reason is one line among forty — so it is
// checked first and named plainly.
const minPythonMinor = 10

// PythonSpec describes a tool that ships as a Python package rather than a release binary.
//
// Some scanners publish no binary at all: Semgrep's GitHub releases carry zero assets, and it
// exists as PyPI wheels, a Docker image and a Homebrew formula. Rather than leaving those tools
// outside `tools install` — which makes one control's provisioning everybody's special case —
// Draugr builds a virtual environment it owns and installs the pinned set into it.
//
// The verification floor is the same one a release archive gets, and there is more of it: every
// artifact in the resolved tree carries the SHA-256 PyPI publishes, so the transitive dependencies
// are pinned too, which a single checksum over one archive does not do.
type PythonSpec struct {
	// Package is the distribution name on PyPI.
	Package string
	// Pins names the generated requirements file under pythonpins/, without the extension.
	Pins string
	// MinPythonMinor is the oldest Python 3 minor this package supports.
	MinPythonMinor int
}

// pythonInstallable is the set of tools obtained as Python packages.
var pythonInstallable = map[string]PythonSpec{
	"semgrep": {Package: "semgrep", Pins: "semgrep", MinPythonMinor: minPythonMinor},
}

// PythonTool reports the spec for a tool obtained as a Python package.
func PythonTool(name string) (PythonSpec, bool) {
	spec, ok := pythonInstallable[name]
	return spec, ok
}

// pythonEnvDir is where a tool's virtual environment lives, under Draugr's own directory.
func pythonEnvDir(root, tool string) string { return filepath.Join(root, "venv", tool) }

// installPython builds the tool's virtual environment and links its entry point onto PATH.
//
// Returns the shim's path and how well the install is known: LevelPinned when every artifact
// matched a digest recorded in this binary, LevelUnverified when the pinned set did not apply to
// this platform and pip resolved freely instead. Reporting the first for the second would be a
// claim about evidence that was never gathered.
func installPython(ctx context.Context, root, tool string, spec PythonSpec, version string) (string, Level, error) {
	python, err := findPython(ctx, spec.MinPythonMinor)
	if err != nil {
		return "", "", err
	}
	reqs, err := pythonPins.ReadFile("pythonpins/" + spec.Pins + ".txt")
	if err != nil {
		return "", "", fmt.Errorf("%s: no pinned requirements are built into this Draugr: %w", tool, err)
	}

	envDir := pythonEnvDir(root, tool)
	// A fresh environment each time. Installing over an old one leaves whatever the previous
	// version pulled in, and the point of a pinned set is that what is on disk is what was pinned.
	if err := os.RemoveAll(envDir); err != nil {
		return "", "", fmt.Errorf("%s: clearing the old environment: %w", tool, err)
	}
	if err := run(ctx, python, "-m", "venv", envDir); err != nil {
		return "", "", fmt.Errorf("%s: creating a virtual environment: %w", tool, err)
	}

	reqPath := filepath.Join(envDir, "draugr-requirements.txt")
	if err := os.WriteFile(reqPath, reqs, 0o600); err != nil {
		return "", "", err
	}
	pip := filepath.Join(envDir, "bin", "pip")

	// --require-hashes refuses anything whose artifact is not one of the pinned digests, and
	// --no-deps keeps pip to the set that was pinned rather than resolving alongside it.
	level := LevelPinned
	err = run(ctx, pip, "install", "--quiet", "--no-input", "--require-hashes",
		"--no-deps", "-r", reqPath)
	if err != nil {
		// The pins are resolved on one platform, so another may legitimately need a different
		// wheel. Falling back keeps the tool installable everywhere; dropping the level keeps the
		// report honest, because nothing recorded in this binary checked what was installed.
		level = LevelUnverified
		fallbackErr := run(ctx, pip, "install", "--quiet", "--no-input",
			spec.Package+"=="+version)
		if fallbackErr != nil {
			return "", "", fmt.Errorf("%s: installing %s==%s: %w", tool, spec.Package, version, err)
		}
	}

	shim := filepath.Join(root, "bin", tool)
	if err := linkPythonEntryPoint(envDir, tool, shim); err != nil {
		return "", "", err
	}
	return shim, level, nil
}

// linkPythonEntryPoint puts the environment's entry point where Draugr's other binaries live.
//
// A shim rather than a symlink: the entry point is a script whose first line names the venv's own
// interpreter by absolute path, and a symlink resolves that correctly only by accident of how the
// kernel reports argv[0]. Two lines of shell are unambiguous.
func linkPythonEntryPoint(envDir, tool, shim string) error {
	entry := filepath.Join(envDir, "bin", tool)
	if _, err := os.Stat(entry); err != nil {
		return fmt.Errorf("%s: the package installed but provides no %q command: %w", tool, tool, err)
	}
	if err := os.MkdirAll(filepath.Dir(shim), 0o750); err != nil {
		return err
	}
	// The environment's own bin goes first on PATH. Semgrep's launcher resolves a `semgrep` from
	// PATH ahead of the one beside it, so a stale copy elsewhere — a pipx install from before this
	// existed, say — silently answers instead, and reports its own version while Draugr reports
	// the one it installed. Two numbers about the same tool disagreeing is worse than either.
	script := "#!/bin/sh\nPATH=" + filepath.Join(envDir, "bin") + ":$PATH\nexport PATH\nexec " +
		entry + " \"$@\"\n"
	return os.WriteFile(shim, []byte(script), 0o750) // #nosec G306 -- a launcher has to be executable
}

// findPython returns an interpreter new enough for the package.
//
// Named candidates first, newest first, then the bare `python3` a distribution provides. Checking
// the version here rather than letting pip fail turns forty lines of resolver output into one
// sentence naming what to install.
func findPython(ctx context.Context, minMinor int) (string, error) {
	if minMinor == 0 {
		minMinor = minPythonMinor
	}
	var candidates []string
	for minor := 14; minor >= minMinor; minor-- {
		candidates = append(candidates, "python3."+strconv.Itoa(minor))
	}
	candidates = append(candidates, "python3")

	var found string
	for _, name := range candidates {
		path, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		ok, version := pythonAtLeast(ctx, path, minMinor)
		if ok {
			return path, nil
		}
		if found == "" && version != "" {
			found = version
		}
	}
	if found != "" {
		return "", fmt.Errorf("python 3.%d or newer is required and this machine has %s — "+
			"install a newer Python, or install the tool yourself and leave it on PATH",
			minMinor, found)
	}
	return "", fmt.Errorf("python 3.%d or newer is required and no python3 was found on PATH — "+
		"install one, or install the tool yourself and leave it on PATH", minMinor)
}

// pythonAtLeast reports whether an interpreter is new enough, and what version it is.
func pythonAtLeast(ctx context.Context, path string, minMinor int) (bool, string) {
	out, err := exec.CommandContext(ctx, path, "-c",
		"import sys;print('%d.%d'%sys.version_info[:2])").Output()
	if err != nil {
		return false, ""
	}
	version := strings.TrimSpace(string(out))
	major, minor, ok := strings.Cut(version, ".")
	if !ok || major != "3" {
		return false, version
	}
	n, err := strconv.Atoi(minor)
	if err != nil {
		return false, version
	}
	return n >= minMinor, version
}

// execLookPath is exec.LookPath, named so a test can reach it.
var execLookPath = exec.LookPath

// run executes a command, folding its output into the error so a failure says what went wrong
// rather than only that something did.
func run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- interpreter and pins are Draugr's own
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
