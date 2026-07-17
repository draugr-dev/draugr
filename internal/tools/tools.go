// Package tools describes the external command-line scanners Draugr orchestrates and
// detects whether they are installed. It backs `draugr doctor` — an explicit preflight
// so a missing tool is reported up front with an install hint, instead of surfacing as a
// buried "executable file not found" error mid-scan.
//
// Detection only ever reads the environment (looks on PATH, runs a version probe). It
// never downloads or installs anything — provisioning is a separate, opt-in step.
package tools

import (
	"context"
	"os/exec"
	"regexp"
	"sort"
)

// Tool describes an external executable a scanner shells out to.
type Tool struct {
	// Binary is the executable name looked up on PATH, e.g. "trivy".
	Binary string
	// VersionArgs prints the tool's version, e.g. ["--version"]. Empty skips the probe.
	VersionArgs []string
	// InstallHint tells the user how or where to install the tool when it's missing.
	InstallHint string
	// Category groups the tool: "scanner" (backs a control) or "utility" (supporting tool
	// like git or cosign). Shown in `tools list`.
	Category string
	// Optional marks a tool whose absence should not fail `doctor` — a nice-to-have that
	// enhances behavior (e.g. cosign for signature verification) rather than a requirement.
	Optional bool
}

// Tool categories.
const (
	CategoryScanner = "scanner"
	CategoryUtility = "utility"
)

// Status is the outcome of detecting a Tool.
type Status struct {
	Tool    Tool
	Found   bool
	Path    string
	Version string
	// Err is set when the tool was found but the version probe failed (non-fatal).
	Err error
}

// LookPathFunc resolves a binary name to a path (defaults to exec.LookPath).
type LookPathFunc func(string) (string, error)

// RunFunc executes argv and returns its output (defaults to running the command).
type RunFunc func(ctx context.Context, argv []string) ([]byte, error)

// semverRE extracts the first dotted version number from tool output, e.g. "0.58.1" from
// Trivy's "Version: 0.58.1" or "2.43.0" from "git version 2.43.0".
var semverRE = regexp.MustCompile(`\d+\.\d+(?:\.\d+)?`)

// Catalog returns the external tools Draugr's built-in scanners use, keyed by binary name.
// Several scanners share one binary (trivy backs images, sca, and iac), so the catalog is
// keyed by the binary rather than the scanner.
func Catalog() map[string]Tool {
	return map[string]Tool{
		"trivy": {
			Binary:      "trivy",
			VersionArgs: []string{"--version"},
			InstallHint: "https://trivy.dev/latest/getting-started/installation/",
			Category:    CategoryScanner,
		},
		"gitleaks": {
			Binary:      "gitleaks",
			VersionArgs: []string{"version"},
			InstallHint: "https://github.com/gitleaks/gitleaks#installing",
			Category:    CategoryScanner,
		},
		"semgrep": {
			Binary:      "semgrep",
			VersionArgs: []string{"--version"},
			InstallHint: "https://semgrep.dev/docs/getting-started/",
			Category:    CategoryScanner,
		},
		"gosec": {
			Binary:      "gosec",
			VersionArgs: []string{"-version"},
			InstallHint: "https://github.com/securego/gosec#installation",
			Category:    CategoryScanner,
		},
		"cosign": {
			Binary:      "cosign",
			VersionArgs: []string{"version"},
			InstallHint: "https://docs.sigstore.dev/cosign/system_config/installation/",
			Category:    CategoryUtility,
			Optional:    true, // enhances provenance verification; not required
		},
		"git": {
			Binary:      "git",
			VersionArgs: []string{"--version"},
			InstallHint: "https://git-scm.com/downloads",
			Category:    CategoryUtility,
		},
	}
}

// All returns the catalog's tools sorted by binary name, for a full environment check when
// no Saga narrows the set.
func All() []Tool {
	cat := Catalog()
	out := make([]Tool, 0, len(cat))
	for _, t := range cat {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Binary < out[j].Binary })
	return out
}

// Detect reports whether a tool is on PATH and, if so, its version. lookPath and run are
// injectable for testing; nil uses the real environment.
func Detect(ctx context.Context, t Tool, lookPath LookPathFunc, run RunFunc) Status {
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	if run == nil {
		run = defaultRun
	}

	st := Status{Tool: t}
	path, err := lookPath(t.Binary)
	if err != nil {
		return st // not found on PATH
	}
	st.Found = true
	st.Path = path

	if len(t.VersionArgs) == 0 {
		return st
	}
	out, err := run(ctx, append([]string{t.Binary}, t.VersionArgs...))
	if err != nil {
		st.Err = err // found, but couldn't read version — report it, don't fail detection
		return st
	}
	st.Version = semverRE.FindString(string(out))
	return st
}

// defaultRun runs the version probe, capturing stdout and stderr (some tools print their
// version to stderr).
func defaultRun(ctx context.Context, argv []string) ([]byte, error) {
	// Running the configured tool is the point; no shell, and argv comes from the typed
	// catalog above, not user input.
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // version probe of a catalog-defined tool // nosem: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	return cmd.CombinedOutput()
}
