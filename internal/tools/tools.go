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
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
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
	// DataArgs probes for data the tool needs beyond its own binary — Nuclei's template set,
	// for instance. Empty means the binary is all there is.
	//
	// Being on PATH is not the same as being able to run. A tool whose data is missing fails at
	// scan time with a message about a symptom, and `doctor` exists to answer "is this going to
	// fail" before the scan rather than after it.
	DataArgs []string
	// DataFiles are paths that must exist for the tool to work, tried in order. Used where the
	// tool cannot be asked cheaply: kube-bench only reveals a missing `cfg/` by attempting a
	// benchmark, and doctor must not run a scan to find out whether a scan would work.
	DataFiles []string
	// DataOK reads DataArgs' output and reports whether the data is there, plus a short
	// description for the report. Required when DataArgs is set.
	DataOK func(out []byte) (ok bool, detail string)
	// DataHint tells the user how to obtain the data when it is missing.
	DataHint string
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
	// DataFound reports whether the tool's supporting data is present. Meaningless unless the
	// tool declares DataArgs; DataChecked says whether it was asked.
	DataChecked bool
	DataFound   bool
	// DataDetail describes what was found, e.g. a template-set version.
	DataDetail string
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
		"grype": {
			Binary:      "grype",
			VersionArgs: []string{"version"},
			InstallHint: "https://github.com/anchore/grype#installation",
			Category:    CategoryScanner,
			// Grype is a matcher with no vulnerability data of its own, and it refuses to scan
			// against a database more than five days old — so a binary on PATH is not yet a
			// scanner that can run. Grype is asked rather than the disk inspected, because it is
			// the only thing that knows whether what is on disk is current enough to be used.
			DataArgs: []string{"db", "status", "-o", "json"},
			DataOK:   GrypeDBOK,
			DataHint: "run `grype db update`",
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
		"nuclei": {
			Binary:      "nuclei",
			VersionArgs: []string{"-version"},
			InstallHint: "https://docs.projectdiscovery.io/tools/nuclei/install",
			Category:    CategoryScanner,
			// Nuclei is a template engine with no templates of its own. Installed but empty, it
			// exits non-zero with "no templates provided for scan", which reads like a mistake in
			// the descriptor rather than a missing download.
			DataArgs: []string{"-templates-version"},
			DataOK:   NucleiTemplatesOK,
			DataHint: "run `nuclei -update-templates`",
		},
		"syft": {
			Binary:      "syft",
			VersionArgs: []string{"version"},
			InstallHint: "https://github.com/anchore/syft#installation",
			// Not a scanner: syft backs no control. It generates the SBOM evidence a Saga asks
			// for with config.sbom, so it is only required when that is switched on.
			Category: CategoryUtility,
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
		"kube-bench": {
			Binary:      "kube-bench",
			VersionArgs: []string{"version"},
			InstallHint: "https://github.com/aquasecurity/kube-bench/releases — extract both the binary and its cfg/ directory",
			Category:    CategoryScanner,
			// kube-bench ships its benchmarks as a cfg/ tree beside the binary, and people
			// install the binary alone. Without it every run dies with "config file is missing
			// 'target_mapping' section", which names an internal structure rather than the
			// directory nobody copied.
			//
			// Checked on disk rather than by asking: the only way to make kube-bench admit the
			// configuration is missing is to start a benchmark, and doctor must not run a scan
			// to find out whether a scan would work. These are its own default search paths.
			DataFiles: []string{
				"~/.draugr/data/kube-bench/config.yaml", // what `draugr tools install` writes
				"{bindir}/cfg/config.yaml",              // a tarball extract, the commonest by hand
				"/etc/kube-bench/cfg/config.yaml",
				"/usr/local/share/kube-bench/cfg/config.yaml",
				"/opt/kube-bench/cfg/config.yaml",
				"./cfg/config.yaml",
			},
			DataHint: "run `draugr tools install kube-bench`, which fetches the binary and its cfg/ tree together",
		},
		"kubectl": {
			Binary:      "kubectl",
			VersionArgs: []string{"version", "--client"},
			InstallHint: "https://kubernetes.io/docs/tasks/tools/",
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

	switch {
	case len(t.DataArgs) > 0 && t.DataOK != nil:
		st.DataChecked = true
		dataOut, dataErr := run(ctx, append([]string{t.Binary}, t.DataArgs...))
		if dataErr == nil {
			st.DataFound, st.DataDetail = t.DataOK(dataOut)
		}
	case len(t.DataFiles) > 0:
		st.DataChecked = true
		for _, p := range t.DataFiles {
			// {bindir} is where a tarball extract leaves the data — beside the binary — which is
			// the commonest install and the one a fixed list of system paths would miss.
			expanded := expandHome(strings.ReplaceAll(p, "{bindir}", filepath.Dir(st.Path)))
			if fileExists(expanded) {
				st.DataFound, st.DataDetail = true, expanded
				break
			}
		}
	}
	return st
}

// fileExists reports whether path is a readable file or directory.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// expandHome resolves a leading ~ so a catalog entry can name a path under the user's home
// without the catalog knowing whose home it is.
func expandHome(path string) string {
	if !strings.HasPrefix(path, "~/") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return filepath.Join(home, path[2:])
}

// defaultRun runs the version probe, capturing stdout and stderr (some tools print their
// version to stderr).
func defaultRun(ctx context.Context, argv []string) ([]byte, error) {
	// Running the configured tool is the point; no shell, and argv comes from the typed
	// catalog above, not user input.
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) // #nosec G204 -- version probe of a catalog-defined tool // nosem: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	return cmd.CombinedOutput()
}

// nucleiTemplatesVersionRE reads `nuclei -templates-version`, which prints
//
//	[INF] Public nuclei-templates version: v10.4.6 (/home/you/nuclei-templates)
//
// and, with no templates installed, prints the same line with the version blank — and exits 0
// either way. The blank is the signal; the exit code says nothing.
var nucleiTemplatesVersionRE = regexp.MustCompile(`nuclei-templates version:\s*(\S+)?\s*\(([^)]*)\)`)

// GrypeDBOK reports whether Grype has a usable vulnerability database, and when it was built.
//
// `valid` is Grype's own verdict and the only one worth reporting: a database file can exist,
// be readable, and still be one Grype will refuse to scan with because it is too old or its
// schema belongs to a version of the tool that is no longer served.
func GrypeDBOK(out []byte) (bool, string) {
	var status struct {
		Built string `json:"built"`
		Valid bool   `json:"valid"`
	}
	if json.Unmarshal(out, &status) != nil || !status.Valid {
		return false, ""
	}
	return true, "built " + status.Built
}

// NucleiTemplatesOK reports whether Nuclei has a template set, and which. Exported because the
// scanner checks the same thing after asking Nuclei to download one — the tool exits 0 either
// way, so the answer has to come from the same place `doctor` gets it.
func NucleiTemplatesOK(out []byte) (bool, string) {
	m := nucleiTemplatesVersionRE.FindSubmatch(out)
	if m == nil {
		return false, ""
	}
	version, dir := string(m[1]), string(m[2])
	if version == "" {
		return false, dir
	}
	return true, version + " (" + dir + ")"
}
