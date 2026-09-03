package tools

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// minGoMinor is the oldest Go this install path uses.
//
// govulncheck v1.7.0 declares `go 1.25.0`, which is newer than this on purpose: Go 1.21 and later
// read that directive and fetch the toolchain the module asks for, so requiring 1.21 here lets a
// host with an older Go still get the right build. A host that has pinned GOTOOLCHAIN=local gets
// Go's own message naming the version it wants, which is more specific than anything this could
// say.
const minGoMinor = 21

// GoSpec describes a tool built from its module with the Go toolchain.
//
// Some tools publish no release binary at all. govulncheck is distributed only as a package path —
// `go install golang.org/x/vuln/cmd/govulncheck` — with no archives on any release page, which is
// the same position Semgrep is in on PyPI and retire.js is in on npm. A tool Draugr asks a control
// to run and then cannot obtain is a control that needs a separate installation story, and most
// people will simply not have the control.
type GoSpec struct {
	// Command is the package path of the command to build.
	Command string
}

// goInstallable is the set of tools obtained with the Go toolchain.
var goInstallable = map[string]GoSpec{
	"govulncheck": {Command: "golang.org/x/vuln/cmd/govulncheck"},
}

// goVersions pins each Go-built tool.
var goVersions = map[string]string{"govulncheck": govulncheckVersion}

// govulncheckVersion is the pinned govulncheck release.
const govulncheckVersion = "1.7.0"

// GoTool reports the spec for a tool built with the Go toolchain.
func GoTool(name string) (GoSpec, bool) {
	spec, ok := goInstallable[name]
	return spec, ok
}

// GoVersion is the pinned version of a tool built with the Go toolchain.
func GoVersion(name string) string { return goVersions[name] }

// installGo builds the tool at its pinned version into Draugr's own bin directory.
//
// Returns the binary's path and how well the install is known: LevelPinned when the module and
// every dependency were verified against the checksum database, LevelUnverified when that could
// not be enforced and the ambient configuration was used instead. Reporting the first for the
// second would be a claim about evidence that was never gathered.
//
// No shim, unlike the Python and Node paths: `go install` produces a self-contained binary that
// needs no interpreter beside it, so the thing on PATH is the tool itself.
func installGo(ctx context.Context, root, tool string, spec GoSpec, version string) (string, Level, error) {
	goBin, err := findGo(ctx, tool)
	if err != nil {
		return "", "", err
	}
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
		return "", "", err
	}

	target := spec.Command + "@v" + strings.TrimPrefix(version, "v")

	// The checksum database is what makes this path verifiable, so it is set rather than
	// inherited. `go help environment` names GOPRIVATE, GONOPROXY and GONOSUMDB as the ways to
	// switch that validation off, and GOINSECURE and GOFLAGS can weaken the fetch around it — a
	// host with any of them already set would otherwise skip verification while this code
	// reported that it happened. Every module in the build is checked, not only the tool, which
	// is the same guarantee --require-hashes gives on PyPI and `npm ci` gives from a lockfile.
	verified := append(os.Environ(),
		"GOBIN="+binDir,
		"GOSUMDB=sum.golang.org",
		"GOPRIVATE=",
		"GONOSUMDB=",
		"GOFLAGS=",
		"GOINSECURE=",
	)
	level := LevelPinned
	if err := runEnv(ctx, verified, goBin, "install", target); err != nil {
		// An air-gapped or proxied host may be unable to reach the checksum database at all.
		// Falling back keeps the tool installable there; dropping the level keeps the report
		// honest, because nothing this code set verified what was built.
		level = LevelUnverified
		fallback := append(os.Environ(), "GOBIN="+binDir)
		if fallbackErr := runEnv(ctx, fallback, goBin, "install", target); fallbackErr != nil {
			return "", "", fmt.Errorf("%s: installing %s: %w", tool, target, err)
		}
	}

	path := filepath.Join(binDir, tool)
	if _, err := os.Stat(path); err != nil {
		return "", "", fmt.Errorf("%s: the module built but produced no %q command: %w", tool, tool, err)
	}
	return path, level, nil
}

// runEnv is run, with an explicit environment.
func runEnv(ctx context.Context, env []string, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- the go tool and the pins are Draugr's own
	cmd.Env = env
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

// findGo locates a Go toolchain new enough to honor a module's own toolchain directive.
func findGo(ctx context.Context, tool string) (string, error) {
	goBin, err := execLookPath("go")
	if err != nil {
		return "", fmt.Errorf("%s is distributed as a Go package and no `go` is on PATH — "+
			"install Go %d or newer from https://go.dev/dl/, or install it yourself with "+
			"`go install %s@v%s`", tool, minGoMinor, goInstallable[tool].Command, goVersions[tool])
	}
	if ok, found := goAtLeast(ctx, goBin, minGoMinor); !ok {
		return "", fmt.Errorf("go %s is older than 1.%d, which is needed to fetch the toolchain "+
			"%s asks for — upgrade Go, or install it yourself with `go install %s@v%s`",
			found, minGoMinor, tool, goInstallable[tool].Command, goVersions[tool])
	}
	return goBin, nil
}

// goAtLeast reports whether the Go on PATH is at least this 1.x minor, and what it is.
func goAtLeast(ctx context.Context, goBin string, minMinor int) (bool, string) {
	out, err := exec.CommandContext(ctx, goBin, "version").Output() // #nosec G204 -- go from PATH
	if err != nil {
		return false, "unknown"
	}
	// "go version go1.26.6 linux/amd64"
	fields := strings.Fields(string(out))
	if len(fields) < 3 {
		return false, "unknown"
	}
	version := strings.TrimPrefix(fields[2], "go")
	majorText, rest, _ := strings.Cut(version, ".")
	major, err := strconv.Atoi(majorText)
	if err != nil {
		// Unparseable is not "new enough". Treating it as satisfied would let the install proceed
		// against a toolchain nothing checked, and the failure would then arrive from `go install`
		// as something about modules.
		return false, version
	}
	if major > 1 {
		return true, version // a Go 2 clears any 1.x floor
	}
	if major < 1 {
		return false, version
	}
	minorText, _, _ := strings.Cut(rest, ".")
	minor, err := strconv.Atoi(minorText)
	if err != nil {
		return false, version
	}
	return minor >= minMinor, version
}
