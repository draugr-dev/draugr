package tools

import (
	"context"
	"debug/buildinfo"
	"fmt"
	"go/version"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// minGoMinor is the oldest Go this install path uses.
//
// The build runs under the toolchain goToolchains names, which is newer than this on purpose: Go
// 1.21 and later fetch the toolchain GOTOOLCHAIN names, so requiring 1.21 here lets a host with an
// older Go still get the right build.
const minGoMinor = 21

// GoSpec describes a tool built from its module with the Go toolchain.
//
// Some tools publish no release binary at all. govulncheck is distributed only as a package path,
// `go install golang.org/x/vuln/cmd/govulncheck`, with no archives on any release page, which is
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
const govulncheckVersion = "1.9.0"

// goToolchains is the oldest Go each Go-built tool is built with.
//
// A pin beside the tool's own, because the Go that builds govulncheck decides what it can analyze.
// The go/types package compiled into the binary refuses a package whose `go` line names a newer
// language version than the Go that built it, so a govulncheck built with Go 1.26 cannot load a
// module declaring `go 1.27`. The newest stable release loads every module that release can build,
// and reports the same results as an older build on a module both can load.
var goToolchains = map[string]string{"govulncheck": govulncheckToolchain}

// govulncheckToolchain is the Go release govulncheck is built with where the Go on PATH is older.
const govulncheckToolchain = "go1.27.3"

// GoTool reports the spec for a tool built with the Go toolchain.
func GoTool(name string) (GoSpec, bool) {
	spec, ok := goInstallable[name]
	return spec, ok
}

// GoVersion is the pinned version of a tool built with the Go toolchain.
func GoVersion(name string) string { return goVersions[name] }

// GoToolchain is the oldest Go release a Go-built tool is built with, as goX.Y.Z, or "" for a tool
// that is not built with Go.
func GoToolchain(name string) string { return goToolchains[name] }

// GoToolchainBehind reports whether buildGo, the Go a copy of a tool was built with, is older than
// the release GoToolchain names for it. False for a tool not built with Go and for a buildGo that
// is not a Go version, such as the empty string a binary with no build information reads as.
func GoToolchainBehind(name, buildGo string) bool {
	pin := GoToolchain(name)
	return pin != "" && version.IsValid(buildGo) && version.Compare(buildGo, pin) < 0
}

// toolchainCurrent reports whether an install record's toolchain is at or above the release
// GoToolchain names. A tool not built with Go has nothing to compare. A Go-built record with no
// toolchain was made before the pin existed, by whatever Go was on PATH, and is rebuilt.
func toolchainCurrent(name, recorded string) bool {
	pin := GoToolchain(name)
	return pin == "" || version.Compare(recorded, pin) >= 0
}

// ReadBuildGo is the Go release a binary was built with, read from the build information the Go
// linker writes into it, or "" when path is not a Go binary or cannot be read.
//
// The binary's own answer is the only reliable one. `govulncheck -version` prints the Go on PATH,
// which is not the Go whose go/types decides which modules it can load.
func ReadBuildGo(path string) string {
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return ""
	}
	// An experiment build appends its settings after a space, as in "go1.27.3 X:boringcrypto".
	fields := strings.Fields(info.GoVersion)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// buildToolchain decides which Go builds a tool, and returns the GOTOOLCHAIN value to build under
// and the Go release that value runs.
//
// A GOTOOLCHAIN in the environment that names a release wins, so somebody who needs a newer Go than
// the pin, or a particular one, gets it. Otherwise the newer of the Go on PATH and the pin: the Go
// on PATH where it is at least the pin, which needs no download, and the pin where it is older.
// Values such as `auto`, `local` and `go1.27.3+auto` name a policy rather than a release, and are
// replaced, because each can build with a Go older than the pin.
func buildToolchain(ctx context.Context, goBin, pin string) (setting, release string) {
	if user := os.Getenv("GOTOOLCHAIN"); version.IsValid(user) && !strings.Contains(user, "+") {
		return user, user
	}
	local := localGoVersion(ctx, goBin)
	if version.IsValid(local) && version.Compare(local, pin) >= 0 {
		return "local", local
	}
	return pin, pin
}

// localGoVersion is the release of the Go at goBin itself, or "" when it cannot be asked.
//
// GOTOOLCHAIN=local, because under the default the go command switches to the toolchain the
// go.mod in the working directory asks for and reports that one instead.
func localGoVersion(ctx context.Context, goBin string) string {
	cmd := exec.CommandContext(ctx, goBin, "env", "GOVERSION") // #nosec G204 -- go from PATH
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// goInstallEnv is the environment `go install` builds a tool under: Draugr's bin directory as
// GOBIN, the toolchain buildToolchain chose, and, when verified, the checksum database enforced.
//
// The toolchain is set on both attempts. A fallback that inherited the ambient GOTOOLCHAIN would
// build with whatever Go is on PATH and record the toolchain this code chose.
//
// The checksum database is what makes the verified attempt verifiable, so it is set rather than
// inherited. `go help environment` names GOPRIVATE, GONOPROXY and GONOSUMDB as the ways to switch
// that validation off, and GOINSECURE and GOFLAGS can weaken the fetch around it, a host with any
// of them already set would otherwise skip verification while this code reported that it
// happened. Every module in the build is checked, not only the tool, which is the same guarantee
// --require-hashes gives on PyPI and `npm ci` gives from a lockfile. A toolchain the build
// downloads is checked against the same database.
func goInstallEnv(binDir, toolchain string, verified bool) []string {
	env := append(os.Environ(), "GOBIN="+binDir, "GOTOOLCHAIN="+toolchain)
	if verified {
		env = append(env,
			"GOSUMDB=sum.golang.org",
			"GOPRIVATE=",
			"GONOSUMDB=",
			"GOFLAGS=",
			"GOINSECURE=",
		)
	}
	return env
}

// goBuild is what installGo built: the binary, the Go release that built it, and how well the
// install is known.
type goBuild struct {
	path      string
	toolchain string
	level     Level
}

// installGo builds the tool at its pinned version into Draugr's own bin directory, with the Go
// buildToolchain chooses.
//
// The level is LevelPinned when the module and every dependency were verified against the checksum
// database, LevelUnverified when that could not be enforced and the ambient configuration was used
// instead. Reporting the first for the second would be a claim about evidence that was never
// gathered.
//
// No shim, unlike the Python and Node paths: `go install` produces a self-contained binary that
// needs no interpreter beside it, so the thing on PATH is the tool itself.
func installGo(ctx context.Context, root, tool string, spec GoSpec, ver string) (goBuild, error) {
	goBin, err := findGo(ctx, tool)
	if err != nil {
		return goBuild{}, err
	}
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
		return goBuild{}, err
	}

	target := spec.Command + "@v" + strings.TrimPrefix(ver, "v")
	setting, release := buildToolchain(ctx, goBin, GoToolchain(tool))

	level := LevelPinned
	if err := runEnv(ctx, goInstallEnv(binDir, setting, true), goBin, "install", target); err != nil {
		// An air-gapped or proxied host may be unable to reach the checksum database at all.
		// Falling back keeps the tool installable there; dropping the level keeps the report
		// honest, because nothing this code set verified what was built.
		level = LevelUnverified
		if fallbackErr := runEnv(ctx, goInstallEnv(binDir, setting, false), goBin, "install", target); fallbackErr != nil {
			return goBuild{}, fmt.Errorf("%s: installing %s with %s: %w", tool, target, release, err)
		}
	}

	path := filepath.Join(binDir, tool)
	if _, err := os.Stat(path); err != nil {
		return goBuild{}, fmt.Errorf("%s: the module built but produced no %q command: %w", tool, tool, err)
	}
	return goBuild{path: path, toolchain: release, level: level}, nil
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
		return "", RuntimeMissing(fmt.Errorf(
			"%s is distributed as a Go package and no `go` is on PATH, install Go 1.%d or newer "+
				"from https://go.dev/dl/, or install it yourself with `go install %s@v%s`",
			tool, minGoMinor, goInstallable[tool].Command, goVersions[tool]))
	}
	if ok, found := goAtLeast(ctx, goBin, minGoMinor); !ok {
		return "", RuntimeMissing(fmt.Errorf(
			"go %s is older than 1.%d, which is needed to fetch the toolchain %s asks for. "+
				"Upgrade Go, or install it yourself with `go install %s@v%s`",
			found, minGoMinor, tool, goInstallable[tool].Command, goVersions[tool]))
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
