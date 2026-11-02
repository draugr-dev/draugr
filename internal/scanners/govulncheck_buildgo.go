package scanners

import (
	"context"
	"fmt"
	"go/version"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/draugr-dev/draugr/internal/tools"
)

// govulncheckBuildGo is the Go release the govulncheck a scan runs was built with, or "" where it
// cannot be read. A variable so a test can name one.
var govulncheckBuildGo = readGovulncheckBuildGo

// readGovulncheckBuildGo reads the build Go of the govulncheck on PATH. The scan resolves
// govulncheck from PATH, with Draugr's own directory first, so this is the binary it runs.
func readGovulncheckBuildGo() string {
	path, err := exec.LookPath("govulncheck")
	if err != nil {
		return ""
	}
	return tools.ReadBuildGo(path)
}

// onBuildGo runs govulncheck over a module only where the Go it was built with can load it, and
// otherwise refuses that module with what to run.
//
// The go/types package compiled into govulncheck refuses a package whose language version is newer
// than the Go that built the binary, and govulncheck reports it as "package requires newer Go
// version", naming neither the module nor the fix. Checked here, before the run, the error names
// the go.mod by its path in the repository, both versions and the command that rebuilds the tool.
func onBuildGo(run func(ctx context.Context, dir string, argv []string) ([]byte, error)) func(ctx context.Context, dir string, argv []string) ([]byte, error) {
	return func(ctx context.Context, dir string, argv []string) ([]byte, error) {
		if err := checkBuildGo(govulncheckBuildGo(), dir, argv); err != nil {
			return nil, err
		}
		return run(ctx, dir, argv)
	}
}

// checkBuildGo compares the Go a module needs with built, the Go govulncheck was built with, for
// the module argv runs over (`-C <dir>`) in the checkout at root.
//
// The comparison is between language versions, go1.27 and go1.26, because that is the one go/types
// makes: a govulncheck built with go1.27.3 loads a module declaring go 1.27.9. Nothing is refused
// where the build Go or the module's go line cannot be read, because the tool's own answer is then
// the better one.
func checkBuildGo(built, root string, argv []string) error {
	i := slices.Index(argv, "-C")
	if !version.IsValid(built) || i < 0 || i+1 >= len(argv) {
		return nil
	}
	file, declared := moduleGoVersion(root, argv[i+1])
	if declared == "" || version.Compare(version.Lang(declared), version.Lang(built)) <= 0 {
		return nil
	}
	name := file
	if rel, ok := relSlash(root, file); ok {
		name = rel
	}
	fix := "Run draugr tools install govulncheck --force."
	if pin := tools.GoToolchain(govulncheckScanner); version.Compare(version.Lang(declared), version.Lang(pin)) > 0 {
		// The pin cannot load it either, so a rebuild at the pin would fail the same way.
		fix = fmt.Sprintf("Run GOTOOLCHAIN=%s draugr tools install govulncheck --force, or upgrade Draugr.",
			toolchainFor(declared))
	}
	return fmt.Errorf("govulncheck was built with %s and cannot load %s, which declares go %s. %s",
		built, name, strings.TrimPrefix(declared, "go"), fix)
}

// moduleGoVersion is the newest Go the module at dir declares, from its go.mod or the go.work that
// governs it, and the file that declares it. Empty where neither declares a Go version.
//
// The go.work is the one the go command would use: the one GOWORK names, or the nearest one above
// the module, found without leaving the checkout, and none under GOWORK=off.
func moduleGoVersion(root, dir string) (file, declared string) {
	file = filepath.Join(dir, "go.mod")
	declared = goDirective(file)
	if work := governingGoWork(root, dir); work != "" {
		if v := goDirective(work); version.Compare(v, declared) > 0 {
			return work, v
		}
	}
	if declared == "" {
		return "", ""
	}
	return file, declared
}

// governingGoWork is the go.work a build in dir reads, or "" for none.
func governingGoWork(root, dir string) string {
	switch gowork := os.Getenv("GOWORK"); gowork {
	case "off":
		return ""
	case "", "auto":
	default:
		return gowork
	}
	for d := dir; ; d = filepath.Dir(d) {
		if _, ok := relSlash(root, d); !ok {
			return ""
		}
		if _, err := os.Stat(filepath.Join(d, "go.work")); err == nil {
			return filepath.Join(d, "go.work")
		}
		if parent := filepath.Dir(d); parent == d {
			return ""
		}
	}
}

// goDirective reads the `go` line of a go.mod or go.work, as a Go version such as go1.27.1, or ""
// where the file is missing or declares none.
func goDirective(path string) string {
	raw, err := os.ReadFile(path) // #nosec G304 -- a go.mod or go.work in the checkout, or the one GOWORK names
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "go" && version.IsValid("go"+fields[1]) {
			return "go" + fields[1]
		}
	}
	return ""
}

// toolchainFor is the toolchain name for a declared Go version. A language version such as go1.28
// names no release, and its first release is go1.28.0.
func toolchainFor(declared string) string {
	if version.Lang(declared) == declared {
		return declared + ".0"
	}
	return declared
}
