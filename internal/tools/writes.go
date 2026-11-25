package tools

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/internal/draugrhome"
)

// toolWrite is one place a tool writes for itself while it runs, outside the directory Draugr
// installed it into: a database it downloads, a template set, a settings file it creates.
type toolWrite struct {
	// Var is the environment variable the tool reads to move it.
	Var string
	// Under is where it goes under DataRoot when DRAUGR_HOME is set.
	Under string
	// Default is where the tool puts it when Var is unset, or "" where that cannot be worked out.
	Default func() string
	// Stays is true for a place DRAUGR_HOME does not move, because the tool shares it with other
	// work on the machine. It is still checked, and Var is what moves it.
	Stays bool
}

// toolWrites lists, for each tool Draugr installs, what it writes as it runs and the variable that
// moves it. Each variable is the tool's own and was read from a run of the version Draugr pins.
//
// The tools that write under the data directory already, because Draugr passes them a path
// (gitleaks, retire.js, osv-scanner), are not here. Semgrep's version-check cache is not here
// either, because Draugr turns that check off.
//
// gosec and govulncheck build the code they read with the Go toolchain, which writes Go's module
// and build caches. Those stay where Go's own settings put them, so a scan shares them with
// `go build` rather than downloading every module again, and they are listed only so doctor
// checks that they take a write.
var toolWrites = map[string][]toolWrite{
	"gosec":       goCaches,
	"govulncheck": goCaches,
	"trivy":       {{Var: "TRIVY_CACHE_DIR", Under: "trivy", Default: inUserCache("trivy")}},
	"grype":       {{Var: "GRYPE_DB_CACHE_DIR", Under: filepath.Join("grype", "db"), Default: inUserCache("grype", "db")}},
	"syft":        {{Var: "SYFT_CACHE_DIR", Under: "syft", Default: inUserCache("syft")}},
	// Semgrep makes the directory these name when it is missing.
	"semgrep": {
		{Var: "SEMGREP_SETTINGS_FILE", Under: filepath.Join("semgrep", "settings.yml"), Default: inSemgrepDir("settings.yml")},
		{Var: "SEMGREP_LOG_FILE", Under: filepath.Join("semgrep", "semgrep.log"), Default: inSemgrepDir("semgrep.log")},
	},
	// The Sigstore trust root, which cosign refreshes before it verifies anything.
	"cosign": {{Var: "TUF_ROOT", Under: "cosign", Default: inHome(".sigstore", "root")}},
	"nuclei": {
		{Var: "NUCLEI_CONFIG_DIR", Under: filepath.Join("nuclei", "config"), Default: inUserConfig("nuclei")},
		{Var: "NUCLEI_TEMPLATES_DIR", Under: filepath.Join("nuclei", "templates"), Default: inHome("nuclei-templates")},
	},
}

// PointToolWritesUnderDraugrHome sets, when DRAUGR_HOME is set, the variable each installed tool
// reads for where it writes, so a scan run with a home directory it cannot write to still runs.
// A variable already set is left alone: whoever set it chose that place.
//
// For the process, and so for every tool it starts, `doctor`'s version probes and the warm-up
// before a scan included. Without DRAUGR_HOME nothing changes, and each tool keeps its own default,
// which another install of the same tool shares.
func PointToolWritesUnderDraugrHome() error {
	if !draugrhome.FromEnv() {
		return nil
	}
	root, err := DataRoot()
	if err != nil {
		return err
	}
	for _, writes := range toolWrites {
		for _, w := range writes {
			if w.Stays || os.Getenv(w.Var) != "" {
				continue
			}
			if err := os.Setenv(w.Var, filepath.Join(root, w.Under)); err != nil {
				return err
			}
		}
	}
	return nil
}

// UnderDraugrHome reports whether path is one PointToolWritesUnderDraugrHome chose, under the data
// directory DRAUGR_HOME names, so the setting that moves it is DRAUGR_HOME and not the tool's own.
func UnderDraugrHome(path string) bool {
	if !draugrhome.FromEnv() {
		return false
	}
	root, err := DataRoot()
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// Unwritable is a place a tool writes that it will not be able to.
type Unwritable struct {
	// Path is where the tool writes, as the variable or the tool's default names it.
	Path string
	// Var is the variable that moves it.
	Var string
	// Named is true where Var was set to Path by somebody other than Draugr, so Var is what to
	// change; otherwise Path is the tool's default or under DRAUGR_HOME, and DRAUGR_HOME is.
	Named bool
	// Stays is true where DRAUGR_HOME does not move Path, so Var is what to change whether or not
	// anybody set it.
	Stays bool
}

// UnwritableFor returns the first place the tool writes as it runs that cannot be written, or nil
// when every one can or the tool writes nowhere Draugr knows of. A place that does not exist yet
// is judged by the nearest directory above it that does, since the tool makes the rest.
//
// Tested by writing, not by reading permission bits: a read-only mount, an ACL and running as root
// each make the bits say something other than what a write would do.
func UnwritableFor(tool string) *Unwritable {
	for _, w := range toolWrites[tool] {
		path := os.Getenv(w.Var)
		if path == "" && w.Default != nil {
			path = w.Default()
		}
		if path == "" {
			continue
		}
		if !canWrite(path) {
			return &Unwritable{
				Path: path, Var: w.Var, Stays: w.Stays,
				Named: os.Getenv(w.Var) != "" && !UnderDraugrHome(path),
			}
		}
	}
	return nil
}

// canWrite reports whether path, or the nearest existing directory above it, takes a write.
func canWrite(path string) bool {
	p := filepath.Clean(path)
	for {
		info, err := os.Stat(p) // #nosec G703 -- a tool's write location, from its own variable or default, only tested
		switch {
		case err == nil && info.IsDir():
			f, err := os.CreateTemp(p, ".draugr-write-check-*")
			if err != nil {
				return false
			}
			_ = f.Close()
			_ = os.Remove(f.Name()) // #nosec G703 -- the file CreateTemp just made
			return true
		case err == nil:
			// An existing file, such as a settings file, is opened for writing without changing it.
			f, err := os.OpenFile(p, os.O_WRONLY, 0) // #nosec G304 G703 -- a tool's own settings or log path, opened to test it takes a write
			if err != nil {
				return false
			}
			_ = f.Close()
			return true
		case !errors.Is(err, fs.ErrNotExist):
			return false
		}
		parent := filepath.Dir(p)
		if parent == p {
			return false
		}
		p = parent
	}
}

// goCaches are the Go toolchain's module and build caches, which gosec and govulncheck fill as they
// load the code. Where Go puts each is what `go env` prints, which applies GOPATH, the user cache
// directory and any `go env -w` setting the way the toolchain does.
var goCaches = []toolWrite{
	{Var: "GOMODCACHE", Default: goEnv("GOMODCACHE"), Stays: true},
	{Var: "GOCACHE", Default: goEnv("GOCACHE"), Stays: true},
}

// goEnvTimeout bounds `go env`, which reads only the environment and Go's own settings file.
const goEnvTimeout = 10 * time.Second

// goEnv is the value `go env` prints for name, or "" where no go is on PATH, it fails, or the
// value is "off", which for GOCACHE means Go writes no build cache.
func goEnv(name string) func() string {
	return func() string {
		ctx, cancel := context.WithTimeout(context.Background(), goEnvTimeout)
		defer cancel()
		out, err := exec.CommandContext(ctx, "go", "env", name).Output() // #nosec G204 -- a fixed variable name
		if err != nil {
			return ""
		}
		v := strings.TrimSpace(string(out))
		if v == "off" {
			return ""
		}
		return v
	}
}

func inUserCache(parts ...string) func() string {
	return func() string {
		dir, err := os.UserCacheDir()
		if err != nil {
			return ""
		}
		return filepath.Join(append([]string{dir}, parts...)...)
	}
}

func inUserConfig(parts ...string) func() string {
	return func() string {
		dir, err := os.UserConfigDir()
		if err != nil {
			return ""
		}
		return filepath.Join(append([]string{dir}, parts...)...)
	}
}

func inHome(parts ...string) func() string {
	return func() string {
		dir, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		return filepath.Join(append([]string{dir}, parts...)...)
	}
}

// inSemgrepDir is a file in Semgrep's own directory: .semgrep under XDG_CONFIG_HOME when that
// names an existing directory, and under the home directory otherwise, which is the rule
// Semgrep's env.py applies.
func inSemgrepDir(name string) func() string {
	return func() string {
		parent := os.Getenv("XDG_CONFIG_HOME")
		if info, err := os.Stat(parent); parent == "" || err != nil || !info.IsDir() { // #nosec G703 -- XDG_CONFIG_HOME, only asked whether it is a directory
			home, err := os.UserHomeDir()
			if err != nil {
				return ""
			}
			parent = home
		}
		return filepath.Join(parent, ".semgrep", name)
	}
}
