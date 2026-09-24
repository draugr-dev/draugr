package sealed

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// Image is the container the sealed tier runs in, pinned by digest. It supplies only the root of a
// filesystem: /usr, /etc and /opt are the host's, mounted read-only, so the tools, interpreters and
// libraries inside are the ones installed on the machine running the test, and the only thing the
// container takes away is the network.
const Image = "ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3"

// Container describes one sealed run.
type Container struct {
	// Work is the one writable directory, mounted at the same path inside. The run's HOME is
	// Work/home, so every cache and dataset Draugr reads is the one the test put there.
	Work string
	// HostHome is the invoking user's home directory, mounted read-only for the tools installed
	// under it.
	HostHome string
	// Path is the PATH inside the container.
	Path string
	// Extra are further read-only mounts, such as a GOROOT outside the directories already mounted.
	Extra []string
	// Env is added to the environment inside the container.
	Env map[string]string
	// UID and GID are who the container runs as, so what it writes belongs to the invoking user.
	UID, GID int
}

// Home is the HOME a sealed run sees.
func (c Container) Home() string { return filepath.Join(c.Work, "home") }

// Args is the docker command line that runs argv sealed, starting in dir.
func (c Container) Args(dir string, argv ...string) []string {
	args := []string{
		"run", "--rm", "--network", "none",
		"--user", fmt.Sprintf("%d:%d", c.UID, c.GID),
		"--workdir", dir,
	}
	mounts := []string{"/usr", "/etc", "/opt", c.HostHome}
	mounts = append(mounts, c.Extra...)
	seen := map[string]bool{}
	for _, m := range mounts {
		if m == "" || seen[m] || covered(m, mounts) {
			continue
		}
		seen[m] = true
		args = append(args, "--volume", m+":"+m+":ro")
	}
	args = append(args, "--volume", c.Work+":"+c.Work)

	env := map[string]string{
		"HOME":        c.Home(),
		"PATH":        c.Path,
		"GOCACHE":     filepath.Join(c.Work, "gocache"),
		"GOPATH":      filepath.Join(c.Work, "gopath"),
		"GOPROXY":     "off",
		"GOTOOLCHAIN": "local",
		"NO_COLOR":    "1",
		"COLUMNS":     "200",
	}
	for k, v := range c.Env {
		env[k] = v
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		args = append(args, "--env", k+"="+env[k])
	}
	args = append(args, Image)
	return append(args, argv...)
}

// covered reports whether m sits inside another mount in the list, which docker would otherwise
// mount twice.
func covered(m string, mounts []string) bool {
	for _, other := range mounts {
		if other != "" && other != m && strings.HasPrefix(m, strings.TrimSuffix(other, "/")+"/") {
			return true
		}
	}
	return false
}

// Command is Args as a command ready to run.
func (c Container) Command(dir string, argv ...string) *exec.Cmd {
	return exec.Command("docker", c.Args(dir, argv...)...) // #nosec G204 -- the test's own argv
}

// HostContainer describes a sealed run over work using the invoking user's tools: PATH as it is,
// behind the tools Draugr installed and the directory of the semgrep on PATH.
//
// Semgrep's CLI runs a second program, pysemgrep, by looking it up on PATH. Beside the semgrep
// binary is the one from the same installation; a stale one elsewhere on PATH belongs to another
// interpreter, which the host may find through its own home directory and the container cannot.
func HostContainer(work string) (Container, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Container{}, err
	}
	// The tools `draugr tools install` put under the invoking user's home, which a scan would find
	// through its own HOME and cannot here, because HOME is the run's.
	path := filepath.Join(home, ".draugr", "bin") + string(os.PathListSeparator) + os.Getenv("PATH")
	if sg, err := exec.LookPath("semgrep"); err == nil {
		if resolved, err := filepath.EvalSymlinks(sg); err == nil {
			path = filepath.Dir(resolved) + string(os.PathListSeparator) + path
		}
	}
	var extra []string
	if goBin, err := exec.LookPath("go"); err == nil {
		if resolved, err := filepath.EvalSymlinks(goBin); err == nil {
			extra = append(extra, filepath.Dir(filepath.Dir(resolved)))
		}
	}
	return Container{
		Work: work, HostHome: home, Path: path, Extra: extra,
		UID: os.Getuid(), GID: os.Getgid(),
	}, nil
}
