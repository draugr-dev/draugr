package scanners

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/draugr-dev/draugr/internal/netpolicy"
	"github.com/draugr-dev/draugr/internal/toolexec"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// Trivy evaluates a Terraform module block by fetching the module from its `source`: the registry,
// a git host, an archive URL. A module it cannot fetch is logged at ERROR and left out, and the
// scan exits 0 with the resources that module would have declared unchecked. Nothing in the report
// says so, and a module it could not reach reads the same as one with nothing wrong in it.
//
// So the scan runs without --quiet, which would drop that line too, and its log is read for each
// module block Trivy could not load. Each is reported unread, the way a dependency file no scanner
// took packages from is.

// trivyModuleNotLoaded is the message Trivy logs for a module it could not load. Unchanged from
// 0.69.3, the release Draugr installs, to 0.74.0.
const trivyModuleNotLoaded = "Failed to load module"

// trivyModuleLoc is the log field naming the module block, as `<path>:<first>-<last>`, the path
// relative to the scanned directory.
var trivyModuleLoc = regexp.MustCompile(`\bloc="([^"]+):(\d+)-\d+"`)

// terraformModuleBlock is the line that opens a module block, with the module's name.
var terraformModuleBlock = regexp.MustCompile(`^\s*module\s+"([^"]+)"`)

// offlineModuleEnv is the environment a misconfiguration scan runs in under --offline.
//
// Trivy has no switch that stops it fetching modules. The proxy variables send every HTTP fetch to
// a port nothing listens on, so it fails at once rather than reaching the host. Trivy's registry
// and archive downloads honor them, as does git over HTTPS. GIT_ALLOW_PROTOCOL refuses git's other
// transports, SSH among them, which no proxy variable reaches. The module is then logged as not
// loaded and reported unread, rather than fetched from a network the run was told not to use.
var offlineModuleEnv = []string{
	"HTTPS_PROXY=http://127.0.0.1:0", "https_proxy=http://127.0.0.1:0",
	"HTTP_PROXY=http://127.0.0.1:0", "http_proxy=http://127.0.0.1:0",
	"NO_PROXY=", "no_proxy=",
	"GIT_ALLOW_PROTOCOL=file",
}

// execWithStderr is toolexec.RunWithStderr, a var so a test can substitute the exec without a
// Trivy on PATH and still reach the retry and the environment trivyConfigExec adds around it.
var execWithStderr = toolexec.RunWithStderr

// trivyConfigExec runs Trivy with its log kept beside its report, retrying while another job in the
// run holds its cache.
func trivyConfigExec(ctx context.Context, dir string, argv []string) ([]byte, []byte, error) {
	var env []string
	if netpolicy.Offline() {
		env = offlineModuleEnv
	}
	var stderr []byte
	out, err := retryLockedCache(ctx, "trivy", func() ([]byte, error) {
		var out []byte
		var err error
		out, stderr, err = execWithStderr(ctx, dir, argv, env)
		return out, err
	})
	return out, stderr, err
}

// trivyUnloadedModules reads Trivy's log for the module blocks it could not load, as one unread
// input per file, sorted by path.
//
// Per file, naming each block in it, because a file can call several modules and an input is keyed
// by its path: two inputs for one file would be folded into whichever sorted first. A block is
// named by its label, `module "vpc"`, which is what a reader searches the file for, or by its line
// where the file cannot be read. A line that says a module failed and names no block is still
// reported, against the repository root, because leaving it out would report a clean scan of a tree
// Trivy did not finish reading.
func trivyUnloadedModules(stderr []byte, dir string) []sarif.Input {
	type block struct {
		line  int
		label string
	}
	byFile := map[string][]block{}
	seen := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(string(stderr)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if !strings.Contains(line, trivyModuleNotLoaded) {
			continue
		}
		path, n := ".", 0
		if m := trivyModuleLoc.FindStringSubmatch(line); m != nil {
			path = repoRelPath(dir, m[1])
			n, _ = strconv.Atoi(m[2])
		}
		// A child module called from two root modules is evaluated, and fails, once for each.
		key := fmt.Sprint(path, "\x00", n)
		if seen[key] {
			continue
		}
		seen[key] = true
		byFile[path] = append(byFile[path], block{n, terraformModuleLabel(dir, path, n)})
	}
	paths := make([]string, 0, len(byFile))
	for p := range byFile {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	var out []sarif.Input
	for _, p := range paths {
		blocks := byFile[p]
		slices.SortFunc(blocks, func(a, b block) int { return a.line - b.line })
		labels := make([]string, len(blocks))
		for i, b := range blocks {
			labels[i] = b.label
		}
		reason := "module " + labels[0] + " not loaded"
		if len(labels) > 1 {
			reason = "modules " + strings.Join(labels, ", ") + " not loaded"
		}
		out = append(out, sarif.Input{Path: p, Unread: reason})
	}
	return out
}

// terraformModuleLabel names the module block opening at line n of path: its label quoted, or
// `at line n` when the line is not a module block or the file cannot be read.
func terraformModuleLabel(dir, path string, n int) string {
	if n < 1 {
		return "block"
	}
	byLine := fmt.Sprintf("at line %d", n)
	if !filepath.IsLocal(path) {
		return byLine
	}
	f, err := os.Open(filepath.Join(dir, path)) // #nosec G304 -- a path inside the checkout, checked above
	if err != nil {
		return byLine
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for i := 1; sc.Scan(); i++ {
		if i < n {
			continue
		}
		if m := terraformModuleBlock.FindStringSubmatch(sc.Text()); m != nil {
			return strconv.Quote(m[1])
		}
		break
	}
	return byLine
}
