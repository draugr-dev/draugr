package scanners

import (
	"bufio"
	"cmp"
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

// trivyModuleNotLoaded is the message Trivy logs at ERROR for a module it could not load,
// unchanged from 0.69.3 to 0.76.1. The period is part of the match: at debug level Trivy also logs
// `Failed to load module from .terraform cache` for a module it then goes on to fetch, and that
// module was loaded.
const trivyModuleNotLoaded = "Failed to load module."

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

// Trivy evaluates the modules a module calls in rounds, and a round ends at the first call whose
// inputs changed, so each round evaluates one call no earlier round did. The rounds are capped, at
// 32 in every release from 0.69.3 to 0.76.1, and a module calling more modules than the rounds
// reach has the rest loaded and never evaluated. Their resources are never checked and Trivy exits
// 0. Only its debug log shows the gap, as a call loaded with no line evaluating it, in a loop that
// never logged finishing.
//
// So the scan runs with --debug, and each root module with calls left unevaluated is reported
// unread, with how many calls it makes and how many were evaluated. Both counts come from the log
// rather than from the cap, because a call evaluated again after another changed its inputs spends
// a round too, and the cap is Trivy's to change.

// The messages Trivy's Terraform scanner logs around a module's calls, unchanged from 0.69.3 to
// 0.76.1, each without its `[terraform evaluator]` or `[terraform scanner]` prefix.
const (
	trivyScanningRoot   = "Scanning root module"
	trivyModuleLoaded   = "Loaded module"
	trivyCallsStarted   = "Starting submodules evaluation..."
	trivyCallsFinished  = "All submodules are evaluated"
	trivyCallsEnded     = "Starting post-submodule evaluation..."
	trivyCallEvaluating = "Evaluating submodule"
)

// trivyLogField is one field of a Trivy log line, `key="quoted"` or `key=bare`.
var trivyLogField = regexp.MustCompile(`(\w+)=("(?:[^"\\]|\\.)*"|\S*)`)

// trivyLogEntry splits a line of Trivy's log, `time<TAB>level<TAB>[component] message<TAB>fields`,
// into its message without the component and its fields in order. Order matters: a module
// evaluated inside another carries one `module` field for each module above it.
func trivyLogEntry(line string) (msg string, fields [][2]string) {
	parts := strings.SplitN(line, "\t", 4)
	if len(parts) < 3 {
		return "", nil
	}
	msg = parts[2]
	if strings.HasPrefix(msg, "[") {
		if i := strings.Index(msg, "] "); i > 0 {
			msg = msg[i+2:]
		}
	}
	if len(parts) == 4 {
		for _, m := range trivyLogField.FindAllStringSubmatch(parts[3], -1) {
			v := m[2]
			if u, err := strconv.Unquote(v); err == nil {
				v = u
			}
			fields = append(fields, [2]string{m[1], v})
		}
	}
	return msg, fields
}

// trivyLogValue is the value of the first field named key, or "".
func trivyLogValue(fields [][2]string, key string) string {
	for _, f := range fields {
		if f[0] == key {
			return f[1]
		}
	}
	return ""
}

// trivyCallLoop is what Trivy's log says about the calls one module makes. The module is named by
// its root module's directory and the chain of calls from the root to it.
type trivyCallLoop struct {
	root  string
	chain []string
	// loaded are the calls loaded, in the order logged.
	loaded    []string
	seen      map[string]bool
	evaluated map[string]bool
	// failed are the calls Trivy could not load, by location: reported unread by
	// trivyUnloadedModules, and counted here among the calls the module makes.
	failed map[string]bool
	// open is a loop of rounds started and not ended, finished one that logged evaluating every
	// call, and ranOut a loop that ended without logging that.
	open, finished, ranOut bool
}

// trivyUnevaluatedModules reads Trivy's debug log for the modules whose calls it stopped evaluating
// with some left, as one unread input per root module directory, sorted by path.
func trivyUnevaluatedModules(stderr []byte, dir string) []sarif.Input {
	var loops []*trivyCallLoop
	byKey := map[string]*trivyCallLoop{}
	root := "."
	sc := bufio.NewScanner(strings.NewReader(string(stderr)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		msg, fields := trivyLogEntry(sc.Text())
		notLoaded := strings.HasPrefix(msg, trivyModuleNotLoaded)
		switch {
		case msg == trivyScanningRoot:
			// Trivy scans one root module at a time, and every line until the next of these is
			// about this one.
			root = cmp.Or(repoRelPath(dir, trivyLogValue(fields, "file_path")), ".")
			continue
		case notLoaded, msg == trivyModuleLoaded, msg == trivyCallsStarted, msg == trivyCallsFinished,
			msg == trivyCallsEnded, msg == trivyCallEvaluating:
		default:
			continue
		}
		var chain []string
		for _, f := range fields {
			if f[0] == "module" {
				chain = append(chain, f[1])
			}
		}
		key := root + "\x00" + strings.Join(chain, "\x00")
		l := byKey[key]
		if l == nil {
			l = &trivyCallLoop{root: root, chain: chain, seen: map[string]bool{},
				evaluated: map[string]bool{}, failed: map[string]bool{}}
			byKey[key] = l
			loops = append(loops, l)
		}
		name := trivyLogValue(fields, "name")
		switch {
		case notLoaded:
			l.failed[trivyLogValue(fields, "loc")] = true
		case msg == trivyModuleLoaded:
			if !l.seen[name] {
				l.seen[name] = true
				l.loaded = append(l.loaded, name)
			}
		case msg == trivyCallEvaluating:
			l.evaluated[name] = true
		case msg == trivyCallsStarted:
			l.open, l.finished = true, false
		case msg == trivyCallsFinished:
			l.finished = true
		case msg == trivyCallsEnded:
			if l.open && !l.finished {
				l.ranOut = true
			}
			l.open = false
		}
	}
	var out []sarif.Input
	for _, l := range loops {
		if reason := l.unevaluated(); reason != "" {
			out = append(out, sarif.Input{Path: l.root, Unread: reason})
		}
	}
	return mergeUnread(out)
}

// unevaluated says how far the loop got and which calls it left, or "" when it finished or left
// none.
func (l *trivyCallLoop) unevaluated() string {
	if !l.ranOut {
		return ""
	}
	var missing []string
	for _, name := range l.loaded {
		if !l.evaluated[name] {
			missing = append(missing, strconv.Quote(name))
		}
	}
	if len(missing) == 0 {
		return ""
	}
	// A module below the root is named by its address, the form `terraform state list` prints.
	where := ""
	if len(l.chain) > 1 {
		where = " in module." + strings.Join(l.chain[1:], ".module.")
	}
	// The counts first, so a reason cut to fit a column keeps them.
	return fmt.Sprintf("Trivy evaluated %d of %d module calls%s, not %s",
		len(l.loaded)-len(missing), len(l.loaded)+len(l.failed), where, strings.Join(missing, ", "))
}

// mergeUnread folds the unread inputs naming one path into one, their reasons joined, and sorts
// them by path. An input is keyed by its path, so two for one path would be folded downstream into
// whichever sorted first, and the other's reason lost.
func mergeUnread(inputs []sarif.Input) []sarif.Input {
	var out []sarif.Input
	at := map[string]int{}
	for _, in := range inputs {
		if i, ok := at[in.Path]; ok {
			out[i].Unread += "; " + in.Unread
			continue
		}
		at[in.Path] = len(out)
		out = append(out, in)
	}
	slices.SortStableFunc(out, func(a, b sarif.Input) int { return strings.Compare(a.Path, b.Path) })
	return out
}
