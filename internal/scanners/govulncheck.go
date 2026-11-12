package scanners

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/build"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/internal/tools"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// govulncheckScanner is the scanner name, and the descriptor key that enables it.
const govulncheckScanner = "govulncheck"

// NewGovulncheck returns the govulncheck scanner: reachability analysis for Go modules.
//
// It answers a different question from the other sca scanners. Trivy reads a manifest and says
// which dependencies have known vulnerabilities; govulncheck builds a call graph from the
// packages that are actually in the build and says which of those vulnerabilities this code can
// reach. The two are complementary rather than competing, which is why what this produces is
// folded onto existing findings rather than reported alongside them.
func NewGovulncheck() plugin.Scanner {
	s := newRepoScannerPerModule(
		plugin.ScannerInfo{
			Name:           govulncheckScanner,
			Origin:         "Go team",
			Data:           govulncheckData,
			Reachability:   true,
			Binary:         "govulncheck",
			Controls:       []string{"sca"},
			TargetKinds:    []plugin.TargetKind{plugin.TargetRepository},
			ConfigSchema:   json.RawMessage(noScannerOptions),
			ModuleManifest: "go.mod",
			// govulncheck loads a module's packages with `go`, whose compile processes fill the
			// bound each tool runs under, so it takes its turn with every other Go package load.
			Exclusive: plugin.ExclusiveGoPackageLoad,
		},
		govulncheckArgs,
		parseGovulncheck,
	)
	s.cacheVersion = govulncheckCacheVersion
	s.preflight = func(ctx context.Context, _ plugin.Config) error { return govulncheckPreflight(ctx) }
	s.prewarm = refreshGovulnDB
	s.run = onRuntime(s.info.Binary, onBuildGo(onUnloaded(onGoWork(inModuleDir(execArgvInDirWithEnv)))))
	return s
}

// inModuleDir runs govulncheck with the module its argv names (`-C <module>`) as its working
// directory.
//
// govulncheck decides which standard-library advisories apply from `go env GOVERSION`, which it runs
// in its own working directory rather than in the module `-C` names. The go command there picks the
// toolchain from the go.mod, or go.work, it finds, so run from the checkout root the root module's
// `go` line, or no module's at all, would set the standard-library version for every module in the
// repository. Run from the module, it is the Go that module builds with.
func inModuleDir(run func(ctx context.Context, dir string, argv, env []string) ([]byte, error)) func(ctx context.Context, dir string, argv, env []string) ([]byte, error) {
	return func(ctx context.Context, dir string, argv, env []string) ([]byte, error) {
		if i := slices.Index(argv, "-C"); i >= 0 && i+1 < len(argv) {
			dir = argv[i+1]
		}
		return run(ctx, dir, argv, env)
	}
}

// lookRuntime finds a runtime on PATH. A variable so a test can take one off it.
var lookRuntime = exec.LookPath

// onRuntime runs a tool only where the runtime the tool catalog says it runs on is on PATH, and
// otherwise refuses with that runtime named.
//
// The tool's own answer names a symptom or nothing at all. govulncheck loads a module's packages
// with `go`, and with no `go` it reports "no go.mod file" over a module that has one; gosec exits 0
// having analyzed nothing. Checked where the tool runs rather than before the checkout, so a tree
// holding no module, where nothing runs, still reports that it holds none.
func onRuntime(binary string, run func(ctx context.Context, dir string, argv []string) ([]byte, error)) func(ctx context.Context, dir string, argv []string) ([]byte, error) {
	rt := tools.Catalog()[binary].Runtime
	if rt.Binary == "" {
		return run
	}
	return func(ctx context.Context, dir string, argv []string) ([]byte, error) {
		if _, err := lookRuntime(rt.Binary); err != nil {
			return nil, fmt.Errorf("%s needs %s, and no `%s` is on PATH", binary, rt.Name, rt.Binary)
		}
		return run(ctx, dir, argv)
	}
}

// govulncheckCacheVersion is the scanner and database version a cached result was made with.
// Against a local copy the probe reads that copy, so refreshing it invalidates the cache.
func govulncheckCacheVersion(ctx context.Context) string {
	choice := resolveGovulnDB()
	if choice.url == "" {
		return sharedGovulncheckVersion.version(ctx)
	}
	return localGovulncheckVersion(choice.url).version(ctx)
}

var (
	localVersionMu     sync.Mutex
	localVersionProbes = map[string]*toolVersionProbe{}
)

// localGovulncheckVersion is the version probe for one local database, created on first use.
func localGovulncheckVersion(url string) *toolVersionProbe {
	localVersionMu.Lock()
	defer localVersionMu.Unlock()
	if p, ok := localVersionProbes[url]; ok {
		return p
	}
	p := &toolVersionProbe{
		argv: []string{"govulncheck", "-db", url, "-version"}, extract: govulncheckVersion, run: execArgvCombined,
	}
	localVersionProbes[url] = p
	return p
}

// govulncheckArgs builds one `govulncheck -C <module> -format json <patterns>` per Go module in the
// checkout that holds a package to build (govulncheckModules), the patterns being `./...` unless
// entry narrows them (govulncheckPatterns).
//
// Per module rather than once at the root, because a repository is not required to be one. A
// polyglot repository keeps its Go service in a subdirectory, a monorepo keeps several, and
// running once at the root answers for whichever the root happens to be. Or fails outright when
// the root holds no go.mod, which would fail the whole control for a repository that simply is
// not Go.
//
// No commands when there is no Go module. That is reported rather than passed off as a clean
// result: see the provenance parseGovulncheck writes.
//
// No flag makes it fail on findings, so there is no exit code to neutralize the way Trivy's
// --exit-code 0 does; in JSON mode it reports and exits 0.
//
// Deliberately not -test. Analyzing tests would report vulnerabilities reachable only from code
// that never ships, and the finding a developer cannot act on is the one that teaches them to
// ignore the report.
// -db only for a local copy that passed its checks (resolveGovulnDB). govulncheck reports "No
// vulnerabilities found" and exits 0 against an empty or unreadable database, so a mirror that was
// never populated, or one that went stale, would read as a clean result; the checks are what make
// a local copy safe to pass. Without one, govulncheck queries vuln.go.dev, and a machine with no
// route to it is refused before anything runs.
func govulncheckArgs(dir string, entry []string, _ plugin.Config) [][]string {
	db := resolveGovulnDB().url
	mods := goModuleDirs(dir)
	var out [][]string
	for _, mod := range govulncheckModules(dir) {
		argv := []string{"govulncheck", "-C", mod}
		if db != "" {
			argv = append(argv, "-db", db)
		}
		argv = append(argv, "-format", "json")
		out = append(out, append(argv, govulncheckPatterns(dir, mod, mods, entry)...))
	}
	return out
}

// govulncheckPatterns are the packages one module's run starts from: the ones entry holds, or the
// whole module when entry holds none of them.
//
// Components carved out of one module share its checkout, because a package does not type-check
// without the packages it imports, and each is analyzed from its own code. Run over the whole
// module, govulncheck reports one call path per vulnerable function, so a component whose code
// never makes the call could only be told unknown. Run from the component's own packages, the
// same silence is a sound unreachable, and a call only another component makes is not evidence
// about this one.
//
// entry is repository-relative, as the descriptor writes paths. A path in a nested module belongs
// to that module's run, a directory with no Go package in it starts nothing, and a file starts
// the package it is in. A path holding the whole module, or none of it, leaves `./...`.
func govulncheckPatterns(root, mod string, mods, entry []string) []string {
	whole := []string{"./..."}
	modRel, ok := relSlash(root, mod)
	if !ok || len(entry) == 0 {
		return whole
	}
	var modules []string
	for _, m := range mods {
		if rel, ok := relSlash(root, m); ok {
			modules = append(modules, rel)
		}
	}
	var patterns []string
	for _, e := range entry {
		p := path.Clean(strings.TrimPrefix(filepath.ToSlash(e), "./"))
		if p == "." || p == modRel || (modRel != "." && strings.HasPrefix(modRel, p+"/")) {
			return whole
		}
		if m, ok := git.InnermostModule(p, modules); !ok || m != modRel {
			continue
		}
		inMod := p
		if modRel != "." {
			inMod = strings.TrimPrefix(p, modRel+"/")
		}
		info, err := os.Stat(filepath.Join(root, filepath.FromSlash(p)))
		switch {
		case err != nil:
			continue
		case info.IsDir():
			if holdsGoPackage(filepath.Join(root, filepath.FromSlash(p))) {
				patterns = append(patterns, "./"+inMod+"/...")
			}
		case strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go"):
			pkg := path.Dir(inMod)
			if pkg != "." {
				pkg = "./" + pkg
			}
			patterns = append(patterns, pkg)
		}
	}
	if len(patterns) == 0 {
		return whole
	}
	slices.Sort(patterns)
	return slices.Compact(patterns)
}

// relSlash is target relative to root, slash-separated, "." for root itself.
func relSlash(root, target string) (string, bool) {
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return "", false
	}
	return filepath.ToSlash(rel), true
}

// holdsGoPackage reports whether dir, or a directory under it in the same module, holds a Go file
// that is part of a build. A pattern matching no package fails the run, so a directory of
// templates or a frontend is no place to start from.
//
// Part of a build under the build constraints the go command applies by default, on this machine,
// with any `-tags` GOFLAGS sets: a file behind `//go:build tools` or `//go:build ignore`, or one for
// another platform, is not. A module of tool imports alone holds nothing to build, and govulncheck
// fails over it with "no packages matched". Directories `./...` passes by, vendor/, testdata/ and
// any whose name starts with `.` or `_`, are passed by here too.
func holdsGoPackage(dir string) bool {
	ctx := build.Default
	ctx.BuildTags = goflagsTags(os.Getenv("GOFLAGS"))
	found := false
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return filepath.SkipDir
		case d.IsDir():
			switch d.Name() {
			case "vendor", "testdata", ".git":
				return filepath.SkipDir
			}
			if p != dir {
				if strings.HasPrefix(d.Name(), ".") || strings.HasPrefix(d.Name(), "_") {
					return filepath.SkipDir
				}
				if _, err := os.Stat(filepath.Join(p, "go.mod")); err == nil {
					return filepath.SkipDir
				}
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		// A file whose constraints cannot be read is counted, so govulncheck runs and says why.
		if match, err := ctx.MatchFile(filepath.Dir(p), name); match || err != nil {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

// goflagsTags reads the build tags a GOFLAGS value sets with `-tags` or `--tags`, comma-separated,
// as the go command reads them.
func goflagsTags(goflags string) []string {
	var tags []string
	for _, f := range strings.Fields(goflags) {
		v, ok := strings.CutPrefix(strings.TrimPrefix(strings.TrimPrefix(f, "-"), "-"), "tags=")
		if !ok || !strings.HasPrefix(f, "-") {
			continue
		}
		tags = nil
		for _, t := range strings.Split(v, ",") {
			if t = strings.TrimSpace(t); t != "" {
				tags = append(tags, t)
			}
		}
	}
	return tags
}

// govulncheckModules lists the modules govulncheck runs over: each one goModuleDirs finds that
// holds a package to build. A module with nothing to build is passed by without a word, because
// there is no code in it for a call graph to start from.
func govulncheckModules(root string) []string {
	var out []string
	for _, mod := range goModuleDirs(root) {
		if holdsGoPackage(mod) {
			out = append(out, mod)
		}
	}
	return out
}

// goModuleDirs lists the directories under root holding a go.mod, outermost first.
//
// Nested modules are still visited: a module inside another is its own build with its own
// dependency graph, and the outer one's analysis says nothing about it. Vendored trees and
// testdata are not. Vendor/ is a copy of somebody else's modules, and testdata is by convention
// not part of the build.
func goModuleDirs(root string) []string {
	var out []string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable directory is not a reason to fail the scan
		}
		if d.IsDir() {
			switch d.Name() {
			case "vendor", "testdata", ".git":
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == "go.mod" {
			out = append(out, filepath.Dir(path))
		}
		return nil
	})
	sort.Strings(out)
	return out
}

// govulncheckMessage is one message in govulncheck's output stream.
//
// The stream is concatenated JSON objects rather than one document or one object per line, so it
// is decoded with a streaming decoder in a loop. Each message carries exactly one of these.
type govulncheckMessage struct {
	Config  *govulncheckConfig  `json:"config,omitempty"`
	SBOM    *govulncheckSBOM    `json:"SBOM,omitempty"`
	OSV     *govulncheckOSV     `json:"osv,omitempty"`
	Finding *govulncheckFinding `json:"finding,omitempty"`
	// Unloaded is Draugr's, never govulncheck's: written in place of a run that could not load its
	// module (see onUnloaded), so the stream still holds one run per module.
	Unloaded *govulncheckUnloaded `json:"draugrUnloaded,omitempty"`
}

// govulncheckConfig is the run's own account of what it was able to do.
type govulncheckConfig struct {
	// ScanLevel is "symbol", "package" or "module". Only "symbol" supports a claim that
	// something is unreachable; the others cannot see a call.
	ScanLevel string `json:"scan_level"`
	// ScanMode is "source" or "binary".
	ScanMode string `json:"scan_mode"`
}

// govulncheckSBOM lists what the analysis actually covered.
//
// The field that makes an unreachable verdict safe to state. A module missing from this list was
// never analyzed, whatever the reason. And "we did not look" must not be reported as "nothing
// reaches it".
type govulncheckSBOM struct {
	// Roots are the packages the run's patterns matched. The module holding them is how a run is
	// matched to the go.mod it came from.
	Roots   []string `json:"roots"`
	Modules []struct {
		Path    string `json:"path"`
		Version string `json:"version"`
	} `json:"modules"`
}

// govulncheckOSV is an advisory the run considered. Most are never referenced by a finding;
// the stream carries the slice of the database that was relevant to the build.
type govulncheckOSV struct {
	ID      string   `json:"id"`
	Summary string   `json:"summary"`
	Aliases []string `json:"aliases"`
	// Affected carries the vulnerable symbols, which are worth reporting whether or not any of
	// them is called: they are what makes an unreachable verdict checkable by hand.
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		EcosystemSpecific struct {
			Imports []struct {
				Path    string   `json:"path"`
				Symbols []string `json:"symbols"`
			} `json:"imports"`
		} `json:"ecosystem_specific"`
	} `json:"affected"`
}

// govulncheckFinding is one vulnerability at one granularity.
//
// The same advisory is reported more than once, once for the module being in the build, once for
// the vulnerable package being imported, and once per call path when a vulnerable symbol is
// actually called. The three are distinguished only by how much of Trace is filled in, so
// reachability is derived from the set of a vulnerability's findings rather than read off any one
// of them.
type govulncheckFinding struct {
	OSV          string             `json:"osv"`
	FixedVersion string             `json:"fixed_version"`
	Trace        []govulncheckFrame `json:"trace"`
}

// govulncheckFrame is one entry in a finding's trace. Traces are ordered callee first.
type govulncheckFrame struct {
	Module   string `json:"module"`
	Version  string `json:"version"`
	Package  string `json:"package"`
	Function string `json:"function"`
	// Receiver is the receiver's type where the function is a method, "*Writer" for Close on a
	// *Writer. Without it two methods of one name read as the same call.
	Receiver string `json:"receiver"`
	Position *struct {
		Filename string `json:"filename"`
		Line     int    `json:"line"`
	} `json:"position"`
}

// parseGovulncheck converts govulncheck's JSON stream into SARIF results carrying reachability.
//
// One result per (advisory alias, module), because that is the shape the rest of the pipeline
// already speaks: an advisory with three CVEs is three findings to every other scanner, and
// emitting one would leave two of them with no reachability while looking like a complete answer.
func parseGovulncheck(out []byte, dir string, _ plugin.Config) (sarif.Report, error) {
	return parseGovulncheckAt(out, dir, time.Now())
}

// parseGovulncheckAt is parseGovulncheck with the moment of the analysis passed in rather than read
// from the wall clock, so a test can fix the day a verdict is dated.
func parseGovulncheckAt(out []byte, dir string, now time.Time) (sarif.Report, error) {
	var modules []string
	if dir != "" {
		modules = govulncheckModules(dir)
	}
	if len(out) == 0 {
		// Silence over a tree that holds modules is runs that wrote nothing, not a tree with none.
		if len(modules) > 0 {
			return sarif.Report{}, fmt.Errorf("govulncheck wrote 0 runs for %d modules", len(modules))
		}
		coverage := "no go.mod found, so nothing here carries a verdict"
		if dir != "" && len(goModuleDirs(dir)) > 0 {
			coverage = "no Go package builds here under the default build tags"
		}
		// No module was found, so nothing ran. Reported rather than returned as a clean result:
		// a tree this analyzer could not answer for must not be indistinguishable from one where
		// it looked and found everything unreachable. The findings keep no verdict, which is the
		// honest outcome, and the report says why there is none.
		//
		// Not a claim about the repository. A component scopes a repository by paths, so one
		// repository is scanned as several trees, and this is about the tree it was given. The
		// report prints it only where the analyzer decided nothing at all, so it never sits beside
		// a count of what it decided somewhere else.
		return sarif.Report{
			Tool: govulncheckScanner,
			Provenance: []sarif.Provenance{{
				Tool: govulncheckScanner,
				Fields: []sarif.Field{{
					Key:   "coverage",
					Value: coverage,
				}},
			}},
		}, nil
	}

	msgs, err := decodeGovulncheckStream(out)
	if err != nil {
		return sarif.Report{}, err
	}

	// One run per module, each starting with its config message, and each judged on its own: what
	// one module calls says nothing about another, and a verdict reached over the union of two
	// builds would lend one module's call path to the other's finding.
	manifests := goModuleManifests(dir)
	asOf := now.UTC().Format("2006-01-02")
	var results []sarif.Result
	runs := splitGovulncheckRuns(msgs)
	// One run per module, as govulncheckArgs ran them. Fewer means a module whose run printed
	// nothing, and its findings would be absent from a report that looks complete.
	if len(modules) > 0 && len(runs) != len(modules) {
		return sarif.Report{}, fmt.Errorf("govulncheck wrote %d runs for %d modules", len(runs), len(modules))
	}
	var inputs []sarif.Input
	for _, run := range runs {
		// A module that did not load is named as unread, and has no results: its findings keep the
		// band the manifest scanner gave them, with no verdict.
		if u := run[0].Unloaded; u != nil {
			inputs = append(inputs, sarif.Input{Path: u.GoMod, Unread: u.Reason, Analysis: true})
			continue
		}
		results = append(results, govulncheckRunResults(run, manifests, asOf)...)
	}
	return sarif.Report{Tool: govulncheckScanner, Results: results, Inputs: inputs, Provenance: []sarif.Provenance{{
		Tool:   govulncheckScanner,
		Fields: []sarif.Field{{Key: "database", Value: resolveGovulnDB().describe()}},
	}}}, nil
}

// splitGovulncheckRuns divides a concatenated stream into one slice per govulncheck run. Each run
// opens with a config message, or is a module that did not load; anything before the first belongs
// to a run of its own.
func splitGovulncheckRuns(msgs []govulncheckMessage) [][]govulncheckMessage {
	var runs [][]govulncheckMessage
	for _, m := range msgs {
		if m.Config != nil || m.Unloaded != nil || len(runs) == 0 {
			runs = append(runs, nil)
		}
		runs[len(runs)-1] = append(runs[len(runs)-1], m)
	}
	return runs
}

// govulncheckRunResults turns one module's run into results located at that module's go.mod.
func govulncheckRunResults(run []govulncheckMessage, manifests map[string]string, asOf string) []sarif.Result {
	var scanLevel string
	manifest := "go.mod"
	analyzed := map[string]bool{}
	advisories := map[string]*govulncheckOSV{}
	byVuln := map[govulncheckKey][]govulncheckFinding{}
	for _, m := range run {
		switch {
		case m.Config != nil:
			scanLevel = m.Config.ScanLevel
		case m.SBOM != nil:
			for _, mod := range m.SBOM.Modules {
				analyzed[mod.Path] = true
			}
			if path, ok := govulncheckManifest(m.SBOM.Roots, manifests); ok {
				manifest = path
			}
		case m.OSV != nil:
			advisories[m.OSV.ID] = m.OSV
		case m.Finding != nil && len(m.Finding.Trace) > 0:
			// The vulnerable module is the deepest frame, and traces are callee first.
			key := govulncheckKey{OSV: m.Finding.OSV, Module: m.Finding.Trace[0].Module}
			byVuln[key] = append(byVuln[key], *m.Finding)
		}
	}
	results := make([]sarif.Result, 0, len(byVuln))
	for _, key := range sortedGovulncheckKeys(byVuln) {
		for _, r := range govulncheckResults(key, byVuln[key], advisories[key.OSV], analyzed, scanLevel, asOf) {
			r.Location.URI = manifest
			results = append(results, r)
		}
	}
	return results
}

// govulncheckManifest finds the go.mod of the module a run analyzed, from the packages it matched.
//
// A root is a package, and equals its module's path only when the package sits at the module
// root. Commands under cmd/ or a directory per binary do not, so a root is matched to the
// longest module path that contains it. The longest, because a nested module's path extends
// the outer module's, and the outer one also contains every package of the nested one.
func govulncheckManifest(roots []string, manifests map[string]string) (string, bool) {
	for _, root := range roots {
		best := ""
		for mod := range manifests {
			if (root == mod || strings.HasPrefix(root, mod+"/")) && len(mod) > len(best) {
				best = mod
			}
		}
		if best != "" {
			return manifests[best], true
		}
	}
	return "", false
}

// goModuleManifests maps each module path under root to its go.mod, relative to root.
func goModuleManifests(root string) map[string]string {
	out := map[string]string{}
	if root == "" {
		return out
	}
	for _, dir := range goModuleDirs(root) {
		path := filepath.Join(dir, "go.mod")
		name := goModulePath(path)
		rel, err := filepath.Rel(root, path)
		if name == "" || err != nil {
			continue
		}
		out[name] = filepath.ToSlash(rel)
	}
	return out
}

// goModulePath reads the module path a go.mod declares, or "" if it declares none.
func goModulePath(gomod string) string {
	raw, err := os.ReadFile(gomod) // #nosec G304 -- a go.mod inside the checkout
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "module" {
			return strings.Trim(fields[1], `"`)
		}
	}
	return ""
}

// govulncheckKey identifies a vulnerability in a module. Both halves are needed: one advisory can
// affect more than one module, and one module has more than one advisory.
type govulncheckKey struct {
	OSV    string
	Module string
}

// sortedGovulncheckKeys orders the keys so a run produces the same report twice.
func sortedGovulncheckKeys(m map[govulncheckKey][]govulncheckFinding) []govulncheckKey {
	keys := make([]govulncheckKey, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].OSV != keys[j].OSV {
			return keys[i].OSV < keys[j].OSV
		}
		return keys[i].Module < keys[j].Module
	})
	return keys
}

// decodeGovulncheckStream reads the concatenated JSON objects govulncheck writes.
func decodeGovulncheckStream(out []byte) ([]govulncheckMessage, error) {
	dec := json.NewDecoder(strings.NewReader(string(out)))
	var msgs []govulncheckMessage
	for {
		var m govulncheckMessage
		err := dec.Decode(&m)
		if errors.Is(err, io.EOF) {
			return msgs, nil
		}
		if err != nil {
			return nil, fmt.Errorf("decode govulncheck output: %w", err)
		}
		msgs = append(msgs, m)
	}
}

// govulncheckResults turns one vulnerability in one module into a result per identifier it is
// known by.
func govulncheckResults(
	key govulncheckKey,
	findings []govulncheckFinding,
	advisory *govulncheckOSV,
	analyzed map[string]bool,
	scanLevel string,
	asOf string,
) []sarif.Result {
	reach := &sarif.Reachability{
		State:    govulncheckState(findings, key.Module, analyzed, scanLevel),
		Analyzer: govulncheckScanner,
		Method:   sarif.MethodCallGraph,
		Symbols:  govulncheckSymbols(advisory, key.Module),
		AsOf:     asOf,
	}
	if reach.State == sarif.ReachabilityReachable {
		reach.Paths = govulncheckPaths(findings)
	}

	pkg := &sarif.Package{
		Name:         key.Module,
		Version:      govulncheckModuleVersion(findings),
		FixedVersion: strings.TrimPrefix(govulncheckFixedVersion(findings), "v"),
		Ecosystem:    "gomod",
	}
	pkg.PURL = govulncheckPURL(pkg.Name, pkg.Version)

	var results []sarif.Result
	for _, id := range govulncheckIdentifiers(key.OSV, advisory) {
		results = append(results, sarif.Result{
			Tool:   govulncheckScanner,
			RuleID: id,
			// The Go vulnerability database publishes no severity, so there is none to report.
			// Absent, this normalizes to warning; where another scanner rated the same finding,
			// the fold keeps that scanner's rating rather than replacing it with this one.
			Level:        sarif.LevelWarning,
			Message:      govulncheckMessageText(key, advisory, reach),
			Location:     sarif.Location{URI: "go.mod"},
			Package:      pkg,
			Reachability: reach,
			Aliases:      govulncheckAliases(id, key.OSV, advisory),
		})
	}
	return results
}

// govulncheckAliases are the identifiers of the advisory a finding was reported from, other than
// the rule id: the Go id first, then the advisory's aliases as the Go vulnerability database lists
// them.
//
// The entry govulncheck printed is one record with one affected range, so its identifiers name the
// flaw this finding is about. A scanner reading the Go database reports a flaw with no CVE under
// its Go id, where this finding carries the GitHub advisory id, and correlation and the verdict's
// fold match that copy through these.
func govulncheckAliases(rule, osvID string, advisory *govulncheckOSV) []string {
	ids := []string{osvID}
	if advisory != nil {
		ids = append(ids, advisory.Aliases...)
	}
	var out []string
	for _, id := range ids {
		if id != "" && id != rule && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}

// govulncheckState decides the verdict, and refuses to state the strong one without grounds.
//
// Reachable is a positive observation and needs nothing else: a call path was found. Unreachable
// is a claim about absence, and absence is only meaningful if something looked, so it requires
// both that the run was analyzing symbols and that this module was in what it analyzed. Anything
// else is unknown, which is the honest answer and the one that keeps a report from implying a
// check that never ran.
func govulncheckState(findings []govulncheckFinding, module string, analyzed map[string]bool, scanLevel string) sarif.ReachabilityState {
	for _, f := range findings {
		for _, frame := range f.Trace {
			if frame.Function != "" {
				return sarif.ReachabilityReachable
			}
		}
	}
	if scanLevel == "symbol" && analyzed[module] {
		return sarif.ReachabilityUnreachable
	}
	return sarif.ReachabilityUnknown
}

// govulncheckPaths converts the traces that reached a symbol into call paths, reversed.
//
// govulncheck orders a trace callee first, the vulnerable function, then whatever called it.
// Reversing it puts this project's own code at the top, which is the order a reader follows.
func govulncheckPaths(findings []govulncheckFinding) []sarif.CallPath {
	var paths []sarif.CallPath
	for _, f := range findings {
		if !govulncheckCalled(f) {
			continue
		}
		frames := make([]sarif.CallFrame, 0, len(f.Trace))
		for i := len(f.Trace) - 1; i >= 0; i-- {
			t := f.Trace[i]
			if t.Function == "" {
				continue
			}
			frame := sarif.CallFrame{Function: govulncheckFunction(t), Package: t.Package, Module: t.Module}
			if t.Position != nil {
				frame.File, frame.Line = t.Position.Filename, t.Position.Line
			}
			frames = append(frames, frame)
		}
		if len(frames) > 0 {
			paths = append(paths, sarif.CallPath{Frames: frames})
		}
	}
	return paths
}

// govulncheckFunction is a frame's function as Go qualifies it: the receiver's type and the method
// for a method (Writer.Close), the name alone otherwise.
func govulncheckFunction(t govulncheckFrame) string {
	if t.Receiver == "" {
		return t.Function
	}
	return strings.TrimPrefix(t.Receiver, "*") + "." + t.Function
}

// govulncheckCalled reports whether a finding names a called symbol.
func govulncheckCalled(f govulncheckFinding) bool {
	for _, t := range f.Trace {
		if t.Function != "" {
			return true
		}
	}
	return false
}

// govulncheckSymbols lists the vulnerable functions the advisory names for this module.
func govulncheckSymbols(advisory *govulncheckOSV, module string) []string {
	if advisory == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, aff := range advisory.Affected {
		if aff.Package.Name != module {
			continue
		}
		for _, imp := range aff.EcosystemSpecific.Imports {
			for _, sym := range imp.Symbols {
				qualified := sym
				if imp.Path != "" {
					qualified = imp.Path + "." + sym
				}
				if !seen[qualified] {
					seen[qualified] = true
					out = append(out, qualified)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// govulncheckIdentifiers lists every identifier this advisory should be reported under.
//
// The CVEs where there are any, for the reason retire.js picks the same way: a CVE is what a reader
// can look up, what an exclusion is most likely written against, and what every other scanner and
// every exploitability feed keys on. An advisory with several CVEs becomes several findings,
// because that is how the manifest scanners report it.
//
// Without a CVE, the GitHub advisory ids, which are what Trivy and Grype report the same flaw
// under. Reported under the Go id, this finding would not match their copies, so the verdict would
// not reach them, they would be ranked without it, and the flaw would be counted twice. The Go id
// is used only for an advisory with neither a CVE nor a GitHub id.
func govulncheckIdentifiers(osvID string, advisory *govulncheckOSV) []string {
	if advisory == nil {
		return []string{osvID}
	}
	for _, prefix := range []string{"CVE-", "GHSA-"} {
		if ids := aliasesWith(advisory.Aliases, prefix); len(ids) > 0 {
			return ids
		}
	}
	return []string{osvID}
}

// aliasesWith returns the aliases starting with prefix, deduplicated and sorted.
func aliasesWith(aliases []string, prefix string) []string {
	var out []string
	seen := map[string]bool{}
	for _, alias := range aliases {
		if strings.HasPrefix(strings.ToUpper(alias), prefix) && !seen[alias] {
			seen[alias] = true
			out = append(out, alias)
		}
	}
	sort.Strings(out)
	return out
}

// govulncheckModuleVersion reports the vulnerable module's version, read from the trace frame
// that names it.
func govulncheckModuleVersion(findings []govulncheckFinding) string {
	for _, f := range findings {
		for _, t := range f.Trace {
			if t.Version != "" {
				return t.Version
			}
		}
	}
	return ""
}

// govulncheckFixedVersion reports the first release that resolves the finding, when there is one.
func govulncheckFixedVersion(findings []govulncheckFinding) string {
	for _, f := range findings {
		if f.FixedVersion != "" {
			return f.FixedVersion
		}
	}
	return ""
}

// govulncheckPURL builds a Go module package URL.
//
// The module path keeps its case: Go module paths are case-sensitive, and lowercasing would make
// pkg:golang/github.com/Masterminds/semver a different package from the one that was scanned.
func govulncheckPURL(module, version string) string {
	if module == "" {
		return ""
	}
	purl := "pkg:golang/" + module
	if version != "" {
		purl += "@" + version
	}
	return purl
}

// govulncheckMessageText describes the finding, leading with the advisory's own summary and
// naming the Go advisory id, which the rule id drops in favor of the CVE.
func govulncheckMessageText(key govulncheckKey, advisory *govulncheckOSV, reach *sarif.Reachability) string {
	summary := ""
	if advisory != nil {
		summary = advisory.Summary
	}
	if summary == "" {
		summary = "vulnerability in " + key.Module
	}
	var b strings.Builder
	b.WriteString(key.Module)
	b.WriteString(": ")
	b.WriteString(summary)
	b.WriteString(" (")
	b.WriteString(key.OSV)
	b.WriteString(")")
	switch reach.State {
	case sarif.ReachabilityReachable:
		b.WriteString(", reachable: ")
		b.WriteString(govulncheckPathSummary(reach.Paths))
	case sarif.ReachabilityUnreachable:
		b.WriteString(", the vulnerable code is never called")
	case sarif.ReachabilityUnknown:
		b.WriteString(", reachability not determined")
	}
	return b.String()
}

// govulncheckPathSummary renders the shortest call path as one line, which is what a reader needs
// before deciding whether to open the full evidence.
func govulncheckPathSummary(paths []sarif.CallPath) string {
	shortest, ok := sarif.ShortestCallPath(paths)
	if !ok {
		return "a call path exists"
	}
	return shortest.String()
}
