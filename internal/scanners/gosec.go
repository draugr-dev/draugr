package scanners

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/draugr-dev/draugr/internal/manifests"
	"github.com/draugr-dev/draugr/internal/toolexec"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// gosecConfigSchema is the JSON Schema for gosec's Saga config (controllers.sast.gosec).
// additionalProperties:false rejects mistyped keys.
//
// Rule selection is here; the severity and confidence floors gosec also offers are not. A floor
// drops findings inside the tool, where Draugr cannot mark them suppressed or record who accepted
// them. Use `exclusions` in the Saga for a finding you have judged, and the gate thresholds for
// what should fail a build. Selecting rules is a different statement: that a check does not apply
// to this codebase at all.
const gosecConfigSchema = `{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "include": {
      "type": "array",
      "items": { "type": "string", "pattern": "^(.*\\$\\{\\{.*\\}\\}.*|G[0-9]{3})$" },
      "description": "Run only these gosec rules, by ID, e.g. [\"G101\", \"G204\"]. Everything else is skipped."
    },
    "exclude": {
      "type": "array",
      "items": { "type": "string", "pattern": "^(.*\\$\\{\\{.*\\}\\}.*|G[0-9]{3})$" },
      "description": "Skip these gosec rules, by ID, e.g. [\"G104\"]. For rules that do not apply to the codebase, a finding you have judged and accepted belongs in exclusions, where it stays in the report marked suppressed."
    },
    "tags": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Go build tags to compile with, e.g. [\"integration\"]. Code behind a tag gosec does not build is code it does not analyze."
    }
  }
}`

// gosecScannerName is the gosec scanner's registered name.
const gosecScannerName = "gosec"

// NewGosec returns a Scanner that runs gosec, a Go-specialized static analyzer, over a
// checked-out repository. It is an optional second scanner for the "sast" control (alongside
// Semgrep); it only makes sense on Go components, so it is opt-in via
// controls.sast.gosec.enabled.
func NewGosec() plugin.Scanner {
	s := newRepoScannerPerModule(
		plugin.ScannerInfo{
			Name:           gosecScannerName,
			Origin:         "securego",
			Binary:         "gosec",
			Controls:       []string{"sast"},
			TargetKinds:    []plugin.TargetKind{plugin.TargetRepository},
			ConfigSchema:   json.RawMessage(gosecConfigSchema),
			ModuleManifest: "go.mod",
			// gosec loads a module's packages with `go`, whose compile processes fill the bound
			// each tool runs under, so it takes its turn with every other Go package load.
			Exclusive: plugin.ExclusiveGoPackageLoad,
		},
		// gosec reads every file of the module, so where an analysis starts (the target's Entry)
		// changes nothing it reports.
		func(dir string, _ []string, cfg plugin.Config) [][]string { return gosecArgs(dir, cfg) },
		parseGosec,
	)
	s.cacheVersion = sharedGosecVersion.version
	// gosec loads a module's packages with `go`. Without it, gosec exits 0 having analyzed
	// nothing, and the control would read as a clean pass.
	s.run = onRuntime(s.info.Binary, onGosecModule(gosecBounded(onGosecWorkspace(onGosecPackages(execArgvInDirWithEnv)))))
	return s
}

// gosecModuleDir is the directory of the module a gosec argv runs over, its last argument without
// the trailing `/...`. It is the argv gosecArgs plans; onGosecPackages names the module's package
// directories in its place when gosec runs.
func gosecModuleDir(argv []string) string {
	if len(argv) == 0 {
		return ""
	}
	return strings.TrimSuffix(argv[len(argv)-1], string(filepath.Separator)+"...")
}

// onGosecWorkspace runs gosec over a module in a workspace with the environment govulncheck gets
// for one (moduleGoWorkEnv), layered over the caller's: GOWORK naming a copy of the go.work outside
// the read-only checkout, or GOWORK=off for a module the workspace does not use.
//
// gosec loads the module's packages with the go command, which in workspace mode writes any
// checksum it lacks to the go.work.sum beside go.work. On the checkout that write fails, and the
// packages it was loading are not analyzed.
func onGosecWorkspace(run func(ctx context.Context, dir string, argv, env []string) ([]byte, error)) func(ctx context.Context, dir string, argv, env []string) ([]byte, error) {
	return func(ctx context.Context, dir string, argv, env []string) ([]byte, error) {
		work, cleanup, err := moduleGoWorkEnv(dir, gosecModuleDir(argv))
		if err != nil {
			return nil, err
		}
		defer cleanup()
		return run(ctx, dir, argv, append(slices.Clip(env), work...))
	}
}

// onGosecPackages runs gosec over the directories of the module's packages, as the go command lists
// them under the same environment and build tags, in place of the `<module>/...` gosecArgs plans.
//
// gosec 2.30.0 walks a path ending in `/...` itself and leaves out every directory whose path
// matches its -exclude-dir patterns, which hold `vendor` by default. The pattern it builds,
// `([\/])?vendor([\/])?`, has both separators optional and matches `vendor` anywhere in the path: a
// package at cmd/vendorhash is left out without a word, and a module in a directory named
// vendor-api has every package left out. A directory named on the command line is taken as it is.
// `go list ./...` lists what the go command builds as part of the module and nothing else: no
// vendor/ or testdata/ directory, no directory whose name starts with `.` or `_`, and no module
// nested inside it, which gosecArgs runs on its own. A directory holding only tests is left out
// as well, because gosec does not analyze test files unless asked to.
//
// The same `go list -e -deps` is the load check. gosec loads each package with go/packages and
// skips one that comes back with no name, which is what go/packages returns where the go command
// failed for the module, then writes a report of what it did analyze and exits 0. `go list -e
// -deps` reports a problem inside one package as that package's error and exits 0; it exits
// non-zero where the go command cannot load the module, and that exit is returned as the run's,
// for onGosecModule to record against the module. A module the go command lists no package in is
// errNoGoPackages, and gosec does not run over it.
//
// gosec names each file in its SARIF relative to the longest path on its command line holding it,
// which for a package directory is the file's bare name, so main.go in two packages would read
// alike. The SARIF goes to a file and the same issues, in the same order, to stdout as JSON, which
// names each file in full, and gosecUnderModule puts each location back relative to the module.
func onGosecPackages(run func(ctx context.Context, dir string, argv, env []string) ([]byte, error)) func(ctx context.Context, dir string, argv, env []string) ([]byte, error) {
	return func(ctx context.Context, dir string, argv, env []string) ([]byte, error) {
		mod := gosecModuleDir(argv)
		if mod == "" {
			return run(ctx, dir, argv, env)
		}
		var tags []string
		for _, a := range argv {
			if strings.HasPrefix(a, "-tags=") {
				tags = append(tags, a)
			}
		}
		pkgs, err := goListPackages(ctx, mod, tags, env)
		if err != nil {
			return nil, fmt.Errorf("go list -e -deps ./... cannot load the module, so gosec did not run: %w", err)
		}
		if len(pkgs) == 0 {
			// With no directory on its command line, gosec would analyze its working directory.
			return nil, errNoGoPackages
		}
		tmp, err := os.MkdirTemp("", "draugr-gosec-*")
		if err != nil {
			return nil, err
		}
		defer func() { _ = os.RemoveAll(tmp) }()
		report := filepath.Join(tmp, "report.sarif")
		cmd := append(slices.Clip(argv[:len(argv)-1]), "-out", report, "-stdout", "-verbose", "json")
		issues, err := run(ctx, dir, append(cmd, pkgs...), env)
		if err != nil {
			return nil, err
		}
		doc, err := os.ReadFile(report) // #nosec G304 -- the file gosec wrote in the directory MkdirTemp just made
		if err != nil {
			return nil, fmt.Errorf("gosec wrote no SARIF report: %w", err)
		}
		return gosecUnderModule(doc, issues, mod)
	}
}

// errNoGoPackages is a module the go command lists no package of, under gosec's build tags.
var errNoGoPackages = errors.New("no Go packages")

// gosecPackageDir is the `go list -f` template that prints the directory of each package the
// pattern matched and gosec analyzes, one with a non-test Go file in the build, and nothing for a
// package listed only as a dependency (-deps).
const gosecPackageDir = `{{if not .DepOnly}}{{if or .GoFiles .CgoFiles}}{{.Dir}}{{end}}{{end}}`

// goListPackages loads the packages of the module at dir, and every package they import, with the
// go command, and returns the directories of the module's own packages that hold a non-test Go
// file. A variable so a test can stand in for the go command.
var goListPackages = func(ctx context.Context, dir string, flags, env []string) ([]string, error) {
	argv := append([]string{"go", "list", "-e", "-deps", "-f", gosecPackageDir}, flags...)
	out, err := toolexec.RunWithEnv(ctx, dir, append(argv, "./..."), env)
	if err != nil {
		return nil, err
	}
	var dirs []string
	for line := range strings.SplitSeq(string(out), "\n") {
		if line != "" {
			dirs = append(dirs, line)
		}
	}
	return dirs, nil
}

// gosecIssue is one issue of gosec's JSON report: the rule, and the file's path in full, which its
// SARIF gives relative to a path on its command line.
type gosecIssue struct {
	RuleID string `json:"rule_id"`
	File   string `json:"file"`
}

// gosecUnderModule returns gosec's SARIF report with each location's URI relative to the module at
// mod, taken from the issue at the same position in gosec's JSON report, which gosec writes from
// the same list in the same order. A rule or a count that differs between the two is an error,
// since then no position can be trusted. A file outside the module keeps the URI gosec wrote.
func gosecUnderModule(report, issues []byte, mod string) ([]byte, error) {
	var listed struct {
		Issues []gosecIssue `json:"Issues"`
	}
	if err := json.Unmarshal(issues, &listed); err != nil {
		return nil, fmt.Errorf("read gosec's JSON report: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(report))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("read gosec's SARIF report: %w", err)
	}
	n := 0
	runs, _ := doc["runs"].([]any)
	for _, run := range runs {
		results, _ := jsonObject(run)["results"].([]any)
		for _, r := range results {
			if n == len(listed.Issues) {
				return nil, fmt.Errorf("gosec's SARIF report holds more results than the %d issues of its JSON report", len(listed.Issues))
			}
			issue := listed.Issues[n]
			n++
			result := jsonObject(r)
			if id, _ := result["ruleId"].(string); id != issue.RuleID {
				return nil, fmt.Errorf("gosec's SARIF result %d is %s and its JSON issue %d is %s", n, id, n, issue.RuleID)
			}
			uri, ok := relSlash(mod, issue.File)
			if !ok {
				continue
			}
			locations, _ := result["locations"].([]any)
			for _, l := range locations {
				if art := jsonObject(jsonObject(jsonObject(l)["physicalLocation"])["artifactLocation"]); art != nil {
					art["uri"] = uri
				}
			}
		}
	}
	if n != len(listed.Issues) {
		return nil, fmt.Errorf("gosec's SARIF report holds %d results and its JSON report %d issues", n, len(listed.Issues))
	}
	return json.Marshal(doc)
}

// jsonObject is v as a decoded JSON object, nil where it is not one.
func jsonObject(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// gosecRecord is a line Draugr writes into gosec's output in place of a run over one module that
// wrote no report, so the output still holds one document per module, in the order gosecArgs ran
// them.
type gosecRecord struct {
	// Module is Draugr's, never gosec's: a SARIF document has no such key.
	Module *gosecModule `json:"draugrModule,omitempty"`
}

// gosecModule is one module gosec wrote no report for, and why.
type gosecModule struct {
	// GoMod is the module's go.mod, relative to the checkout.
	GoMod string `json:"goMod"`
	// NoPackages says gosec found no Go package in the module.
	NoPackages bool `json:"noPackages,omitempty"`
	// Failed is the error of a run that failed for any other reason.
	Failed string `json:"failed,omitempty"`
}

// onGosecModule turns a run of gosec over one module that did not write a report into a record of
// that module, so the runs over the other modules keep their findings.
//
// A module that holds no Go package, a documentation site with its own go.mod being the common case,
// is one the go command lists no package of (errNoGoPackages), and gosec does not run over it. It is
// recorded as a go.mod gosec did not analyze. An exit of gosec, or of the go command listing the
// module's packages, is recorded as a failure of that module, which parseGosec reports as the scan's
// error beside the other modules' findings.
//
// Only those are recorded. An error that holds for every module, gosec not installed or the run
// canceled, still fails the job as it is.
func onGosecModule(run func(ctx context.Context, root string, argv []string) ([]byte, error)) func(ctx context.Context, root string, argv []string) ([]byte, error) {
	return func(ctx context.Context, root string, argv []string) ([]byte, error) {
		out, err := run(ctx, root, argv)
		noPackages := errors.Is(err, errNoGoPackages)
		_, exited := errors.AsType[*exec.ExitError](err)
		if (!noPackages && !exited) || ctx.Err() != nil || len(argv) == 0 {
			return out, err
		}
		mod := gosecModuleDir(argv)
		rec := gosecModule{GoMod: "go.mod"}
		if rel, ok := relSlash(root, mod); ok && rel != "." {
			rec.GoMod = rel + "/go.mod"
		}
		if noPackages {
			rec.NoPackages = true
		} else {
			rec.Failed = stripCheckoutDir(root, err.Error())
		}
		// The run's own output is left out: a run that exited non-zero wrote no report to read.
		msg, err := json.Marshal(gosecRecord{Module: &rec})
		if err != nil {
			return nil, err
		}
		return append(msg, '\n'), nil
	}
}

// gosecLoads is how many packages gosec loads and analyzes at once, its `-concurrency`, before the
// bound lowers it (toolexec.Divide).
//
// In gosec 2.30.0 (analyzer.go, Analyzer.Process) `-concurrency` is the number of workers, each
// taking one package at a time: it loads the package with go/packages, which runs one
// `go list -export` that compiles whatever of the package's dependencies the build cache lacks,
// and then analyzes it. The same number also limits how many of gosec's SSA analyzers run at once
// over one package. Its default is GOMAXPROCS, which Draugr sets to the whole bound, and each of
// those `go list` commands builds with the whole bound as its -p, so one gosec run could start the
// bound's square in compile processes.
//
// Two workers, each with half the bound as its -p, keep the compile processes within the bound
// and divide it as evenly as two can, leaving at most one unit unused. The first loads compile
// most of the module's dependencies, and a larger -p is what shortens those; later loads find
// them cached and spend their time in analysis, which the second worker overlaps with the first's
// load. Each worker also holds its package's syntax, types and SSA in memory while it analyzes,
// so fewer workers keep gosec's own memory down as well.
//
// Every gosec since 2.10.0 has `-concurrency`, and Draugr installs 2.30.0. The releases that
// accept the `-track-suppressions` Draugr already passes and lack it are 2.9.x, built against
// golang.org/x/tools 0.1.8, which predates the export data Go has written since 1.20, so they
// load no package with a Go toolchain Draugr supports.
const gosecLoads = 2

// gosecBounded runs gosec with the job's bound divided among the packages it loads at once, as
// toolexec.Divide gives it: -concurrency at how many it loads, and GOFLAGS with -p at the bound over
// that many, layered over the caller's environment. Here rather than in gosecArgs because the
// job's bound is a share of the machine that only the job's context knows.
func gosecBounded(run func(ctx context.Context, dir string, argv, env []string) ([]byte, error)) func(ctx context.Context, dir string, argv []string) ([]byte, error) {
	return func(ctx context.Context, dir string, argv []string) ([]byte, error) {
		loads, env := toolexec.Divide(ctx, gosecLoads)
		withLoads := append([]string{argv[0], "-concurrency", strconv.Itoa(loads)}, argv[1:]...)
		return run(ctx, dir, withLoads, env)
	}
}

// gosecArgs builds `gosec -fmt sarif -no-fail … <module>/...` for each Go module under dir, the
// checkout, which the repoScanner runs as the working directory.
//
//   - -no-fail keeps the process successful when findings exist (findings live in the SARIF
//     report, not the exit code; the sast controller judges severity).
//   - no -quiet: gosec's -quiet suppresses all output on a clean scan, which would leave no
//     SARIF to parse.
//   - -track-suppressions keeps a `#nosec` result in the report, marked, with the text after the
//     `--` as its justification. Without it gosec removes the result, and a finding somebody
//     excluded is indistinguishable from one nobody ever made: the report reads clean, and the
//     question asked of an exclusion later, who decided this was acceptable, has nothing to
//     answer from.
//   - -concurrency, how many packages gosec loads at once, is added by gosecBounded, from the same
//     division of the job's bound as the -p its run is given (gosecLoads).
func gosecArgs(dir string, cfg plugin.Config) [][]string {
	base := []string{"gosec", "-fmt", "sarif", "-no-fail", "-track-suppressions"}
	if v := commaList(cfg, "include"); v != "" {
		base = append(base, "-include="+v)
	}
	if v := commaList(cfg, "exclude"); v != "" {
		base = append(base, "-exclude="+v)
	}
	if v := commaList(cfg, "tags"); v != "" {
		base = append(base, "-tags="+v)
	}
	// One run per module, by absolute path. gosec loads packages from the working directory's
	// module, so `./...` from a root with no go.mod analyzes nothing and writes nothing, and a
	// module nested inside another is outside the outer one's `./...`. When gosec runs,
	// onGosecPackages names the module's package directories in place of `<module>/...`.
	var out [][]string
	for _, mod := range goModuleDirs(dir) {
		argv := append([]string{}, base...)
		out = append(out, append(argv, filepath.Join(mod, "...")))
	}
	return out
}

// parseGosec reads the SARIF documents the per-module runs wrote, one after another, in the order
// gosecArgs ran them.
//
// gosec names a file relative to the module it analyzed, so each document's locations are put back
// under that module's directory: `main.go` in the module at service/ is service/main.go.
//
// A record onGosecModule wrote in place of a module's report stands for that module. A module with
// no Go package is an input gosec did not analyze, with the reason manifests.NoGoPackages. A module
// whose run failed is named in a *moduleFailures returned beside the report of the other modules.
//
// No output means no module was found, and the report says so rather than passing: a tree gosec
// could not analyze must not read like one it analyzed and found clean.
func parseGosec(out []byte, dir string, cfg plugin.Config) (sarif.Report, error) {
	modules := goModuleDirs(dir)
	if len(bytes.TrimSpace(out)) == 0 {
		// Silence over a tree that holds modules is runs that wrote nothing, not a tree with none,
		// and saying "no go.mod" there would describe a repository that is not this one.
		if dir != "" && len(modules) > 0 {
			return sarif.Report{}, fmt.Errorf("gosec wrote 0 reports for %d modules", len(modules))
		}
		return sarif.Report{
			Tool: "gosec",
			Provenance: []sarif.Provenance{{
				Tool:   "gosec",
				Fields: []sarif.Field{{Key: "coverage", Value: "no go.mod found, so gosec analyzed nothing here"}},
			}},
		}, nil
	}
	selected := commaList(cfg, "include") != "" || commaList(cfg, "exclude") != ""
	dec := json.NewDecoder(bytes.NewReader(out))
	var reports []sarif.Report
	var inputs []sarif.Input
	var failed []string
	docs := 0
	for {
		var doc json.RawMessage
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return sarif.Report{}, fmt.Errorf("read gosec SARIF: %w", err)
		}
		i := docs
		docs++
		// A module gosec wrote no report for (see onGosecModule).
		var rec gosecRecord
		if json.Unmarshal(doc, &rec) == nil && rec.Module != nil {
			if rec.Module.NoPackages {
				inputs = append(inputs, sarif.Input{Path: rec.Module.GoMod, Unread: string(manifests.NoGoPackages), Analysis: true})
			} else {
				failed = append(failed, "over "+rec.Module.GoMod+": "+rec.Module.Failed)
			}
			continue
		}
		rep, err := sarif.FromSARIF(doc)
		if err != nil {
			return sarif.Report{}, err
		}
		if err := rateByGosecSeverity(&rep, doc); err != nil {
			return sarif.Report{}, err
		}
		if dir != "" && i < len(modules) {
			underModule(&rep, dir, modules[i])
		}
		if selected {
			rep.Results = slices.DeleteFunc(rep.Results, outOfSelection)
		}
		reports = append(reports, rep)
	}
	if dir != "" && docs != len(modules) {
		return sarif.Report{}, fmt.Errorf("gosec wrote %d reports for %d modules", docs, len(modules))
	}
	merged := sarif.Merge(reports...)
	merged.Inputs = append(merged.Inputs, inputs...)
	if len(failed) > 0 {
		return merged, &moduleFailures{failed: failed, read: len(reports) > 0}
	}
	return merged, nil
}

// gosecSeverityLevel is the SARIF level each of gosec's severity ratings means.
var gosecSeverityLevel = map[string]sarif.Level{
	"HIGH":   sarif.LevelError,
	"MEDIUM": sarif.LevelWarning,
	"LOW":    sarif.LevelNote,
}

// rateByGosecSeverity sets each result's level from the severity gosec gave its rule.
//
// gosec writes level error for its MEDIUM rules as well as its HIGH ones, and states the rating
// only as a tag on the rule: `"tags": ["security", "MEDIUM"]`. Read by level alone, every MEDIUM
// rule would rank as high, a band above where gosec itself put it. A rule with no rating tag keeps
// the level gosec wrote.
func rateByGosecSeverity(rep *sarif.Report, doc []byte) error {
	var log struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID         string `json:"id"`
						Properties struct {
							Tags []string `json:"tags"`
						} `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(doc, &log); err != nil {
		return fmt.Errorf("read gosec rule severities: %w", err)
	}
	levels := map[string]sarif.Level{}
	for _, run := range log.Runs {
		for _, rule := range run.Tool.Driver.Rules {
			for _, tag := range rule.Properties.Tags {
				if l, ok := gosecSeverityLevel[tag]; ok {
					levels[rule.ID] = l
				}
			}
		}
	}
	for i := range rep.Results {
		if l, ok := levels[rep.Results[i].RuleID]; ok {
			rep.Results[i].Level = l
		}
	}
	return nil
}

// outOfSelection reports whether a result is one of the rules -include or -exclude left out.
//
// Under -track-suppressions gosec still runs those rules and reports each result as a suppression
// of kind external, justified "Globally suppressed.", where a #nosec is kind inSource. Kept, the
// result reads as a finding somebody accepted, when the descriptor said the rule does not apply to
// this codebase at all.
func outOfSelection(r sarif.Result) bool {
	return r.Suppression != nil && r.Suppression.Kind == "external"
}

// underModule prefixes each relative location in rep with module's directory relative to root.
func underModule(rep *sarif.Report, root, module string) {
	rel, err := filepath.Rel(root, module)
	if err != nil || rel == "." {
		return
	}
	for i := range rep.Results {
		uri := rep.Results[i].Location.URI
		if uri != "" && !filepath.IsAbs(uri) {
			rep.Results[i].Location.URI = filepath.ToSlash(filepath.Join(rel, uri))
		}
	}
}
