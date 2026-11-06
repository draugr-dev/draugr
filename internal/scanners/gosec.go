package scanners

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	s.run = onRuntime(s.info.Binary, onGosecModule(gosecBounded(execArgvInDirWithEnv)))
	return s
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

// onGosecModule turns a run of gosec over one module that exited non-zero into a record of that
// module, so the runs over the other modules keep their findings.
//
// A module that holds no Go package, a documentation site with its own go.mod being the common case,
// makes gosec exit 1 with `No packages found`, and says nothing about the modules beside it. It is
// recorded as a go.mod gosec did not analyze. Any other exit is recorded as a failure of that module,
// which parseGosec reports as the scan's error beside the other modules' findings.
//
// Only an exit of gosec itself is recorded. An error that holds for every module, gosec not installed
// or the run canceled, still fails the job as it is.
func onGosecModule(run func(ctx context.Context, root string, argv []string) ([]byte, error)) func(ctx context.Context, root string, argv []string) ([]byte, error) {
	return func(ctx context.Context, root string, argv []string) ([]byte, error) {
		out, err := run(ctx, root, argv)
		exit, ok := errors.AsType[*exec.ExitError](err)
		if !ok || ctx.Err() != nil || len(argv) == 0 {
			return out, err
		}
		mod := strings.TrimSuffix(argv[len(argv)-1], string(filepath.Separator)+"...")
		rec := gosecModule{GoMod: "go.mod"}
		if rel, ok := relSlash(root, mod); ok && rel != "." {
			rec.GoMod = rel + "/go.mod"
		}
		if gosecFoundNoPackages(exit) {
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

// gosecFoundNoPackages reports whether exit is gosec's exit over a module that holds no Go package:
// status 1, with `No packages found` as the message of a line of its log. gosec logs it, and exits 1,
// where no directory under the path it was given holds a .go file.
func gosecFoundNoPackages(exit *exec.ExitError) bool {
	if exit.ExitCode() != 1 {
		return false
	}
	for _, line := range strings.Split(string(exit.Stderr), "\n") {
		if line = strings.TrimSpace(line); line == gosecNoPackages || strings.HasSuffix(line, " "+gosecNoPackages) {
			return true
		}
	}
	return false
}

// gosecNoPackages is what gosec logs before it exits over a module that holds no Go package.
const gosecNoPackages = "No packages found"

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

// gosecBounded runs gosec with the bound divided among the packages it loads at once: GOFLAGS
// with -p at the bound over gosecLoads, as toolexec.Divide gives it, layered over the caller's
// environment.
func gosecBounded(run func(ctx context.Context, dir string, argv, env []string) ([]byte, error)) func(ctx context.Context, dir string, argv []string) ([]byte, error) {
	return func(ctx context.Context, dir string, argv []string) ([]byte, error) {
		_, env := toolexec.Divide(gosecLoads)
		return run(ctx, dir, argv, env)
	}
}

// gosecArgs builds `gosec -fmt sarif -no-fail ./...`. gosec loads Go packages relative to the
// working directory, so the repoScanner runs it with the checkout as the cwd and the target is
// the relative `./...` pattern (the dir argument is unused here).
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
//   - -concurrency is how many packages gosec loads at once, from the same division of the bound
//     as the -p its run is given (gosecLoads).
func gosecArgs(dir string, cfg plugin.Config) [][]string {
	loads, _ := toolexec.Divide(gosecLoads)
	base := []string{"gosec", "-fmt", "sarif", "-no-fail", "-track-suppressions", "-concurrency", strconv.Itoa(loads)}
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
	// module nested inside another is outside the outer one's `./...`.
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
