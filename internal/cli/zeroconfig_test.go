package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/internal/needs"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// zeroConfigModel is the model a zero-config scan of dir runs, failing the test where there is none.
func zeroConfigModel(t *testing.T, dir string) *saga.Model {
	t.Helper()
	m, err := syntheticSaga(dir)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// goAndCopiedJS is a Go module beside a web directory carrying a copy of jQuery: a tree that calls
// for gosec, govulncheck and retire.js, none of which the base runs.
var goAndCopiedJS = map[string]string{
	"checkout/go.mod":                    "module checkout\n\nrequire golang.org/x/text v0.3.0\n",
	"checkout/main.go":                   "package main\n",
	"web/package.json":                   `{"dependencies": {"left-pad": "1.0.0"}}`,
	"web/package-lock.json":              `{"lockfileVersion": 3, "packages": {}}`,
	"web/static/js/jquery-1.8.3.min.js":  "",
	"app/Dockerfile":                     "FROM python:3.8-slim\n",
	"api/openapi.yaml":                   "openapi: 3.0.0\n",
	"deploy/terraform/main.tf":           "",
	"web/static/js/angular.1.2.0.min.js": "",
}

// pythonWithDev is a Python application with a development requirements file Trivy opens only by a
// file pattern, and a setup.py only Grype reads.
var pythonWithDev = map[string]string{
	"app/requirements.txt":     "flask==1.0\n",
	"app/requirements-dev.txt": "pytest==8.0.0\n",
	"lib/setup.py":             "setup(install_requires=['requests'])\n",
}

// A zero-config scan runs the descriptor `draugr init` writes for the same tree: the same controls,
// the same scanners for each, the same scanner settings, and the same names. Two trees, so one that
// happened to need nothing beyond the base could not pass for both.
func TestZeroConfigRunsWhatInitWrites(t *testing.T) {
	for name, tc := range map[string]struct {
		files    map[string]string
		scanners []string
	}{
		"go and copied JavaScript":         {goAndCopiedJS, []string{"gosec", "govulncheck", "retirejs"}},
		"python with requirements-dev.txt": {pythonWithDev, []string{"grype-fs", "trivy-fs"}},
	} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "shop")
			layout(t, dir, tc.files)
			t.Chdir(dir)

			written := filepath.Join(t.TempDir(), "draugr.saga.yaml")
			if err := runInit(".", initOptions{output: written}, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
			fromInit, err := loadSaga(written)
			if err != nil {
				t.Fatal(err)
			}
			synthesized := zeroConfigModel(t, ".")

			reg := builtins.Registry()
			if got, want := needs.Uses(reg, synthesized), needs.Uses(reg, fromInit); !reflect.DeepEqual(got, want) {
				t.Errorf("zero-config runs %v\ninit's descriptor runs %v", usesNames(got), usesNames(want))
			}
			if !reflect.DeepEqual(synthesized.Config, fromInit.Config) {
				t.Errorf("config differs:\nzero-config %+v\ninit        %+v", synthesized.Config, fromInit.Config)
			}
			if !reflect.DeepEqual(synthesized.Components, fromInit.Components) || synthesized.Project != fromInit.Project {
				t.Errorf("zero-config names %q %+v, init %q %+v",
					synthesized.Project, synthesized.Components, fromInit.Project, fromInit.Components)
			}
			names := usesNames(needs.Uses(reg, synthesized))
			for _, s := range tc.scanners {
				if !slices.Contains(names, s) {
					t.Errorf("the tree calls for %s, and the scan runs %v", s, names)
				}
			}
			if _, on := synthesized.Config.Controls["images"]; on {
				t.Error("init writes images commented out, and the scan turned it on")
			}
			if c := synthesized.Components[0]; len(c.Images) > 0 || len(c.Hosts) > 0 {
				t.Errorf("init writes images and hosts commented out, and the scan declares %+v", c)
			}
		})
	}
	// requirements-dev.txt is reached by the pattern init writes, which is a setting rather than a
	// scanner, so it is checked on the setting.
	t.Run("filePatterns", func(t *testing.T) {
		dir := t.TempDir()
		layout(t, dir, pythonWithDev)
		blk, _ := zeroConfigModel(t, dir).Config.Controls["sca"]["trivyFs"].(saga.ControllerSettings)
		if blk["filePatterns"] == nil {
			t.Errorf("sca.trivyFs = %v, want the filePatterns that reach requirements-dev.txt", blk)
		}
	})
}

// usesNames are the scanners in uses, by name.
func usesNames(uses []needs.Use) []string {
	out := make([]string, len(uses))
	for i, u := range uses {
		out[i] = u.Info.Name
	}
	return out
}

// Every scanner the tree chooses is named on a FOUND row, which is where its caveat finds the files
// that called for it.
func TestEveryScannerTheTreeChoosesHasAFoundRow(t *testing.T) {
	dir := t.TempDir()
	layout(t, dir, goAndCopiedJS)
	layout(t, dir, pythonWithDev)
	zc, err := synthesize(dir)
	if err != nil {
		t.Fatal(err)
	}
	base, err := zeroConfigBase()
	if err != nil {
		t.Fatal(err)
	}
	reg := builtins.Registry()
	inBase := usesNames(needs.Uses(reg, base))
	rows := foundRows(zc.tree)
	chosen := 0
	for _, u := range needs.Uses(reg, zc.model) {
		if slices.Contains(inBase, u.Info.Name) {
			continue
		}
		chosen++
		if foundFiles(rows, u.Info.Name) == "" {
			t.Errorf("%s runs because of the tree, and no FOUND row names it", u.Info.Name)
		}
	}
	if chosen < 4 {
		t.Errorf("the tree chose %d scanners, want gosec, govulncheck, retirejs and grype-fs", chosen)
	}
}

// A scanner the tree chose that cannot run here is turned off and named, with the files that called
// for it and what is missing. One the base runs is left to fail its control as a descriptor's would,
// and one the machine can run is left alone.
func TestZeroConfigTurnsOffWhatCannotRunHere(t *testing.T) {
	reg := builtins.Registry()
	for name, tc := range map[string]struct {
		missing []string
		scope   engine.Scope
		// want is each caveat as "files: why", in name order.
		want []string
		off  []string
	}{
		"Go off PATH": {
			missing: []string{"go"},
			want:    []string{"checkout/go.mod: gosec needs Go", "checkout/go.mod: govulncheck needs Go"},
			off:     []string{"gosec", "govulncheck"},
		},
		"Go and gosec off PATH": {
			missing: []string{"go", "gosec"},
			want:    []string{"checkout/go.mod: gosec needs Go", "checkout/go.mod: govulncheck needs Go"},
			off:     []string{"gosec", "govulncheck"},
		},
		"gosec missing, Go present": {
			missing: []string{"gosec"},
			want:    []string{"checkout/go.mod: gosec not installed · draugr tools install gosec"},
			off:     []string{"gosec"},
		},
		"Node off PATH": {
			missing: []string{"node"},
			want:    []string{"web/static/js/angular.1.2.0.min.js · web/static/js/jquery-1.8.3.min.js: retire needs Node"},
			off:     []string{"retirejs"},
		},
		"only sast in scope": {
			missing: []string{"go", "node"},
			scope:   engine.Scope{Controls: []string{"sast"}},
			want:    []string{"checkout/go.mod: gosec needs Go"},
			off:     []string{"gosec"},
		},
		"a base scanner missing": {missing: []string{"trivy", "semgrep"}},
		"everything here":        {},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			layout(t, dir, goAndCopiedJS)
			zc, err := synthesize(dir)
			if err != nil {
				t.Fatal(err)
			}
			before := usesNames(needs.Uses(reg, zc.model))
			var got []string
			for _, u := range zc.turnOffUnrunnable(reg, tc.scope, notInstalled(tc.missing...)) {
				if u.Component != zc.model.Components[0].Name {
					t.Errorf("caveat on component %q, want %q", u.Component, zc.model.Components[0].Name)
				}
				got = append(got, u.Files+": "+u.Why)
			}
			slices.Sort(got)
			if !slices.Equal(got, tc.want) {
				t.Errorf("caveats = %q, want %q", got, tc.want)
			}
			after := usesNames(needs.Uses(reg, zc.model))
			for _, s := range before {
				if off := !slices.Contains(after, s); off != slices.Contains(tc.off, s) {
					t.Errorf("%s: turned off = %v, want %v", s, off, !off)
				}
			}
			if slices.Contains(tc.off, "govulncheck") && zc.model.Config.Reachability != nil {
				t.Errorf("govulncheck is off and reachability still names %v", zc.model.Config.Reachability.Analyzers)
			}
		})
	}
}

// A tool Draugr does not install is named without a command that would not find it.
func TestCannotRunNamesNoInstallForAToolDraugrDoesNotFetch(t *testing.T) {
	info := plugin.ScannerInfo{Name: "mend-sca", Binary: "mend"}
	if got := cannotRun(info, notInstalled("mend")); got != "mend not installed" {
		t.Errorf("cannotRun = %q", got)
	}
	info.AlsoRequires = []string{"git"}
	if got := cannotRun(info, notInstalled("git")); got != "git not installed · draugr tools install git" &&
		got != "git not installed" {
		t.Errorf("cannotRun = %q", got)
	}
	if got := cannotRun(plugin.ScannerInfo{Name: "builtin"}, notInstalled()); got != "" {
		t.Errorf("a scanner with no binary lacks %q", got)
	}
}

// turnOff on a block that is not there yet still writes enabled: false, so a control whose block
// the scaffold did not write cannot run the scanner either.
func TestTurnOffWritesABlockWhereThereIsNone(t *testing.T) {
	m := &saga.Model{Config: saga.Config{Controls: map[string]saga.ControllerSettings{"sast": {"enabled": true}}}}
	turnOff(m, plugin.ScannerInfo{Name: "gosec", Controls: []string{"sast", "absent"}})
	blk, ok := m.Config.Controls["sast"]["gosec"].(saga.ControllerSettings)
	if !ok || blk["enabled"] != false {
		t.Errorf("sast.gosec = %v, want enabled: false", m.Config.Controls["sast"]["gosec"])
	}
	m.Config.Controls["sca"] = saga.ControllerSettings{"grypeFs": map[string]any{"enabled": true}}
	turnOff(m, plugin.ScannerInfo{Name: "grype-fs", Controls: []string{"sca"}})
	if blk, _ := m.Config.Controls["sca"]["grypeFs"].(saga.ControllerSettings); blk["enabled"] != false {
		t.Errorf("sca.grypeFs = %v, want enabled: false", m.Config.Controls["sca"]["grypeFs"])
	}
	// An analyzer named twice and once leaves the block, and nil leaves nothing to do.
	m.Config.Reachability = &saga.ReachabilityConfig{Analyzers: []string{"govulncheck", "other"}}
	turnOff(m, plugin.ScannerInfo{Name: "govulncheck", Reachability: true})
	if got := m.Config.Reachability.Analyzers; !slices.Equal(got, []string{"other"}) {
		t.Errorf("analyzers = %v, want the other one kept", got)
	}
	m.Config.Reachability = nil
	turnOff(m, plugin.ScannerInfo{Name: "govulncheck", Reachability: true})
}

// FOUND carries the rows init prints, worded for a run: what was turned on, and the control a
// Dockerfile or an OpenAPI document would need, left off.
func TestFoundIsInitsRowsWordedForTheRun(t *testing.T) {
	dir := t.TempDir()
	layout(t, dir, goAndCopiedJS)
	zc, err := synthesize(dir)
	if err != nil {
		t.Fatal(err)
	}
	found := zc.found()
	rows := foundRows(zc.tree)
	if len(found) != len(rows) {
		t.Fatalf("FOUND has %d rows, init prints %d", len(found), len(rows))
	}
	for i, r := range rows {
		if found[i].Kind != r.kind || found[i].Files != r.where {
			t.Errorf("row %d = %+v, init prints %q %q", i, found[i], r.kind, r.where)
		}
	}
	did := map[string]string{}
	for _, f := range found {
		did[f.Kind] = f.Did
	}
	for kind, want := range map[string]string{
		"go":                "sca · gosec · govulncheck",
		"copied JavaScript": "retirejs",
		"Terraform":         "iac",
		"Dockerfile":        "iac · images off",
		"OpenAPI":           "dast off",
	} {
		if did[kind] != want {
			t.Errorf("%s: did %q, want %q", kind, did[kind], want)
		}
	}
}

// fakeSemgrep stands in for the base sast scanner, and fakeGosec for the one a go.mod adds. Both
// record that they ran, so a test can tell a scanner turned off from one that ran and failed.
type fakeSemgrep struct{ ran *atomic.Int32 }

func (fakeSemgrep) Info() plugin.ScannerInfo {
	return plugin.ScannerInfo{Name: "semgrep", Controls: []string{"sast"},
		TargetKinds: []plugin.TargetKind{plugin.TargetRepository}}
}
func (f fakeSemgrep) Scan(context.Context, plugin.Target, plugin.Config) (sarif.Report, error) {
	f.ran.Add(1)
	return sarif.Report{Tool: "semgrep", Results: []sarif.Result{
		{RuleID: "R", Level: sarif.LevelNote, Location: sarif.Location{URI: "checkout/main.go", StartLine: 1}},
	}}, nil
}

type fakeGosec struct{ ran *atomic.Int32 }

func (fakeGosec) Info() plugin.ScannerInfo {
	return plugin.ScannerInfo{Name: "gosec", Binary: "gosec", Controls: []string{"sast"},
		TargetKinds: []plugin.TargetKind{plugin.TargetRepository}}
}
func (f fakeGosec) Scan(context.Context, plugin.Target, plugin.Config) (sarif.Report, error) {
	f.ran.Add(1)
	return sarif.Report{}, errors.New(`exec: "gosec": executable file not found in $PATH`)
}

// A zero-config scan of a tree whose go.mod calls for gosec, on a machine without it: the run
// completes, sast passes on what semgrep found, gosec never runs, and the report carries FOUND and a
// not-checked caveat naming both modules. Two modules, so a caveat naming only the first, or a row
// per module, cannot pass.
func TestZeroConfigScanReportsAScannerItCannotRunAsACaveat(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "shop")
	layout(t, dir, map[string]string{
		"checkout/go.mod":  "module checkout\n\ngo 1.26\n",
		"checkout/main.go": "package main\n",
		"tools/go.mod":     "module tools\n\ngo 1.26\n",
		"tools/main.go":    "package main\n",
	})
	semgrepRan, gosecRan := &atomic.Int32{}, &atomic.Int32{}
	reg := engine.NewRegistry()
	reg.RegisterController(controllers.NewSAST())
	reg.RegisterScanner(fakeSemgrep{ran: semgrepRan})
	reg.RegisterScanner(fakeGosec{ran: gosecRan})

	orig := scanInstallOffer
	t.Cleanup(func() { scanInstallOffer = orig })
	scanInstallOffer.terminal = func() bool { return false }
	scanInstallOffer.lookPath = notInstalled("gosec")

	for _, format := range []string{"console", "markdown", "html", "json"} {
		var out bytes.Buffer
		opts := scanOptions{format: format, noPublish: true}
		if format == "html" {
			// A document rather than a stream, so it is written into -o.
			opts.format, opts.outputDir, opts.reports = "json", t.TempDir(), []string{"html"}
		}
		err := runScan(context.Background(), dir, opts, reg, &out)
		if err != nil && err.Error() != "policy verdict: fail" {
			t.Fatalf("%s: the run ended %v", format, err)
		}
		got := out.String()
		if format == "html" {
			page, err := os.ReadFile(filepath.Join(opts.outputDir, "report.html"))
			if err != nil {
				t.Fatal(err)
			}
			got = string(page)
		}
		switch format {
		case "console":
			for _, want := range []string{
				"FOUND  read from the tree · `draugr init` writes them to draugr.saga.yaml\n",
				"  go  checkout/go.mod · tools/go.mod  gosec · govulncheck\n",
				"checkout/go.mod · tools/go.mod  not-checked  gosec not installed · draugr tools install gosec",
			} {
				if !strings.Contains(got, want) {
					t.Errorf("console missing %q:\n%s", want, got)
				}
			}
			if strings.Contains(got, "ERROR") {
				t.Errorf("a scanner the tree chose shows as an error:\n%s", got)
			}
			if strings.Index(got, "CONTROLS") > strings.Index(got, "FOUND") {
				t.Errorf("FOUND comes after CONTROLS:\n%s", got)
			}
		case "markdown":
			for _, want := range []string{"### Found", "| go | checkout/go.mod · tools/go.mod | gosec · govulncheck |",
				"`not-checked` · `checkout/go.mod · tools/go.mod` · gosec not installed"} {
				if !strings.Contains(got, want) {
					t.Errorf("markdown missing %q:\n%s", want, got)
				}
			}
		case "html":
			for _, want := range []string{`id="found"`, "gosec not installed · draugr tools install gosec"} {
				if !strings.Contains(got, want) {
					t.Errorf("html missing %q", want)
				}
			}
		case "json":
			// The document a pipeline parses carries what it always carried: a caveat no gate fails
			// on is not in it.
			for _, absent := range []string{"read from the tree", "gosec not installed"} {
				if strings.Contains(got, absent) {
					t.Errorf("report.json gained %q:\n%s", absent, got)
				}
			}
		}
	}
	if gosecRan.Load() != 0 {
		t.Errorf("gosec ran %d times after it was turned off", gosecRan.Load())
	}
	if semgrepRan.Load() == 0 {
		t.Error("semgrep did not run")
	}
}

// A run from a descriptor has no FOUND section and turns nothing off: somebody wrote down what to
// scan, and a scanner they asked for that cannot run is an error.
func TestADescriptorRunHasNoFoundSection(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "shop")
	layout(t, dir, map[string]string{
		"go.mod":  "module shop\n\ngo 1.26\n",
		"main.go": "package main\n",
		"draugr.saga.yaml": "project: shop\nconfig:\n  controls:\n    sast:\n      enabled: true\n" +
			"      gosec:\n        enabled: true\ncomponents:\n  - name: shop\n    repositories:\n      - url: .\n",
	})
	semgrepRan, gosecRan := &atomic.Int32{}, &atomic.Int32{}
	reg := engine.NewRegistry()
	reg.RegisterController(controllers.NewSAST())
	reg.RegisterScanner(fakeSemgrep{ran: semgrepRan})
	reg.RegisterScanner(fakeGosec{ran: gosecRan})

	orig := scanInstallOffer
	t.Cleanup(func() { scanInstallOffer = orig })
	scanInstallOffer.terminal = func() bool { return false }
	scanInstallOffer.lookPath = notInstalled("gosec")

	t.Chdir(dir)
	var out bytes.Buffer
	err := runScan(context.Background(), "", scanOptions{format: "console", noPublish: true}, reg, &out)
	if err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Errorf("a scanner the descriptor asked for failed, and the run says %v", err)
	}
	if strings.Contains(out.String(), "FOUND") || strings.Contains(out.String(), "not-checked") {
		t.Errorf("a descriptor run printed FOUND or a not-checked caveat:\n%s", out.String())
	}
	if gosecRan.Load() == 0 {
		t.Error("the descriptor asked for gosec and it was not attempted")
	}
}
