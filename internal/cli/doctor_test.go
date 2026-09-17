package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/tools"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

const doctorSagaProvenance = `project: app
release:
  version: "1.0"
config:
  controls:
    provenance:
      enabled: true
components:
  - name: web
    images:
      - image: ghcr.io/acme/web:1
`

const doctorSagaRepoAndImage = `project: app
release:
  version: "1.0"
config:
  controllers:
    sca:
      enabled: true
    images:
      enabled: true
components:
  - name: web
    repositories:
      - url: .
    images:
      - image: alpine:3.19
`

const doctorSagaImagesOnly = `project: app
release:
  version: "1.0"
config:
  controllers:
    images:
      enabled: true
components:
  - name: web
    images:
      - image: alpine:3.19
`

const doctorSagaNoControls = `project: app
release:
  version: "1.0"
components:
  - name: web
    images:
      - image: alpine:3.19
`

// doctorSagaSAST enables sast; the scanners list controls whether gosec is required.
const doctorSagaSASTDefault = `project: app
release:
  version: "1.0"
config:
  controllers:
    sast:
      enabled: true
components:
  - name: web
    repositories:
      - url: .
`

const doctorSagaSASTGosec = `project: app
release:
  version: "1.0"
config:
  controllers:
    sast:
      enabled: true
      gosec:
        enabled: true
components:
  - name: web
    repositories:
      - url: .
`

// TestRunDoctorSASTScannerSelection verifies gosec is only a required tool when the sast scanner
// set selects it. Default sast (semgrep) must not demand gosec (it's opt-in).
func TestRunDoctorSASTScannerSelection(t *testing.T) {
	// Default sast → semgrep required, gosec not. With only semgrep+git present, doctor passes.
	var out bytes.Buffer
	if err := runDoctor(context.Background(), &out, builtins.Registry(),
		writeSaga(t, doctorSagaSASTDefault), doctorRun{}, fakeDetect("semgrep", "git"), nil); err != nil {
		t.Fatalf("default sast should not require gosec: %v\n%s", err, out.String())
	}
	if strings.Contains(out.String(), "gosec") {
		t.Errorf("gosec should not appear for default sast\n%s", out.String())
	}

	// Opt into gosec → now it's required; missing gosec fails the check and is listed.
	out.Reset()
	err := runDoctor(context.Background(), &out, builtins.Registry(),
		writeSaga(t, doctorSagaSASTGosec), doctorRun{}, fakeDetect("semgrep", "git"), nil)
	if err == nil {
		t.Fatalf("selecting gosec should require it (and it's missing)\n%s", out.String())
	}
	if !strings.Contains(out.String(), "gosec") {
		t.Errorf("gosec should be listed when selected\n%s", out.String())
	}
}

// fakeDetect reports the given binaries as found (others missing), without touching PATH.
func fakeDetect(found ...string) func(context.Context, tools.Tool) tools.Status {
	set := map[string]bool{}
	for _, b := range found {
		set[b] = true
	}
	return func(_ context.Context, t tools.Tool) tools.Status {
		if set[t.Binary] {
			return tools.Status{Tool: t, Found: true, Path: "/usr/bin/" + t.Binary, Version: "1.2.3"}
		}
		return tools.Status{Tool: t, Found: false}
	}
}

func TestRunDoctorAllPresent(t *testing.T) {
	var out bytes.Buffer
	err := runDoctor(context.Background(), &out, builtins.Registry(),
		writeSaga(t, doctorSagaRepoAndImage), doctorRun{}, fakeDetect("trivy", "git"), nil)
	if err != nil {
		t.Fatalf("runDoctor: %v", err)
	}
	s := out.String()
	for _, want := range []string{"Descriptor  ✓ valid", "trivy", "git", "✓ found", "All required tools present"} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q\n%s", want, s)
		}
	}
}

func TestRunDoctorMissingFails(t *testing.T) {
	var out bytes.Buffer
	// git present, trivy missing → non-zero.
	err := runDoctor(context.Background(), &out, builtins.Registry(),
		writeSaga(t, doctorSagaRepoAndImage), doctorRun{}, fakeDetect("git"), nil)
	if err == nil {
		t.Fatal("expected error when a required tool is missing")
	}
	s := out.String()
	// The row names the command rather than trivy.dev: Draugr distributes trivy, and the pinned
	// archive with its checksum checked is a better answer than whatever the download page is
	// serving today.
	if !strings.Contains(s, "✗ missing") || !strings.Contains(s, "install: draugr tools install trivy") {
		t.Errorf("output should flag the missing tool and name how to get it\n%s", s)
	}
	if !strings.Contains(s, "tools install") {
		t.Errorf("output should nudge provisioning\n%s", s)
	}
}

func TestRunDoctorInvalidDescriptor(t *testing.T) {
	var out bytes.Buffer
	err := runDoctor(context.Background(), &out, builtins.Registry(),
		writeSaga(t, invalidSaga), doctorRun{}, fakeDetect("trivy", "git"), nil)
	if err == nil {
		t.Fatal("expected error for invalid descriptor")
	}
	if !strings.Contains(err.Error(), "invalid descriptor") {
		t.Errorf("err = %v", err)
	}
	if !strings.Contains(out.String(), "✗ invalid") {
		t.Errorf("output should report the invalid descriptor\n%s", out.String())
	}
}

func TestRunDoctorNoSagaChecksAll(t *testing.T) {
	var out bytes.Buffer
	err := runDoctor(context.Background(), &out, builtins.Registry(),
		"", doctorRun{}, fakeDetect("trivy", "gitleaks", "semgrep", "gosec", "git", "nuclei", "syft",
			"kube-bench", "kubectl"), nil)
	if err != nil {
		t.Fatalf("runDoctor: %v", err)
	}
	s := out.String()
	if strings.Contains(s, "Descriptor") {
		t.Errorf("no saga given → should not print a descriptor line\n%s", s)
	}
	for _, bin := range []string{"trivy", "gitleaks", "semgrep", "gosec", "git", "nuclei", "syft",
		"kube-bench", "kubectl"} {
		if !strings.Contains(s, bin) {
			t.Errorf("full check should include %q\n%s", bin, s)
		}
	}
}

func TestRunDoctorJSON(t *testing.T) {
	var out bytes.Buffer
	err := runDoctor(context.Background(), &out, builtins.Registry(),
		writeSaga(t, doctorSagaRepoAndImage), doctorRun{json: true}, fakeDetect("git"), nil)
	if err == nil {
		t.Fatal("expected error (trivy missing)")
	}
	var report struct {
		Descriptor struct {
			Path  string `json:"path"`
			Valid bool   `json:"valid"`
		} `json:"descriptor"`
		Tools   []map[string]any `json:"tools"`
		Missing int              `json:"missing"`
	}
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out.String())
	}
	if !report.Descriptor.Valid {
		t.Error("descriptor should be reported valid")
	}
	if report.Missing != 1 {
		t.Errorf("missing = %d, want 1", report.Missing)
	}
	if len(report.Tools) != 2 { // trivy + git
		t.Errorf("tools = %d, want 2", len(report.Tools))
	}
}

func TestRequiredToolsDerivation(t *testing.T) {
	reg := builtins.Registry()

	// Repo + image controls → trivy and git.
	model, err := saga.LoadFile(writeSaga(t, doctorSagaRepoAndImage))
	if err != nil {
		t.Fatal(err)
	}
	if got := binaries(requiredTools(reg, model)); !slices.Equal(got, []string{"git", "trivy"}) {
		t.Errorf("repo+image required = %v, want [git trivy]", got)
	}

	// Images only → trivy, no git.
	model, err = saga.LoadFile(writeSaga(t, doctorSagaImagesOnly))
	if err != nil {
		t.Fatal(err)
	}
	if got := binaries(requiredTools(reg, model)); !slices.Equal(got, []string{"trivy"}) {
		t.Errorf("images-only required = %v, want [trivy]", got)
	}
}

// A tool the descriptor selected is required, whatever the catalog calls it. cosign is optional in
// the inventory view, where nothing has been chosen and the question is what Draugr could use. Once
// a descriptor turns on the control cosign is the scanner for, a doctor that still calls it
// optional reports a clean environment for a scan that cannot run.
func TestASelectedToolIsRequiredEvenIfTheCatalogCallsItOptional(t *testing.T) {
	reg := builtins.Registry()
	model, err := saga.LoadFile(writeSaga(t, doctorSagaProvenance))
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, tl := range requiredTools(reg, model) {
		if tl.Binary != "cosign" {
			continue
		}
		found = true
		if tl.Optional {
			t.Error("cosign is provenance's scanner here, so a missing one has to fail doctor")
		}
	}
	if !found {
		t.Fatal("provenance is enabled, so cosign should be required")
	}
}

// The row beside a tool name is where somebody reads what to do about it, so it names the command
// that fetches the pinned, checksum-verified build rather than an upstream page.
func TestTheInstallNoteNamesTheCommandWhereThereIsOne(t *testing.T) {
	if got := installAdvice(tools.Tool{Binary: "notation", InstallHint: "https://notaryproject.dev/x"}); got != "draugr tools install notation" {
		t.Errorf("advice = %q, want the command", got)
	}
	// And the upstream page for one Draugr does not distribute, where the command would succeed
	// and leave the tool missing.
	hint := "proprietary; install from the vendor"
	if got := installAdvice(tools.Tool{Binary: "mend", InstallHint: hint}); got != hint {
		t.Errorf("advice = %q, want %q", got, hint)
	}
	// A hint carrying a prerequisite keeps it, even for a tool the command fetches. kube-bench
	// ships its benchmarks as a cfg/ tree beside the binary and people install the binary alone,
	// after which every run dies naming an internal structure rather than the missing directory.
	// The command does not remove that, so replacing the sentence with it drops the half the
	// reader is about to need.
	kb := tools.Catalog()["kube-bench"]
	if got := installAdvice(kb); got != kb.InstallHint {
		t.Errorf("advice = %q, want the hint kept: %q", got, kb.InstallHint)
	}
	if !strings.Contains(installAdvice(kb), "cfg/") {
		t.Error("the cfg/ directory is the whole of what somebody gets wrong here")
	}
}

func TestDoctorCommandViaCobra(t *testing.T) {
	// A saga with no enabled controls needs no tools, so the command succeeds regardless of
	// what's installed in the test environment.
	cmd := newDoctorCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--offline", writeSaga(t, doctorSagaNoControls)}) // --offline: no network in unit tests
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	// Nothing is enabled, so nothing is required. Which must not read the same as having checked a
	// list of tools and found them all.
	if !strings.Contains(out.String(), "No external tools required") {
		t.Errorf("output = %q", out.String())
	}
}

func TestDraugrVersionReportAndLine(t *testing.T) {
	// latest available → update-available report + line.
	r := draugrVersionReport(context.Background(), func(context.Context) (string, error) { return "9.9.9", nil })
	if r.Latest != "9.9.9" || !r.UpdateAvailable {
		t.Errorf("report = %+v, want latest 9.9.9 + update available", r)
	}
	var b bytes.Buffer
	writeDraugrLine(&b, r)
	if !strings.Contains(b.String(), "latest: v9.9.9") || !strings.Contains(b.String(), "self-update") {
		t.Errorf("update line = %q", b.String())
	}

	// nil resolver (offline/opt-out) → no latest, plain line.
	if r := draugrVersionReport(context.Background(), nil); r.Latest != "" {
		t.Errorf("nil resolver should not set latest, got %+v", r)
	}
	// resolver error → best-effort, no latest.
	if r := draugrVersionReport(context.Background(),
		func(context.Context) (string, error) { return "", errors.New("x") }); r.Latest != "" {
		t.Errorf("resolver error should omit latest, got %+v", r)
	}

	// up-to-date line.
	b.Reset()
	writeDraugrLine(&b, draugrReport{Version: "9.9.9", Latest: "9.9.9"})
	if !strings.Contains(b.String(), "up to date") {
		t.Errorf("up-to-date line = %q", b.String())
	}
}

func binaries(ts []tools.Tool) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = t.Binary
	}
	return out
}

func TestRequiredToolsIncludesSyftOnlyWhenSBOMIsEnabled(t *testing.T) {
	// SBOM generation is not a control, so no scanner declares syft. Without the explicit hook
	// a Saga could ask for SBOMs and doctor would report a ready environment.
	reg := builtins.Registry()

	off := &saga.Model{Release: saga.Release{Version: "1"}}
	for _, tl := range requiredTools(reg, off) {
		if tl.Binary == "syft" {
			t.Error("syft should not be required when config.sbom is absent")
		}
	}

	on := &saga.Model{
		Release: saga.Release{Version: "1"},
		Config:  saga.Config{SBOM: &saga.SBOMConfig{Enabled: true}},
	}
	var found bool
	for _, tl := range requiredTools(reg, on) {
		if tl.Binary == "syft" {
			found = true
		}
	}
	if !found {
		t.Error("syft should be required when config.sbom is enabled")
	}

	// enabled:false is a deliberate off switch, not a request.
	paused := &saga.Model{
		Release: saga.Release{Version: "1"},
		Config:  saga.Config{SBOM: &saga.SBOMConfig{Enabled: false}},
	}
	for _, tl := range requiredTools(reg, paused) {
		if tl.Binary == "syft" {
			t.Error("syft should not be required when sbom is explicitly disabled")
		}
	}
}

// TestRequiredToolsIncludesAReachabilityAnalyzer is the mirror of the syft test above, for the
// other requirement no scanner block declares. A reachability analyzer is named in
// config.reachability and is deliberately not selectable from a scanner block, so the scanner
// selection filters it out with everything the control will not run, and doctor reported a ready
// environment for a descriptor whose scan then stopped on a missing analyzer.
func TestRequiredToolsIncludesAReachabilityAnalyzer(t *testing.T) {
	reg := builtins.Registry()
	sca := saga.Config{
		Controls: map[string]saga.ControllerSettings{"sca": {"enabled": true}},
	}
	requires := func(m *saga.Model, binary string) bool {
		for _, tl := range requiredTools(reg, m) {
			if tl.Binary == binary {
				return true
			}
		}
		return false
	}

	t.Run("named, with its control enabled", func(t *testing.T) {
		on := &saga.Model{Release: saga.Release{Version: "1"}, Config: sca}
		on.Config.Reachability = &saga.ReachabilityConfig{Analyzers: []string{"govulncheck"}}
		if !requires(on, "govulncheck") {
			t.Error("an analyzer named in config.reachability is a tool the scan will run")
		}
	})

	t.Run("not named", func(t *testing.T) {
		off := &saga.Model{Release: saga.Release{Version: "1"}, Config: sca}
		if requires(off, "govulncheck") {
			t.Error("govulncheck is opt-in; an absent reachability block does not ask for it")
		}
	})

	// config.reachability is project-wide, so an analyzer whose control is switched off is a tool
	// this scan will never reach for. Asking for it sends somebody to install a scanner that would
	// not have run.
	t.Run("named, with its control disabled", func(t *testing.T) {
		paused := &saga.Model{
			Release: saga.Release{Version: "1"},
			Config: saga.Config{
				Controls:     map[string]saga.ControllerSettings{"sca": {"enabled": false}},
				Reachability: &saga.ReachabilityConfig{Analyzers: []string{"govulncheck"}},
			},
		}
		if requires(paused, "govulncheck") {
			t.Error("an analyzer for a disabled control is not required")
		}
	})

	// An empty list is the same as omitting the block, which is what the field documents.
	t.Run("named as an empty list", func(t *testing.T) {
		empty := &saga.Model{Release: saga.Release{Version: "1"}, Config: sca}
		empty.Config.Reachability = &saga.ReachabilityConfig{}
		if requires(empty, "govulncheck") {
			t.Error("no analyzers named means none required")
		}
	})
}

const doctorSagaInfrastructure = `project: platform
release: {version: "1.0"}
config:
  controllers:
    infrastructure:
      enabled: true
      kubeBench: {enabled: true}
components:
  - name: cluster
    infrastructure: [{kind: kubernetes, ref: prod}]
`

// The same control with its default scanner, which reads the Kubernetes API and shells out to
// nothing.
const doctorSagaInfrastructureDefault = `project: platform
release: {version: "1.0"}
config:
  controllers:
    infrastructure: {enabled: true}
components:
  - name: cluster
    infrastructure: [{kind: kubernetes, ref: prod}]
`

// Some tools shell out in turn. kube-bench's CIS policy checks are scripts that invoke kubectl, so
// a machine with kube-bench and no kubectl fails at scan time, after a preflight that said
// everything was fine.
func TestRequiredToolsIncludesASecondaryBinary(t *testing.T) {
	model, err := saga.LoadFile(writeSaga(t, doctorSagaInfrastructure))
	if err != nil {
		t.Fatal(err)
	}
	got := binaries(requiredTools(builtins.Registry(), model))
	if !slices.Equal(got, []string{"kube-bench", "kubectl"}) {
		t.Errorf("infrastructure required = %v, want [kube-bench kubectl]", got)
	}
}

// The other half of the same idea: a control requires the scanners it will run, not every one that
// could serve it. The default here needs no binary at all, so demanding kube-bench and kubectl
// would send someone to install tools the scan never uses, and report a control as unable to run
// when it can.
func TestRequiredToolsFollowsScannerSelection(t *testing.T) {
	model, err := saga.LoadFile(writeSaga(t, doctorSagaInfrastructureDefault))
	if err != nil {
		t.Fatal(err)
	}
	if got := binaries(requiredTools(builtins.Registry(), model)); len(got) != 0 {
		t.Errorf("infrastructure required = %v, want none, the default scanner execs nothing", got)
	}
}

// A scanner needing a tool the catalog has never heard of must not vanish from the check: a
// `doctor` that drops the names it does not recognize reports "all required tools present" for
// a control that cannot run. The one command whose job is answering "will a scan work?" would
// be answering yes because it did not recognize the name.
func TestRequiredToolsKeepsBinariesTheCatalogDoesNotKnow(t *testing.T) {
	reg := engine.NewRegistry()
	reg.RegisterController(unknownToolController{})
	reg.RegisterScanner(unknownToolScanner{})

	model, err := saga.LoadFile(writeSaga(t, doctorSagaRepoAndImage))
	if err != nil {
		t.Fatal(err)
	}
	got := binaries(requiredTools(reg, model))
	if !slices.Contains(got, "some-future-tool") {
		t.Errorf("a scanner's binary should be checked even when Draugr does not package it: %v", got)
	}
}

// unknownToolScanner needs a binary that is deliberately not in the tool catalog.
type unknownToolScanner struct{}

func (unknownToolScanner) Info() plugin.ScannerInfo {
	return plugin.ScannerInfo{
		Name:        "future",
		Binary:      "some-future-tool",
		Controls:    []string{"images"},
		TargetKinds: []plugin.TargetKind{plugin.TargetImage},
	}
}

func (unknownToolScanner) Scan(context.Context, plugin.Target, plugin.Config) (sarif.Report, error) {
	return sarif.Report{}, nil
}

type unknownToolController struct{}

func (unknownToolController) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: "images", Scope: plugin.ScopeComponent, DefaultScanners: []string{"future"}}
}

func (unknownToolController) Plan(saga.Model, *saga.Component) ([]plugin.ScanJob, error) {
	return nil, nil
}

func (unknownToolController) Aggregate([]sarif.Report) (plugin.ControlResult, error) {
	return plugin.ControlResult{Control: "images"}, nil
}

func TestDoctorWithoutADescriptorReportsRatherThanFails(t *testing.T) {
	// Nothing has been selected, so nothing is required. Treating the whole catalog as required told
	// a clean machine it was missing seven tools it may never need, kube-bench most clearly, since
	// the default infrastructure scanner is native and needs no binary.
	var out bytes.Buffer
	if err := runDoctor(context.Background(), &out, builtins.Registry(),
		"", doctorRun{}, fakeDetect(), nil); err != nil {
		t.Fatalf("an inventory should not fail: %v\n%s", err, out.String())
	}
	got := out.String()
	if !strings.Contains(got, "Which you need depends on your descriptor") {
		t.Errorf("it should say what would answer the question:\n%s", got)
	}
	if strings.Contains(got, "required tool(s) missing") {
		t.Errorf("nothing is required without a descriptor:\n%s", got)
	}
}

func TestDoctorWithADescriptorStillFailsOnWhatItNeeds(t *testing.T) {
	// The question that does have an answer: these tools were selected by this descriptor, and
	// they are not here.
	var out bytes.Buffer
	err := runDoctor(context.Background(), &out, builtins.Registry(),
		writeSaga(t, doctorSagaSASTDefault), doctorRun{}, fakeDetect("git"), nil)
	if err == nil {
		t.Fatalf("a descriptor whose tools are absent should fail\n%s", out.String())
	}
	// The error is the advice. Printed as a line above it as well, the count and the remedy
	// appeared together and the count again on the next line.
	if !strings.Contains(err.Error(), "required tool missing") {
		t.Errorf("got %v", err)
	}
	if !strings.Contains(err.Error(), "draugr tools install") {
		t.Errorf("the failure should say what to run: %v", err)
	}
	// And it is not printed twice: the block above ends with the table, not with a copy of this.
	if strings.Contains(out.String(), "required tool missing") {
		t.Errorf("the advice is in the error and was written to the output too:\n%s", out.String())
	}
}

// doctorSagaUncovered declares an image and a host while enabling only the repository controls,
// the descriptor that scans clean having looked at neither.
const doctorSagaUncovered = `project: app
release:
  version: "1.0"
config:
  controllers:
    secrets:
      enabled: true
components:
  - name: web
    repositories:
      - url: .
    images:
      - image: alpine:3.19
    hosts:
      - name: ui
        url: https://example.com
`

// TestDoctorReportsUncoveredSurface is the half of "will this scan tell me what I think it will"
// that tool detection cannot answer. Every tool can be present and the run still cover less than
// the reader assumes, because nothing is looking at what the descriptor declares.
func TestDoctorReportsUncoveredSurface(t *testing.T) {
	var out bytes.Buffer
	err := runDoctor(context.Background(), &out, builtins.Registry(),
		writeSaga(t, doctorSagaUncovered), doctorRun{}, fakeDetect("gitleaks", "git"), nil)
	if err != nil {
		t.Fatalf("reporting is not failing: %v\n%s", err, out.String())
	}
	// Column values rather than a welded pair. `web images` ran two vocabularies together, and
	// the control that would close the gap is spelled the same as the surface it reads.
	for _, want := range []string{
		"NOT CHECKED", "Component  Surface  Controls off",
		"web        images   images", "web        hosts    dast, headers, tls",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("doctor never mentioned %q:\n%s", want, out.String())
		}
	}
}

// TestDoctorFailsOnUncoveredOnlyWhenAsked pins the default. A deliberately narrow descriptor is a
// legitimate thing to have, and a preflight that fails on a choice somebody made is one people
// learn to pass --no-verify to.
func TestDoctorFailsOnUncoveredOnlyWhenAsked(t *testing.T) {
	path := writeSaga(t, doctorSagaUncovered)
	for _, c := range []struct {
		name    string
		run     doctorRun
		wantErr bool
	}{
		{"reported by default", doctorRun{}, false},
		{"failed when asked", doctorRun{failOnUncovered: true}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			var out bytes.Buffer
			err := runDoctor(context.Background(), &out, builtins.Registry(),
				path, c.run, fakeDetect("gitleaks", "git"), nil)
			if (err != nil) != c.wantErr {
				t.Errorf("error = %v, want error: %v\n%s", err, c.wantErr, out.String())
			}
		})
	}
}

// TestDoctorMissingToolOutranksUncoveredSurface keeps the more serious answer the one given. A
// tool that is absent stops the scan outright; an uncovered surface only narrows it, and a reader
// sent to enable a control when the real problem is an uninstalled binary is sent the wrong way.
func TestDoctorMissingToolOutranksUncoveredSurface(t *testing.T) {
	var out bytes.Buffer
	err := runDoctor(context.Background(), &out, builtins.Registry(),
		writeSaga(t, doctorSagaUncovered), doctorRun{failOnUncovered: true}, fakeDetect("git"), nil)
	if err == nil {
		t.Fatal("a missing tool should still fail")
	}
	if !strings.Contains(err.Error(), "tool") {
		t.Errorf("the missing tool should be the reported failure, got: %v", err)
	}
}

// TestDoctorSaysNothingWhenEverySurfaceIsCovered keeps the note from becoming furniture. A caveat
// that appears on every run is one nobody reads on the run that matters.
func TestDoctorSaysNothingWhenEverySurfaceIsCovered(t *testing.T) {
	var out bytes.Buffer
	err := runDoctor(context.Background(), &out, builtins.Registry(),
		writeSaga(t, doctorSagaRepoAndImage), doctorRun{failOnUncovered: true},
		fakeDetect("trivy", "git"), nil)
	if err != nil {
		t.Fatalf("a covered descriptor must not fail even with the flag: %v\n%s", err, out.String())
	}
	if strings.Contains(out.String(), "Not checked") {
		t.Errorf("nothing is uncovered, so nothing should be reported:\n%s", out.String())
	}
}

// TestDoctorJSONCarriesUncoveredSurface stops the two answers diverging. A pipeline reading --json
// and a person reading the table have to be told the same thing.
func TestDoctorJSONCarriesUncoveredSurface(t *testing.T) {
	var out bytes.Buffer
	if err := runDoctor(context.Background(), &out, builtins.Registry(),
		writeSaga(t, doctorSagaUncovered), doctorRun{json: true},
		fakeDetect("gitleaks", "git"), nil); err != nil {
		t.Fatalf("runDoctor: %v", err)
	}
	var got struct {
		UncoveredSurfaces []string `json:"uncoveredSurfaces"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, out.String())
	}
	if len(got.UncoveredSurfaces) != 2 {
		t.Errorf("uncoveredSurfaces = %v, want the image and the host", got.UncoveredSurfaces)
	}
}

// TestMissingToolsAdviceOnlyOffersWhatWouldWork covers the difference between help and a wild
// goose chase.
//
// Some scanners are execed but never distributed. The Mend CLI is proprietary, so `draugr tools
// install` cannot fetch them. Suggesting it anyway is worse than saying nothing: the command runs,
// succeeds, and the tool is still missing.
func TestMissingToolsAdviceOnlyOffersWhatWouldWork(t *testing.T) {
	missing := func(binary string) tools.Status {
		return tools.Status{Tool: tools.Tool{Binary: binary}, Found: false}
	}

	// The Mend CLI is proprietary: Draugr execs it and can never fetch it.
	only := missingToolsAdvice([]tools.Status{missing("mend")})
	if strings.Contains(only, "tools install") {
		t.Errorf("the Mend CLI is not something Draugr can fetch, so this sends the reader to a "+
			"command that will not find it: %q", only)
	}
	if !strings.Contains(only, "1 required tool") {
		t.Errorf("advice should still say how many are missing: %q", only)
	}

	both := missingToolsAdvice([]tools.Status{missing("mend"), missing("trivy")})
	if !strings.Contains(both, "tools install") {
		t.Errorf("trivy is installable, so the offer should stand: %q", both)
	}
	if !strings.Contains(both, "2 required tool") {
		t.Errorf("advice should count both: %q", both)
	}

	// A tool that is present but has no data cannot run either, and is counted with the rest.
	noData := missingToolsAdvice([]tools.Status{
		{Tool: tools.Tool{Binary: "mend"}, Found: true, DataChecked: true, DataFound: false},
	})
	if !strings.Contains(noData, "1 required tool") {
		t.Errorf("a tool without its data is still unusable: %q", noData)
	}
}

// TestEveryScannerBinaryIsInstallableOrSourced closes the third gap unit tests cannot see.
//
// `draugr tools install` fetches pinned releases Draugr verified, which it can only do for tools
// it vouched for. A scanner whose binary is neither in that catalog nor named here leaves doctor
// telling somebody to run a command that will never find it, advice worse than none, because it
// sends them looking for a bug in Draugr rather than at the tool's own documentation.
//
// Crossed against the live registry, so registering a scanner is what triggers the requirement.
func TestEveryScannerBinaryIsInstallableOrSourced(t *testing.T) {
	t.Parallel()

	catalog := tools.Catalog()
	for _, s := range builtins.Registry().Scanners() {
		info := s.Info()
		for _, binary := range append([]string{info.Binary}, info.AlsoRequires...) {
			if binary == "" || binary == "git" {
				continue // git is assumed present, not provisioned
			}
			if _, installable := catalog[binary]; installable {
				continue
			}
			if _, sourced := externalTools[binary]; sourced {
				continue
			}
			t.Errorf("scanner %q needs %q, which Draugr neither installs nor knows a source for: "+
				"doctor will suggest `draugr tools install %s`, and that will never find it. Add "+
				"it to externalTools in internal/cli/doctor.go, or to the tool catalog",
				info.Name, binary, binary)
		}
	}
}

// TestEveryExternalToolIsStillNeeded keeps the list from outliving the scanner that required it.
// A stale entry is harmless at runtime and misleading to read, which is how a list stops being
// trusted as a description of anything.
func TestEveryExternalToolIsStillNeeded(t *testing.T) {
	t.Parallel()

	needed := map[string]bool{}
	for _, s := range builtins.Registry().Scanners() {
		info := s.Info()
		needed[info.Binary] = true
		for _, extra := range info.AlsoRequires {
			needed[extra] = true
		}
	}
	for binary := range externalTools {
		if !needed[binary] {
			t.Errorf("externalTools names %q, which no registered scanner requires", binary)
		}
	}
}

// toolAt builds a found tool at a version, for the comparison against what Draugr pins.
func toolAt(binary, version string) tools.Status {
	return tools.Status{Tool: tools.Tool{Binary: binary}, Found: true, Version: version, Path: "/x/" + binary}
}

// A tool Draugr does not pin has nothing to be compared against, and a tool matching its pin has
// nothing to say. Only the third case is information.
func TestUntestedVersionOnlySpeaksWhenItHasSomethingToSay(t *testing.T) {
	pinned := tools.PinnedVersion("trivy")
	if pinned == "" {
		t.Fatal("trivy has no pin, so this test cannot say anything")
	}
	for _, tc := range []struct {
		name string
		st   tools.Status
		want string
	}{
		{"running the pinned build", toolAt("trivy", pinned), ""},
		{"a leading v is not a difference", toolAt("trivy", "v"+pinned), ""},
		{"running something else", toolAt("trivy", "0.1.0"), pinned},
		{"no pin to compare against", toolAt("git", "2.55.0"), ""},
		{"not found", tools.Status{Tool: tools.Tool{Binary: "trivy"}}, ""},
		{"found but the version could not be read", tools.Status{
			Tool: tools.Tool{Binary: "trivy"}, Found: true, Err: errors.New("probe failed"),
		}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := untestedVersion(tc.st); got != tc.want {
				t.Errorf("untestedVersion = %q, want %q", got, tc.want)
			}
		})
	}
}

// The row carries the detail and one line carries the count, because a machine that has not
// reinstalled in a while has most of them and a mark on every row is not a mark.
func TestTheTableNamesTheTestedVersionAndCountsThemOnce(t *testing.T) {
	pinned := tools.PinnedVersion("trivy")
	var buf bytes.Buffer
	writeDoctorTable(&buf, []tools.Status{toolAt("trivy", "0.1.0"), toolAt("git", "2.55.0")})
	out := buf.String()
	if !strings.Contains(out, "tested against "+pinned) {
		t.Errorf("the row does not name the version Draugr tests:\n%s", out)
	}
	if !strings.Contains(out, "1 tool is not the version Draugr tests") {
		t.Errorf("the count is missing or does not agree with itself:\n%s", out)
	}
	if !strings.Contains(out, "tools install --force") {
		t.Errorf("the line says there is a problem and not what closes it:\n%s", out)
	}
}

// Nothing to say means saying nothing: a machine running exactly what Draugr tests must not be
// told about it.
func TestTheTableIsSilentWhenEveryToolMatches(t *testing.T) {
	var buf bytes.Buffer
	writeDoctorTable(&buf, []tools.Status{toolAt("trivy", tools.PinnedVersion("trivy"))})
	if strings.Contains(buf.String(), "not the version") {
		t.Errorf("a machine running the tested build was warned:\n%s", buf.String())
	}
}

// --strict is for a pipeline that would rather stop than scan with a build nothing has exercised.
// Without it the same machine passes, because a different version is very likely fine and a check
// that fails on very-likely-fine is one people stop running.
func TestDoctorStrictFailsOnAnUntestedVersionAndTheDefaultDoesNot(t *testing.T) {
	// fakeDetect reports 1.2.3 for everything, which is nothing's pin.
	detect := fakeDetect("semgrep", "git", "trivy", "gitleaks")
	saga := writeSaga(t, doctorSagaSASTDefault)

	var out bytes.Buffer
	if err := runDoctor(context.Background(), &out, builtins.Registry(), saga, doctorRun{}, detect, nil); err != nil {
		t.Fatalf("a version difference must not fail by default: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "not the version Draugr tests") {
		t.Errorf("the default should still say so, just not fail:\n%s", out.String())
	}

	out.Reset()
	err := runDoctor(context.Background(), &out, builtins.Registry(), saga, doctorRun{strict: true}, detect, nil)
	if err == nil {
		t.Fatalf("--strict was asked for and an untested version passed\n%s", out.String())
	}
	if !strings.Contains(err.Error(), "tools install --force") {
		t.Errorf("the error says there is a problem and not what closes it: %v", err)
	}
}
