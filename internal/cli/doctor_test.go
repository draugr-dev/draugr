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

const doctorSagaRepoAndImage = `release:
  name: app
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

const doctorSagaImagesOnly = `release:
  name: app
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

const doctorSagaNoControls = `release:
  name: app
  version: "1.0"
components:
  - name: web
    images:
      - image: alpine:3.19
`

// doctorSagaSAST enables sast; the scanners list controls whether gosec is required.
const doctorSagaSASTDefault = `release:
  name: app
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

const doctorSagaSASTGosec = `release:
  name: app
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

// TestRunDoctorSASTScannerSelection verifies gosec is only a required tool when the sast
// scanner set selects it — default sast (semgrep) must not demand gosec (it's opt-in).
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
	if !strings.Contains(s, "✗ missing") || !strings.Contains(s, "trivy.dev") {
		t.Errorf("output should flag the missing tool with a hint\n%s", s)
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
	// Nothing is enabled, so nothing is required — which must not read the same as having
	// checked a list of tools and found them all.
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

	off := &saga.Model{Release: saga.Release{Name: "a", Version: "1"}}
	for _, tl := range requiredTools(reg, off) {
		if tl.Binary == "syft" {
			t.Error("syft should not be required when config.sbom is absent")
		}
	}

	on := &saga.Model{
		Release: saga.Release{Name: "a", Version: "1"},
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
		Release: saga.Release{Name: "a", Version: "1"},
		Config:  saga.Config{SBOM: &saga.SBOMConfig{Enabled: false}},
	}
	for _, tl := range requiredTools(reg, paused) {
		if tl.Binary == "syft" {
			t.Error("syft should not be required when sbom is explicitly disabled")
		}
	}
}

const doctorSagaInfrastructure = `release: {name: platform, version: "1.0"}
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
const doctorSagaInfrastructureDefault = `release: {name: platform, version: "1.0"}
config:
  controllers:
    infrastructure: {enabled: true}
components:
  - name: cluster
    infrastructure: [{kind: kubernetes, ref: prod}]
`

// Some tools shell out in turn. kube-bench's CIS policy checks are scripts that invoke kubectl,
// so a machine with kube-bench and no kubectl fails at scan time — after a preflight that said
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

// The other half of the same idea: a control requires the scanners it will run, not every one
// that could serve it. The default here needs no binary at all, so demanding kube-bench and
// kubectl would send someone to install tools the scan never uses — and report a control as
// unable to run when it can.
func TestRequiredToolsFollowsScannerSelection(t *testing.T) {
	model, err := saga.LoadFile(writeSaga(t, doctorSagaInfrastructureDefault))
	if err != nil {
		t.Fatal(err)
	}
	if got := binaries(requiredTools(builtins.Registry(), model)); len(got) != 0 {
		t.Errorf("infrastructure required = %v, want none — the default scanner execs nothing", got)
	}
}

// A scanner needing a tool the catalog has never heard of must not vanish from the check: a
// `doctor` that drops the names it does not recognise reports "all required tools present" for
// a control that cannot run. The one command whose job is answering "will a scan work?" would
// be answering yes because it did not recognise the name.
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
	// Nothing has been selected, so nothing is required. Treating the whole catalogue as
	// required told a clean machine it was missing seven tools it may never need — kube-bench
	// most clearly, since the default infrastructure scanner is native and needs no binary.
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
	if !strings.Contains(err.Error(), "required tool(s) not found") {
		t.Errorf("got %v", err)
	}
}

// doctorSagaUncovered declares an image and a host while enabling only the repository controls —
// the descriptor that scans clean having looked at neither.
const doctorSagaUncovered = `release:
  name: app
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
	for _, want := range []string{"Not checked", "declares images", "declares hosts"} {
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
