package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/netpolicy"
	"github.com/draugr-dev/draugr/internal/tools"
)

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
	// The row names the command rather than trivy.dev: `draugr tools install` fetches trivy, and the pinned
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

// The row beside a tool name is where somebody reads what to do about it, so it names the command
// that fetches the pinned, checksum-verified build rather than an upstream page.
func TestTheInstallNoteNamesTheCommandWhereThereIsOne(t *testing.T) {
	if got := installAdvice(tools.Tool{Binary: "notation", InstallHint: "https://notaryproject.dev/x"}); got != "draugr tools install notation" {
		t.Errorf("advice = %q, want the command", got)
	}
	// And the upstream page for one `draugr tools install` does not fetch, where the command would succeed
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
	t.Setenv(netpolicy.EnvVar, "")
	t.Cleanup(func() { netpolicy.SetOffline(false) })
	root := newRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"doctor", "--offline", writeSaga(t, doctorSagaNoControls)}) // --offline: no network in unit tests
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	// Nothing is enabled, so nothing is required. Which must not read the same as having checked a
	// list of tools and found them all.
	if !strings.Contains(out.String(), "No external tools required") {
		t.Errorf("output = %q", out.String())
	}
}

// With no tool required there is no TOOLS heading or header row, only the line that says so.
func TestDoctorPrintsNoToolsTableWhenNothingIsRequired(t *testing.T) {
	var out bytes.Buffer
	if err := runDoctor(context.Background(), &out, builtins.Registry(), writeSaga(t, doctorSagaNoControls),
		doctorRun{}, fakeDetect(), nil); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if strings.Contains(got, "TOOLS") || strings.Contains(got, "Status") {
		t.Errorf("an empty tool table was printed:\n%s", got)
	}
	if !strings.Contains(got, "No external tools required.") {
		t.Errorf("the closing line is missing:\n%s", got)
	}
	if strings.Contains(got, "\n\n\n") {
		t.Errorf("two blank lines where the table was:\n%q", got)
	}
}

// `doctor --offline` is the root flag, and it sets the network policy every fetch reads. A flag of
// doctor's own would shadow it, so doctor would skip its own checks while every fetch it reached
// still read the policy as online.
func TestDoctorOfflineSetsTheNetworkPolicy(t *testing.T) {
	t.Setenv(netpolicy.EnvVar, "")
	t.Cleanup(func() { netpolicy.SetOffline(false) })
	root := newRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"doctor", "--offline", writeSaga(t, doctorSagaNoControls)})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !netpolicy.Offline() {
		t.Error("doctor --offline left the network policy online")
	}
	if !strings.Contains(out.String(), "(offline: none of these will happen)") {
		t.Errorf("the NETWORK section does not say it is offline:\n%s", out.String())
	}
	if strings.Contains(out.String(), "latest:") || strings.Contains(out.String(), "up to date") {
		t.Errorf("the release check ran under --offline:\n%s", out.String())
	}
	if flag := newDoctorCommand().Flags().Lookup("offline"); flag != nil {
		t.Error("doctor declares an --offline of its own, which shadows the root flag")
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
			// An image and a host, each uncovered: the count agrees with its noun.
			if c.wantErr && err.Error() != "2 declared surfaces not covered by an enabled control" {
				t.Errorf("error = %q", err)
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
// Some scanners are execed and never fetched. The Mend CLI is proprietary, so `draugr tools
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
			got := ""
			if target := versionTargetFor(tc.st.Tool.Binary, nil); offTarget(tc.st, target) {
				got = target.version
			}
			if got != tc.want {
				t.Errorf("off target = %q, want %q", got, tc.want)
			}
		})
	}
}

// The row carries the detail and one line carries the count, because a machine that has not
// reinstalled in a while has most of them and a mark on every row is not a mark.
func TestTheTableNamesTheTestedVersionAndCountsThemOnce(t *testing.T) {
	pinned := tools.PinnedVersion("trivy")
	var buf bytes.Buffer
	writeDoctorTable(&buf, []tools.Status{toolAt("trivy", "0.1.0"), toolAt("git", "2.55.0")}, nil)
	out := buf.String()
	if !strings.Contains(out, "tested against "+pinned) {
		t.Errorf("the row does not name the version Draugr tests:\n%s", out)
	}
	if !strings.Contains(out, "1 installed tool is not the version Draugr tests. "+
		"`draugr tools install --force` installs the tested build.") {
		t.Errorf("the count is missing or does not agree with itself:\n%s", out)
	}
	if got := offTargetPhrase(4, 0); got != "4 installed tools are not the version Draugr tests" {
		t.Errorf("plural = %q", got)
	}
}

// Nothing to say means saying nothing: a machine running exactly what Draugr tests must not be
// told about it.
func TestTheTableIsSilentWhenEveryToolMatches(t *testing.T) {
	var buf bytes.Buffer
	writeDoctorTable(&buf, []tools.Status{toolAt("trivy", tools.PinnedVersion("trivy"))}, nil)
	if strings.Contains(buf.String(), "not the version") {
		t.Errorf("a machine running the tested build was warned:\n%s", buf.String())
	}
}

// Without a descriptor, --strict still answers about the tools that are present. A missing tool in
// the inventory is reported and not failed, and it does not stand in for the answer --strict asked.
func TestDoctorStrictWithoutADescriptorAppliesWhenAToolIsMissing(t *testing.T) {
	detect := fakeDetect("trivy") // 1.2.3, nothing's pin; everything else missing
	var out bytes.Buffer
	err := runDoctor(context.Background(), &out, builtins.Registry(), "", doctorRun{strict: true}, detect, nil)
	if err == nil || !strings.Contains(err.Error(), "not the version Draugr tests") {
		t.Fatalf("err = %v, want --strict to fail on trivy's version\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "are not installed") {
		t.Errorf("the missing tools should still be reported:\n%s", out.String())
	}

	// Without --strict the same inventory passes.
	out.Reset()
	if err := runDoctor(context.Background(), &out, builtins.Registry(), "", doctorRun{}, detect, nil); err != nil {
		t.Errorf("an inventory without --strict failed: %v", err)
	}
}

// With a descriptor, a missing tool leads: it stops the scan outright, and --strict's complaint
// about a version is the smaller problem.
func TestDoctorStrictLetsAMissingToolLeadWithADescriptor(t *testing.T) {
	detect := fakeDetect("git") // git at 1.2.3, semgrep missing
	err := runDoctor(context.Background(), &bytes.Buffer{}, builtins.Registry(),
		writeSaga(t, doctorSagaSASTDefault), doctorRun{strict: true}, detect, nil)
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Errorf("err = %v, want the missing tool's message", err)
	}
}

// Doctor refuses a misspelled control with the message validate and scan give, did-you-mean
// included. The schema accepts any key, so without the check a misspelled control passes doctor and
// fails the scan.
func TestDoctorRefusesAMisspelledControl(t *testing.T) {
	path := writeSaga(t, `project: app
release:
  version: "1.0"
config:
  controls:
    secrts:
      enabled: true
components:
  - name: web
    repositories:
      - url: .
`)
	var out bytes.Buffer
	err := runDoctor(context.Background(), &out, builtins.Registry(), path, doctorRun{}, fakeDetect(), nil)
	if err == nil {
		t.Fatalf("a misspelled control passed doctor:\n%s", out.String())
	}
	if !strings.Contains(err.Error(), `did you mean "secrets"?`) {
		t.Errorf("err = %v, want validate's did-you-mean", err)
	}
	if !strings.Contains(out.String(), "✗ invalid") {
		t.Errorf("the descriptor line should say invalid:\n%s", out.String())
	}
	// The same check validate makes, word for word.
	verr := loadAndCheck(path)
	if verr == nil {
		t.Fatal("validate accepted the descriptor doctor refused")
	}
	problem, _, _ := strings.Cut(verr.Error(), "\n")
	if !strings.Contains(err.Error(), problem) {
		t.Errorf("doctor's message %q does not carry validate's %q", err, problem)
	}
}

// The JSON's missing is the count the exit code is decided on: a tool present without its data is
// missing, and an optional tool that is absent is not.
func TestDoctorJSONCountsWhatTheExitCodeCounts(t *testing.T) {
	detect := func(_ context.Context, tl tools.Tool) tools.Status {
		if tl.Binary == "trivy" {
			tl.DataHint = "run `trivy image --download-db-only`"
			return tools.Status{Tool: tl, Found: true, Version: "1.2.3", Path: "/usr/bin/trivy",
				DataChecked: true, DataFound: false}
		}
		return tools.Status{Tool: tl, Found: true, Version: "1.2.3", Path: "/usr/bin/" + tl.Binary}
	}
	var out bytes.Buffer
	err := runDoctor(context.Background(), &out, builtins.Registry(), writeSaga(t, doctorSagaRepoAndImage),
		doctorRun{json: true}, detect, nil)
	if err == nil {
		t.Fatal("a required tool without its data should fail the check")
	}
	var got struct {
		Missing int `json:"missing"`
		Tools   []struct {
			Binary string `json:"binary"`
			Hint   string `json:"hint"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, out.String())
	}
	if got.Missing != 1 {
		t.Errorf("missing = %d, want 1 for trivy with no data\n%s", got.Missing, out.String())
	}
	hinted := false
	for _, tr := range got.Tools {
		if tr.Binary == "trivy" {
			hinted = tr.Hint == "run `trivy image --download-db-only`"
		}
	}
	if !hinted {
		t.Errorf("trivy's hint should say how to get its data:\n%s", out.String())
	}

	// An optional tool that is absent is reported and not counted, in the inventory as in the text.
	out.Reset()
	optional := func(_ context.Context, tl tools.Tool) tools.Status {
		return tools.Status{Tool: tl, Found: !tl.Optional, Version: "1.2.3", Path: "/usr/bin/" + tl.Binary}
	}
	if err := runDoctor(context.Background(), &out, builtins.Registry(), "", doctorRun{json: true}, optional, nil); err != nil {
		t.Fatal(err)
	}
	got.Missing = -1
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Missing != 0 {
		t.Errorf("missing = %d, want 0 when only optional tools are absent", got.Missing)
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
