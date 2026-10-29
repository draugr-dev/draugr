package tools

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The plan names the check before an install and the result names the check after it. Each case
// installs one way and holds the result to the plan: the same words where the plan's check was
// made, and a note saying why where it was not.
func TestTheResultNamesTheCheckThePlanNamed(t *testing.T) {
	content := []byte("#!/bin/sh\necho v\n")
	listed := sha256Hex(content) + "  vtool\n"

	cases := []struct {
		name string
		// checksums is what the upstream's checksums URL answers; "" serves no checksums URL.
		checksums  string
		status     int
		cosign     bool // the CLI is installed
		signed     bool // the spec carries a signature
		wantPlan   string
		wantResult string
		wantNote   string
		wantLevel  Level
	}{
		{name: "nothing published", wantPlan: CheckNone, wantResult: CheckNone,
			wantNote: noteNothingPublished, wantLevel: LevelUnverified},
		{name: "unsigned checksums", checksums: listed, wantPlan: CheckChecksum,
			wantResult: CheckChecksum, wantLevel: LevelChecksum},
		{name: "checksums unreachable", checksums: listed, status: http.StatusInternalServerError,
			wantPlan: CheckChecksum, wantResult: CheckNone, wantNote: noteChecksumsFetch,
			wantLevel: LevelUnverified},
		{name: "signed, cosign absent", checksums: listed, signed: true, wantPlan: CheckChecksum,
			wantResult: CheckChecksum, wantNote: noteNoCosign, wantLevel: LevelChecksum},
		{name: "signed, cosign present", checksums: listed, signed: true, cosign: true,
			wantPlan: CheckSigned, wantResult: CheckSigned, wantLevel: LevelSigned},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "checksums.txt") {
					if tc.status != 0 {
						w.WriteHeader(tc.status)
						return
					}
					_, _ = w.Write([]byte(tc.checksums))
					return
				}
				_, _ = w.Write(content)
			}))
			defer srv.Close()

			checksums := ""
			if tc.checksums != "" && !tc.signed {
				checksums = srv.URL + "/{version}/checksums.txt"
			}
			registerVersionedTool(t, "vtool", srv.URL, sha256Hex(content), checksums)
			if tc.signed {
				spec := installable["vtool"]
				spec.Cosign = &CosignSpec{
					ChecksumsURL:         srv.URL + "/9.9.9/checksums.txt",
					ChecksumsURLTemplate: srv.URL + "/{version}/checksums.txt",
					BundleURLTemplate:    srv.URL + "/{version}/checksums.txt.sigstore.json",
				}
				installable["vtool"] = spec
			}
			stubCosign(t, tc.cosign, nil)

			if got := PlannedCheck("vtool", "1.2.3"); got != tc.wantPlan {
				t.Errorf("plan = %q, want %q", got, tc.wantPlan)
			}
			got, err := InstallVersion(context.Background(), "vtool", "1.2.3", t.TempDir(), srv.Client(), false)
			if err != nil {
				t.Fatalf("InstallVersion: %v", err)
			}
			if got.Checked != tc.wantResult || got.ProvenanceNote != tc.wantNote || got.Verified != tc.wantLevel {
				t.Errorf("result = (%q, %q, %q), want (%q, %q, %q)",
					got.Checked, got.ProvenanceNote, got.Verified, tc.wantResult, tc.wantNote, tc.wantLevel)
			}
		})
	}
}

// The version Draugr ships is checked against the SHA-256 this build records, and the result says
// sha256 for it, the same as the plan.
func TestThePinnedBuildIsReportedAsPinned(t *testing.T) {
	content := []byte("#!/bin/sh\necho v\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(content)
	}))
	defer srv.Close()
	registerVersionedTool(t, "vtool", srv.URL, sha256Hex(content), "")

	if got := PlannedCheck("vtool", ""); got != CheckPinned {
		t.Errorf("plan = %q, want %q", got, CheckPinned)
	}
	got, err := InstallVersion(context.Background(), "vtool", "", t.TempDir(), srv.Client(), false)
	if err != nil {
		t.Fatal(err)
	}
	if got.Checked != CheckPinned || got.ProvenanceNote != "" || got.Verified != LevelPinned {
		t.Errorf("result = (%q, %q, %q)", got.Checked, got.ProvenanceNote, got.Verified)
	}
}

func TestReleaseCheckFollowsCosign(t *testing.T) {
	key := platformKey()
	pinned := InstallSpec{Assets: map[string]Asset{key: {SHA256: "abc"}}, Cosign: &CosignSpec{}}
	other := InstallSpec{Assets: map[string]Asset{key: {}}, Cosign: &CosignSpec{}}
	cases := []struct {
		name   string
		spec   InstallSpec
		cosign bool
		want   string
	}{
		{"pinned, no signature", InstallSpec{Assets: map[string]Asset{key: {SHA256: "abc"}}}, true, CheckPinned},
		{"pinned and signed", pinned, true, CheckPinnedSigned},
		// Without the CLI no signature is checked, so the plan does not promise one.
		{"pinned and signed, no cosign", pinned, false, CheckPinned},
		{"another version, signed", other, true, CheckSigned},
		{"another version, signed, no cosign", other, false, CheckChecksum},
		{"another version, checksums", InstallSpec{Assets: map[string]Asset{key: {}}, ChecksumsURLTemplate: "u"}, true, CheckChecksum},
		{"another version, nothing", InstallSpec{Assets: map[string]Asset{key: {}}}, true, CheckNone},
	}
	for _, tc := range cases {
		if got := releaseCheck(tc.spec, tc.cosign); got != tc.want {
			t.Errorf("%s: releaseCheck = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestPlannedCheckForLanguagePackages(t *testing.T) {
	cases := []struct{ name, version, want string }{
		{"semgrep", "", CheckPyPI},
		{"semgrep", "v" + semgrepVersion, CheckPyPI},
		// The embedded hashes describe one version. Another has none to be checked against.
		{"semgrep", "1.100.0", CheckNone},
		{"retire", "", CheckNPM},
		{"retire", "5.0.0", CheckNone},
		// The checksum database answers for every version of a module.
		{"govulncheck", "", CheckGoSumDB},
		{"govulncheck", "1.5.0", CheckGoSumDB},
		{"kubectl", "", ""},
	}
	for _, tc := range cases {
		if got := PlannedCheck(tc.name, tc.version); got != tc.want {
			t.Errorf("PlannedCheck(%s, %q) = %q, want %q", tc.name, tc.version, got, tc.want)
		}
	}
}

func TestPlannedVersionIsTheOneAnInstallFetches(t *testing.T) {
	trivy, _ := Spec("trivy")
	cases := []struct {
		name, version, want string
		ok                  bool
	}{
		{"trivy", "", trivy.Version, true},
		{"trivy", "v0.68.0", "0.68.0", true},
		{"semgrep", "", semgrepVersion, true},
		{"semgrep", "1.100.0", "1.100.0", true},
		{"govulncheck", "v1.5.0", "1.5.0", true},
		{"kubectl", "", "", false},
	}
	for _, tc := range cases {
		got, ok := PlannedVersion(tc.name, tc.version)
		if got != tc.want || ok != tc.ok {
			t.Errorf("PlannedVersion(%s, %q) = (%q, %v), want (%q, %v)", tc.name, tc.version, got, ok, tc.want, tc.ok)
		}
	}
	// A platform the spec has no build for.
	installable["noplatform"] = InstallSpec{Binary: "noplatform", Version: "1.0.0", Assets: map[string]Asset{}}
	t.Cleanup(func() { delete(installable, "noplatform") })
	if _, ok := PlannedVersion("noplatform", ""); ok {
		t.Error("a tool with no build for this platform was planned")
	}
}

// Current is what the plan's "already at" reads and what the install loop skips on, so the two
// agree. A release binary is current when its record and its checksum match, at the version the
// install would fetch.
func TestCurrentReadsTheRecordAndTheChecksum(t *testing.T) {
	archive := makeTarGz(t, "faketool", []byte("#!/bin/sh\necho fake\n"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(archive)
	}))
	defer srv.Close()
	registerTestTool(t, "faketool", srv.URL+"/faketool.tar.gz", sha256Hex(archive), "faketool")
	dest := t.TempDir()

	if _, ok := Current(dest, "faketool", ""); ok {
		t.Fatal("nothing is installed yet")
	}
	if _, err := Install(context.Background(), "faketool", dest, srv.Client(), false); err != nil {
		t.Fatal(err)
	}
	if v, ok := Current(dest, "faketool", ""); !ok || v != "9.9.9" {
		t.Errorf("Current = (%q, %v), want the installed 9.9.9", v, ok)
	}
	if _, ok := Current(dest, "faketool", "1.0.0"); ok {
		t.Error("a different version was reported current")
	}
	// A binary changed since it was installed is not the one the record describes.
	if err := os.WriteFile(filepath.Join(dest, "faketool"), []byte("tampered"), 0o700); err != nil { // #nosec G306 -- test binary
		t.Fatal(err)
	}
	if _, ok := Current(dest, "faketool", ""); ok {
		t.Error("a modified binary was reported current")
	}
	if _, ok := Current(dest, "kubectl", ""); ok {
		t.Error("a tool Draugr cannot install was reported current")
	}
	installable["noplatform"] = InstallSpec{Binary: "noplatform", Version: "1.0.0", Assets: map[string]Asset{}}
	t.Cleanup(func() { delete(installable, "noplatform") })
	if _, ok := Current(dest, "noplatform", ""); ok {
		t.Error("a tool with no build for this platform was reported current")
	}
}

// Another version carries no recorded asset digest, so the record's own digest of the binary is
// what makes it current. Comparing the asset digest would download X on every run of `--version X`.
func TestAnotherVersionIsCurrentOnceInstalled(t *testing.T) {
	content := []byte("#!/bin/sh\necho v\n")
	downloads := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		downloads++
		_, _ = w.Write(content)
	}))
	defer srv.Close()
	registerVersionedTool(t, "vtool", srv.URL, sha256Hex(content), "")
	dest := t.TempDir()

	if _, err := InstallVersion(context.Background(), "vtool", "1.2.3", dest, srv.Client(), false); err != nil {
		t.Fatal(err)
	}
	if v, ok := Current(dest, "vtool", "1.2.3"); !ok || v != "1.2.3" {
		t.Errorf("Current = (%q, %v), want 1.2.3", v, ok)
	}
	got, err := InstallVersion(context.Background(), "vtool", "1.2.3", dest, srv.Client(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !got.AlreadyPresent || downloads != 1 {
		t.Errorf("AlreadyPresent = %v after %d downloads, want true after 1", got.AlreadyPresent, downloads)
	}
}

// A tool with a data tree is not current without it, so the install that restores the tree runs.
func TestABinaryWithoutItsDataIsNotCurrent(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	content := []byte("#!/bin/sh\necho v\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(content)
	}))
	defer srv.Close()
	registerVersionedTool(t, "vtool", srv.URL, sha256Hex(content), "")
	dest := t.TempDir()
	if _, err := InstallVersion(context.Background(), "vtool", "", dest, srv.Client(), false); err != nil {
		t.Fatal(err)
	}
	if _, ok := Current(dest, "vtool", ""); !ok {
		t.Fatal("the installed binary should be current before it needs data")
	}

	spec := installable["vtool"]
	spec.DataDir = "vtool"
	asset := spec.Assets[platformKey()]
	asset.DataInArchive = "cfg/"
	spec.Assets = map[string]Asset{platformKey(): asset}
	installable["vtool"] = spec
	if _, ok := Current(dest, "vtool", ""); ok {
		t.Error("a binary whose data directory is missing was reported current")
	}
	root, err := DataRoot()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "vtool"), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, ok := Current(dest, "vtool", ""); !ok {
		t.Error("the binary and its data are both present and should be current")
	}
}

// A language package already installed at the requested version is left alone, as a release
// binary is. Rebuilding it costs minutes and a network round and changes nothing.
func TestALanguagePackageIsNotRebuiltWhenCurrent(t *testing.T) {
	root := t.TempDir()
	destDir := filepath.Join(root, "bin")
	log := filepath.Join(t.TempDir(), "calls")
	fakePython(t, log, "--require-hashes")

	first, err := InstallVersion(t.Context(), "semgrep", "", destDir, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if first.AlreadyPresent || first.Checked != CheckPyPI || first.Verified != LevelPinned {
		t.Errorf("first install = %+v", first)
	}
	if v, ok := Current(destDir, "semgrep", ""); !ok || v != semgrepVersion {
		t.Fatalf("Current = (%q, %v) after the install", v, ok)
	}
	before, err := os.ReadFile(log) // #nosec G304 -- a path this test just created
	if err != nil {
		t.Fatal(err)
	}

	second, err := InstallVersion(t.Context(), "semgrep", "", destDir, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if !second.AlreadyPresent || second.Version != semgrepVersion || second.Verified != LevelPinned {
		t.Errorf("second install = %+v, want it left alone", second)
	}
	after, err := os.ReadFile(log) // #nosec G304 -- a path this test just created
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Errorf("pip ran again for a current install:\n%s", strings.TrimPrefix(string(after), string(before)))
	}

	// Another version is not the one installed, and --force reinstalls regardless.
	if _, ok := Current(destDir, "semgrep", "1.100.0"); ok {
		t.Error("another version was reported current")
	}
	forced, err := InstallVersion(t.Context(), "semgrep", "", destDir, nil, true)
	if err != nil || forced.AlreadyPresent {
		t.Errorf("--force did not reinstall: %+v, %v", forced, err)
	}

	// A shim whose environment is gone runs nothing, so it is not current.
	if err := os.RemoveAll(pythonEnvDir(root, "semgrep")); err != nil {
		t.Fatal(err)
	}
	if _, ok := Current(destDir, "semgrep", ""); ok {
		t.Error("a shim with no environment behind it was reported current")
	}
	// Nor is a shim changed since it was written.
	if _, err := InstallVersion(t.Context(), "semgrep", "", destDir, nil, false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destDir, "semgrep"), []byte("#!/bin/sh\n"), 0o700); err != nil { // #nosec G306 -- test shim
		t.Fatal(err)
	}
	if _, ok := Current(destDir, "semgrep", ""); ok {
		t.Error("a modified shim was reported current")
	}
}

// Another version of semgrep is installed by name. The hash-pinned set describes the version
// Draugr ships, and installing from it would put that release on disk under the requested name.
func TestAnotherSemgrepVersionIsInstalledByNameAndUnverified(t *testing.T) {
	root := t.TempDir()
	log := filepath.Join(t.TempDir(), "calls")
	fakePython(t, log, "--require-hashes", "semgrep==1.100.0")

	got, err := InstallVersion(t.Context(), "semgrep", "v1.100.0", filepath.Join(root, "bin"), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	calls, err := os.ReadFile(log) // #nosec G304 -- a path this test just created
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(calls), "--require-hashes") {
		t.Errorf("the pinned set was installed for another version:\n%s", calls)
	}
	if !strings.Contains(string(calls), "semgrep==1.100.0") {
		t.Errorf("the requested version was not asked for:\n%s", calls)
	}
	if got.Version != "1.100.0" || got.Checked != CheckNone || got.Verified != LevelUnverified ||
		got.ProvenanceNote != noteNoPinsForVersion {
		t.Errorf("result = %+v", got)
	}
}

// Another version that pip or npm cannot install reports what the package manager said, since no
// hashed attempt was made to carry an error of its own.
func TestAnotherVersionThatCannotBeInstalledSaysWhy(t *testing.T) {
	fakePython(t, filepath.Join(t.TempDir(), "calls")) // pip refuses everything
	_, err := InstallVersion(t.Context(), "semgrep", "1.100.0", filepath.Join(t.TempDir(), "bin"), nil, false)
	if err == nil || !strings.Contains(err.Error(), "semgrep==1.100.0") || !strings.Contains(err.Error(), "pip refused") {
		t.Errorf("err = %v, want pip's refusal of semgrep==1.100.0", err)
	}

	stubNodeTools(t, fakeNPM(t, filepath.Join(t.TempDir(), "calls"))) // npm refuses everything
	_, err = InstallVersion(t.Context(), "retire", "5.0.0", filepath.Join(t.TempDir(), "bin"), nil, false)
	if err == nil || !strings.Contains(err.Error(), "retire@5.0.0") || !strings.Contains(err.Error(), "npm refused") {
		t.Errorf("err = %v, want npm's refusal of retire@5.0.0", err)
	}
}

// The pinned version whose hashed install fails falls back, and says why it is unverified.
func TestASemgrepFallbackSaysWhy(t *testing.T) {
	fakePython(t, filepath.Join(t.TempDir(), "calls"), "semgrep==")
	got, err := InstallVersion(t.Context(), "semgrep", "", filepath.Join(t.TempDir(), "bin"), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.Checked != CheckNone || got.ProvenanceNote != notePythonFallback {
		t.Errorf("result = (%q, %q)", got.Checked, got.ProvenanceNote)
	}
}

// The same for retire.js: another version is installed by name, not from the pinned lockfile.
func TestAnotherRetireVersionIsInstalledByNameAndUnverified(t *testing.T) {
	log := filepath.Join(t.TempDir(), "calls")
	stubNodeTools(t, fakeNPM(t, log, "ci", "install"))

	got, err := InstallVersion(t.Context(), "retire", "5.0.0", filepath.Join(t.TempDir(), "bin"), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	calls, err := os.ReadFile(log) // #nosec G304 -- a path this test just created
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(calls), "ci ") {
		t.Errorf("the pinned lockfile was installed for another version:\n%s", calls)
	}
	if !strings.Contains(string(calls), "retire@5.0.0") {
		t.Errorf("the requested version was not asked for:\n%s", calls)
	}
	if got.Checked != CheckNone || got.Verified != LevelUnverified || got.ProvenanceNote != noteNoPinsForVersion {
		t.Errorf("result = %+v", got)
	}

	pinned, err := InstallVersion(t.Context(), "retire", "", filepath.Join(t.TempDir(), "bin"), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if pinned.Checked != CheckNPM || pinned.Verified != LevelPinned || pinned.ProvenanceNote != "" {
		t.Errorf("pinned result = %+v", pinned)
	}
}

func TestARetireFallbackSaysWhy(t *testing.T) {
	stubNodeTools(t, fakeNPM(t, filepath.Join(t.TempDir(), "calls"), "install"))
	got, err := InstallVersion(t.Context(), "retire", "", filepath.Join(t.TempDir(), "bin"), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.Checked != CheckNone || got.ProvenanceNote != noteNodeFallback {
		t.Errorf("result = (%q, %q)", got.Checked, got.ProvenanceNote)
	}
}

// The checksum database vouches for whichever version is built. The level says signed for a
// version Draugr does not ship, because pinned means the shipped one.
func TestGovulncheckLevelsByVersion(t *testing.T) {
	goBin := fakeGo(t, "go1.26.6", false)
	stubLookPath(t, func(string) (string, error) { return goBin, nil })

	pinned, err := InstallVersion(t.Context(), "govulncheck", "", filepath.Join(t.TempDir(), "bin"), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if pinned.Checked != CheckGoSumDB || pinned.Verified != LevelPinned {
		t.Errorf("pinned = (%q, %q)", pinned.Checked, pinned.Verified)
	}
	other, err := InstallVersion(t.Context(), "govulncheck", "1.5.0", filepath.Join(t.TempDir(), "bin"), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if other.Checked != CheckGoSumDB || other.Verified != LevelSigned || other.Version != "1.5.0" {
		t.Errorf("other = (%q, %q, %q)", other.Checked, other.Verified, other.Version)
	}

	fallbackGo := fakeGo(t, "go1.26.6", true)
	stubLookPath(t, func(string) (string, error) { return fallbackGo, nil })
	fallback, err := InstallVersion(t.Context(), "govulncheck", "", filepath.Join(t.TempDir(), "bin"), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if fallback.Checked != CheckNone || fallback.ProvenanceNote != noteGoFallback {
		t.Errorf("fallback = (%q, %q)", fallback.Checked, fallback.ProvenanceNote)
	}
}

func TestRecordManagedReportsAMissingFile(t *testing.T) {
	if _, err := recordManaged(t.TempDir(), Installed{Name: "semgrep", Path: filepath.Join(t.TempDir(), "absent")}); err == nil {
		t.Error("a file that is not there cannot be recorded")
	}
}
