package scanners

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

const licenseJSON = `{"Results":[{"Target":"go.mod","Class":"license","Licenses":[
 {"Severity":"LOW","Category":"notice","PkgName":"github.com/spf13/cobra","FilePath":"go.mod","Name":"Apache-2.0"},
 {"Severity":"HIGH","Category":"restricted","PkgName":"github.com/copyleft/lib","FilePath":"go.mod","Name":"GPL-3.0-only"},
 {"Severity":"CRITICAL","Category":"forbidden","PkgName":"github.com/bad/lib","FilePath":"go.mod","Name":"AGPL-3.0-only"},
 {"Severity":"MEDIUM","Category":"reciprocal","PkgName":"github.com/mid/lib","FilePath":"go.mod","Name":"MPL-2.0"},
 {"Severity":"UNKNOWN","Category":"unknown","PkgName":"github.com/mystery/lib","FilePath":"go.mod","Name":"NOASSERTION"}
]}]}`

func TestTrivyLicenseArgs(t *testing.T) {
	// JSON, not SARIF: Trivy's SARIF output contains no license findings at all.
	want := "trivy fs --quiet --scanners license --format json /src"
	if got := strings.Join(trivyLicenseArgs("/src", nil), " "); got != want {
		t.Errorf("argv = %q, want %q", got, want)
	}
}

func TestParseTrivyLicensesReportsOnlyObligations(t *testing.T) {
	rep, err := parseTrivyLicenses([]byte(licenseJSON), t.TempDir(), nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := map[string]sarif.Level{}
	for _, r := range rep.Results {
		got[r.RuleID] = r.Level
	}
	want := map[string]sarif.Level{
		"license/AGPL-3.0-only/github.com/bad/lib":     sarif.LevelError,
		"license/GPL-3.0-only/github.com/copyleft/lib": sarif.LevelWarning,
		"license/MPL-2.0/github.com/mid/lib":           sarif.LevelNote,
		"license/NOASSERTION/github.com/mystery/lib":   sarif.LevelNote,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d findings, want %d: %v", len(got), len(want), got)
	}
	for id, lvl := range want {
		if got[id] != lvl {
			t.Errorf("%s = %q, want %q", id, got[id], lvl)
		}
	}
	// Apache-2.0 is permissive: inventory, not a finding. Reporting it would bury the four above
	// under dozens that say nothing. And the SBOM already carries the full inventory.
	for id := range got {
		if strings.Contains(id, "Apache-2.0") {
			t.Errorf("a permissive license should not be a finding: %s", id)
		}
	}
}

func TestParseTrivyLicensesPolicyBeatsCategory(t *testing.T) {
	// Whether a license is acceptable depends on what you do with your software, which Trivy
	// cannot know and the team always does.
	cfg := plugin.Config{denyKey: []string{"Apache-2.0"}, warnKey: []string{"MPL-2.0"}}
	rep, err := parseTrivyLicenses([]byte(licenseJSON), t.TempDir(), cfg)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	lvl := map[string]sarif.Level{}
	msg := map[string]string{}
	for _, r := range rep.Results {
		lvl[r.RuleID] = r.Level
		msg[r.RuleID] = r.Message
	}
	// Permissive by category, denied by policy.
	if got := lvl["license/Apache-2.0/github.com/spf13/cobra"]; got != sarif.LevelError {
		t.Errorf("denied license = %q, want error", got)
	}
	if !strings.Contains(msg["license/Apache-2.0/github.com/spf13/cobra"], "license policy") {
		t.Errorf("the message should say the policy decided it: %q", msg["license/Apache-2.0/github.com/spf13/cobra"])
	}
	// reciprocal would be a note; policy raises it to a warning.
	if got := lvl["license/MPL-2.0/github.com/mid/lib"]; got != sarif.LevelWarning {
		t.Errorf("warned license = %q, want warning", got)
	}
}

// Two components list the same license in their own blocks. Each finding names its component's
// setting, and the rule the two share names neither.
func TestParseTrivyLicensesNamesTheSettingThatListedTheLicense(t *testing.T) {
	const denied = "license/Apache-2.0/github.com/spf13/cobra"
	for comp, want := range map[string]string{
		"api":    `components["api"].controls.licenses.deny`,
		"worker": `config.controls.licenses.deny, components["worker"].controls.licenses.deny`,
	} {
		cfg := plugin.Config{denyKey: []string{"Apache-2.0"}, denyFromKey: map[string]any{"Apache-2.0": want}}
		rep, err := parseTrivyLicenses([]byte(licenseJSON), t.TempDir(), cfg)
		if err != nil {
			t.Fatalf("%s: parse: %v", comp, err)
		}
		for _, r := range rep.Results {
			if r.RuleID == denied && !strings.HasSuffix(r.Message, "Denied by this project's license policy ("+want+").") {
				t.Errorf("%s: message = %q", comp, r.Message)
			}
		}
		if strings.Contains(rep.Rules[denied].FullDescription, "components[") {
			t.Errorf("%s: the rule names a component: %q", comp, rep.Rules[denied].FullDescription)
		}
	}
	// A job the control did not plan carries no sources, and names the project's key.
	if got := policyReason("Flagged", warnKey, ""); got != "Flagged by this project's license policy (config.controls.licenses.warn)." {
		t.Errorf("without a source: %q", got)
	}
}

func TestParseTrivyLicensesResolvesTheDependencyLine(t *testing.T) {
	// Trivy gives licenses no line at all, unlike its vulnerability findings. Without this every
	// license lands at the top of go.mod in a pile, the same failure as an image finding reported
	// at "library/python:1".
	dir := t.TempDir()
	manifest := "module example\n\nrequire (\n\tgithub.com/spf13/cobra v1.0.0\n\tgithub.com/copyleft/lib v2.0.0\n)\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := parseTrivyLicenses([]byte(licenseJSON), dir, nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, r := range rep.Results {
		if r.RuleID == "license/GPL-3.0-only/github.com/copyleft/lib" {
			if r.Location.URI != "go.mod" || r.Location.StartLine != 5 {
				t.Errorf("location = %s:%d, want go.mod:5", r.Location.URI, r.Location.StartLine)
			}
			return
		}
	}
	t.Fatal("the copyleft finding is missing")
}

func TestParseTrivyLicensesSurvivesAnUnreadableManifest(t *testing.T) {
	// A missing line degrades the finding; it must not lose it. Line zero is honest, the finding
	// still points at the file.
	rep, err := parseTrivyLicenses([]byte(licenseJSON), "/nonexistent-checkout", nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rep.Results) != 4 {
		t.Fatalf("got %d findings, want 4 even without line numbers", len(rep.Results))
	}
	for _, r := range rep.Results {
		if r.Location.URI != "go.mod" {
			t.Errorf("the finding should still name the file, got %q", r.Location.URI)
		}
		if r.Location.StartLine != 0 {
			t.Errorf("want line 0 when it can't be resolved, got %d", r.Location.StartLine)
		}
	}
}

func TestLicenseHelpURI(t *testing.T) {
	// Trivy's own link wins when present; SPDX is the stable fallback.
	if got := licenseHelpURI(trivyLicense{Name: "MIT", Link: "https://example.test/x"}); got != "https://example.test/x" {
		t.Errorf("helpUri = %q, want the tool's link", got)
	}
	if got := licenseHelpURI(trivyLicense{Name: "MIT"}); got != "https://spdx.org/licenses/MIT.html" {
		t.Errorf("helpUri = %q, want the SPDX page", got)
	}
	// An expression isn't an SPDX id, and no link beats a broken one.
	for _, name := range []string{"MIT OR Apache-2.0", "LicenseRef-custom/thing", ""} {
		if got := licenseHelpURI(trivyLicense{Name: name}); got != "" {
			t.Errorf("helpUri(%q) = %q, want empty rather than a 404", name, got)
		}
	}
}

func TestParseTrivyLicensesRejectsGarbage(t *testing.T) {
	if _, err := parseTrivyLicenses([]byte("not json"), t.TempDir(), nil); err == nil {
		t.Error("want an error for undecodable output")
	}
}

func TestStringListTolerAtesYAMLDecoding(t *testing.T) {
	// YAML gives []any; a caller constructing Config in Go gives []string.
	if got := stringList(plugin.Config{denyKey: []any{"MIT", 7, "ISC"}}, denyKey); strings.Join(got, ",") != "MIT,ISC" {
		t.Errorf("stringList = %v, want the strings only", got)
	}
	if got := stringList(plugin.Config{denyKey: []string{"MIT"}}, denyKey); len(got) != 1 {
		t.Errorf("stringList = %v", got)
	}
	if got := stringList(nil, denyKey); got != nil {
		t.Errorf("stringList(nil) = %v", got)
	}
}

// The image mode names the image on the command line rather than a directory.
func TestTrivyLicenseImageArgv(t *testing.T) {
	argv, err := trivyLicenseImageArgv(plugin.ImageTarget{Ref: "ghcr.io/acme/api:1.4"}, plugin.Config{})
	if err != nil {
		t.Fatalf("argv: %v", err)
	}
	want := []string{"trivy", "image", "--quiet", "--scanners", "license", "--format", "json",
		"ghcr.io/acme/api:1.4"}
	if !slices.Equal(argv, want) {
		t.Errorf("argv = %v, want %v", argv, want)
	}

	// The digest wins where there is one: a tag moves and a scan keyed on it describes whichever
	// image was current, which is the wrong one as soon as anybody rebuilds.
	argv, err = trivyLicenseImageArgv(plugin.ImageTarget{
		Ref: "ghcr.io/acme/api:1.4", Digest: "sha256:" + strings.Repeat("a", 64)}, plugin.Config{})
	if err != nil {
		t.Fatalf("argv: %v", err)
	}
	if last := argv[len(argv)-1]; !strings.Contains(last, "@sha256:") {
		t.Errorf("target = %q, want the digest pinned", last)
	}

	if _, err := trivyLicenseImageArgv(plugin.RepositoryTarget{URL: "x"}, plugin.Config{}); err == nil {
		t.Error("a repository target was accepted by the image mode")
	}
	if _, err := trivyLicenseImageArgv(plugin.ImageTarget{}, plugin.Config{}); err == nil {
		t.Error("an image with neither ref nor digest was accepted")
	}
}

// Full scanning is opt-in, in both modes and by the same key.
//
// It changes what the scan reads rather than how it reports. Package metadata is a dependency
// list, and full scanning walks every file for a LICENSE or a header. So a descriptor that did
// not ask for it must not pay for it.
func TestLicenseFullIsOptInInBothModes(t *testing.T) {
	repo := trivyLicenseArgs("/tmp/tree", plugin.Config{})
	if slices.Contains(repo, "--license-full") {
		t.Error("repository mode asked for full scanning without being told to")
	}
	if repo = trivyLicenseArgs("/tmp/tree", plugin.Config{"full": true}); !slices.Contains(repo, "--license-full") {
		t.Errorf("full: true did not reach the command line: %v", repo)
	}

	img, err := trivyLicenseImageArgv(plugin.ImageTarget{Ref: "alpine:3.19"}, plugin.Config{"full": true})
	if err != nil {
		t.Fatalf("argv: %v", err)
	}
	if !slices.Contains(img, "--license-full") {
		t.Errorf("full: true did not reach the image command line: %v", img)
	}
}

// One scanner, two modes, and the dispatch is on the target rather than on a flag.
func TestTheLicenseScannerRefusesATargetItCannotRead(t *testing.T) {
	s := NewTrivyLicense()
	info := s.Info()
	if !slices.Contains(info.TargetKinds, plugin.TargetRepository) ||
		!slices.Contains(info.TargetKinds, plugin.TargetImage) {
		t.Errorf("target kinds = %v, want both, the question has no target kind in it", info.TargetKinds)
	}
	if _, err := s.Scan(context.Background(), plugin.HostTarget{URL: "https://example.com"}, plugin.Config{}); err == nil {
		t.Error("a host target was accepted; nothing there has a dependency tree to read")
	}
}

func TestParseTrivyLicensesRuleIsTheSameUnderEveryPolicy(t *testing.T) {
	// SARIF keeps one rule per id for the whole run, and deny and warn are set per component. Two
	// components carrying the same package under the same license, one denying it and one only
	// flagging it, write one rule between them, so the rule must say nothing either verdict would
	// contradict. The verdict is in each result's message.
	const doc = `{"Results":[{"Target":"package-lock.json","Class":"lang-pkgs","Licenses":[
 {"Severity":"LOW","Category":"notice","PkgName":"inherits","FilePath":"package-lock.json","Name":"ISC"},
 {"Severity":"MEDIUM","Category":"reciprocal","PkgName":"github.com/mid/lib","FilePath":"package-lock.json","Name":"MPL-2.0"}
]}]}`
	parse := func(cfg plugin.Config) sarif.Report {
		t.Helper()
		rep, err := parseTrivyLicenses([]byte(doc), t.TempDir(), cfg)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		return rep
	}
	denied := parse(plugin.Config{denyKey: []string{"ISC", "MPL-2.0"}})
	flagged := parse(plugin.Config{warnKey: []string{"ISC", "MPL-2.0"}})

	for _, id := range []string{"license/ISC/inherits", "license/MPL-2.0/github.com/mid/lib"} {
		d, ok := denied.Rules[id]
		if !ok {
			t.Fatalf("no rule %s under deny", id)
		}
		if f := flagged.Rules[id]; !reflect.DeepEqual(d, f) {
			t.Errorf("rule %s differs by policy:\ndeny: %+v\nwarn: %+v", id, d, f)
		}
		if strings.Contains(d.FullDescription, "policy") {
			t.Errorf("rule %s carries one component's verdict: %q", id, d.FullDescription)
		}
	}
	// The reciprocal license keeps Trivy's reading of it, which holds under either policy.
	if got := denied.Rules["license/MPL-2.0/github.com/mid/lib"].FullDescription; !strings.Contains(got, "File-level copyleft") {
		t.Errorf("reciprocal rule description = %q, want the category's meaning", got)
	}
	// Each result still states its own verdict.
	for _, c := range []struct {
		rep  sarif.Report
		want string
	}{{denied, "Denied by this project's license policy"}, {flagged, "Flagged by this project's license policy"}} {
		for _, r := range c.rep.Results {
			if !strings.Contains(r.Message, c.want) {
				t.Errorf("%s message = %q, want %q", r.RuleID, r.Message, c.want)
			}
		}
	}
}

// fullLicenseJSON is the shape `trivy fs --license-full` reports over two directories: the
// lockfile's packages, with the lines Trivy's npm parser records for each entry, in one result
// set; their licenses in a second; and the licenses it read from files in a third, with no package
// name.
const fullLicenseJSON = `{"Results":[
 {"Target":"api/package-lock.json","Class":"lang-pkgs","Type":"npm","Packages":[
  {"Name":"ms","Version":"2.1.3","Locations":[{"StartLine":16,"EndLine":20}]}]},
 {"Target":"api/package-lock.json","Class":"license","Packages":[],"Licenses":[
  {"Severity":"HIGH","Category":"restricted","PkgName":"ms","FilePath":"api/package-lock.json","Name":"GPL-3.0-only"}]},
 {"Target":"Loose File License(s)","Class":"license-file","Packages":[],"Licenses":[
  {"Severity":"HIGH","Category":"restricted","PkgName":"","FilePath":"api/LICENSE","Name":"LGPL-3.0","Link":"https://spdx.org/licenses/LGPL-3.0.html"},
  {"Severity":"HIGH","Category":"restricted","PkgName":"","FilePath":"web/LICENSE","Name":"LGPL-3.0","Link":"https://spdx.org/licenses/LGPL-3.0.html"}]}
]}`

// fullLicenseLock is a package-lock.json whose root lists each dependency before the package's own
// node_modules/ entry.
const fullLicenseLock = `{
  "name": "api",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "api",
      "dependencies": {
        "ms": "2.1.3",
        "tslib": "2.6.2"
      }
    },
    "node_modules/tslib": {
      "version": "2.6.2",
      "license": "0BSD"
    },
    "node_modules/ms": {
      "version": "2.1.3",
      "license": "MIT"
    }
  }
}
`

func parseFullLicenses(t *testing.T) sarif.Report {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "api"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "api", "package-lock.json"), []byte(fullLicenseLock), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := parseTrivyLicenses([]byte(fullLicenseJSON), dir, nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return rep
}

// A license Trivy read from a file has no package, so the finding names the file, in each of two.
func TestAFileLevelLicenseNamesTheFile(t *testing.T) {
	rep := parseFullLicenses(t)
	var files []sarif.Result
	for _, r := range rep.Results {
		if r.RuleID == "license/LGPL-3.0" {
			files = append(files, r)
		}
	}
	if len(files) != 2 {
		t.Fatalf("got %d file-level findings, want one per file", len(files))
	}
	for _, r := range files {
		want := r.Location.URI + " is LGPL-3.0. Copyleft."
		if !strings.HasPrefix(r.Message, want) {
			t.Errorf("message = %q, want it to open %q", r.Message, want)
		}
		if r.Location.StartLine != 0 {
			t.Errorf("%s: line = %d, want 0, the license covers the whole file", r.Location.URI, r.Location.StartLine)
		}
	}
	// Every file carrying the license shares the rule, so its description names none of them.
	if got := rep.Rules["license/LGPL-3.0"].ShortDescription; got != "A file is licensed LGPL-3.0" {
		t.Errorf("file-level rule description = %q", got)
	}
}

// A package's license points at its own node_modules/ entry in package-lock.json, the line Trivy's
// parser recorded for it, rather than the root's dependency list, which names it first.
func TestAPackageLicenseLocatesTheLockfileEntry(t *testing.T) {
	for _, r := range parseFullLicenses(t).Results {
		if r.RuleID != "license/GPL-3.0-only/ms" {
			continue
		}
		if r.Location.URI != "api/package-lock.json" || r.Location.StartLine != 16 {
			t.Errorf("location = %s:%d, want api/package-lock.json:16", r.Location.URI, r.Location.StartLine)
		}
		if !strings.HasPrefix(r.Message, "ms is GPL-3.0-only.") {
			t.Errorf("message = %q", r.Message)
		}
		return
	}
	t.Fatal("the package finding is missing")
}

func TestLicenseSubjectWithNeitherPackageNorFile(t *testing.T) {
	if got := licenseSubject(trivyLicense{Name: "MIT"}); got != "A file" {
		t.Errorf("subject = %q, want a noun rather than a blank", got)
	}
}
