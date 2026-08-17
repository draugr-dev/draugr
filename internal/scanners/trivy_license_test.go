package scanners

import (
	"os"
	"path/filepath"
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
	// Apache-2.0 is permissive: inventory, not a finding. Reporting it would bury the four
	// above under dozens that say nothing — and the SBOM already carries the full inventory.
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

func TestParseTrivyLicensesResolvesTheDependencyLine(t *testing.T) {
	// Trivy gives licenses no line at all, unlike its vulnerability findings. Without this
	// every license lands at the top of go.mod in a pile — the same failure as an image finding
	// reported at "library/python:1".
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
	// A missing line degrades the finding; it must not lose it. Line zero is honest — the
	// finding still points at the file.
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
