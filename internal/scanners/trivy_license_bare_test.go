package scanners

import (
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// licenseFileJSON is Trivy's report of a LICENSE file holding the GPL version 3, named as Trivy
// names license files: by the bare SPDX id, filed as restricted.
func licenseFileJSON(name string) string {
	return `{"Results":[{"Target":"LICENSE","Class":"license-file","Licenses":[` +
		`{"Severity":"HIGH","Category":"restricted","PkgName":"","FilePath":"LICENSE","Name":"` + name + `","Confidence":1}]}]}`
}

// A deny list names a GNU license with its range of versions, and Trivy may name it without one.
// The bare id matches either range, so a denied license fails whichever way either side wrote it;
// an explicit -only and an explicit -or-later are two licenses, and the category decides.
func TestALicenseDenyMatchesTheBareGNUId(t *testing.T) {
	for _, c := range []struct {
		deny, found string
		want        sarif.Level
		denied      bool
	}{
		{"GPL-3.0-only", "GPL-3.0", sarif.LevelError, true},
		{"GPL-3.0-or-later", "GPL-3.0", sarif.LevelError, true},
		{"GPL-3.0", "GPL-3.0-or-later", sarif.LevelError, true},
		{"GPL-3.0", "GPL-3.0-only", sarif.LevelError, true},
		{"GPL-3.0-or-later", "GPL-3.0+", sarif.LevelError, true},
		// Two explicit ranges are two licenses: the deny does not apply, and Trivy's category does.
		{"GPL-3.0-only", "GPL-3.0-or-later", sarif.LevelWarning, false},
		// Another version, or another license, is not this one.
		{"GPL-2.0-only", "GPL-3.0", sarif.LevelWarning, false},
		{"LGPL-3.0-only", "GPL-3.0", sarif.LevelWarning, false},
	} {
		cfg := plugin.Config{denyKey: []string{c.deny}}
		rep, err := parseTrivyLicenses([]byte(licenseFileJSON(c.found)), t.TempDir(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Results) != 1 {
			t.Fatalf("deny %s, found %s: %d results", c.deny, c.found, len(rep.Results))
		}
		r := rep.Results[0]
		if r.Level != c.want || strings.Contains(r.Message, "Denied by this project's license policy") != c.denied {
			t.Errorf("deny %s, found %s: level %s, message %q; want %s, denied %v", c.deny, c.found, r.Level, r.Message, c.want, c.denied)
		}
	}
}

// The setting that listed the license is named under the entry as it was written, whichever form.
func TestALicenseDenyNamesTheEntryItMatched(t *testing.T) {
	const from = `components["api"].controls.licenses.warn`
	cfg := plugin.Config{warnKey: []string{"GPL-3.0-only"}, warnFromKey: map[string]any{"GPL-3.0-only": from}}
	rep, err := parseTrivyLicenses([]byte(licenseFileJSON("GPL-3.0")), t.TempDir(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 || !strings.Contains(rep.Results[0].Message, from) {
		t.Errorf("results %+v, want one naming %s", rep.Results, from)
	}
}

// An exclusion matches rule ids exactly, so setting aside one range of a license leaves a finding
// whose range Trivy did not say: it stays counted rather than accepted on a guess.
func TestAnExclusionOfOneRangeLeavesTheBareId(t *testing.T) {
	if saga.WildcardMatch("license/GPL-3.0-only/*", "license/GPL-3.0/LICENSE") {
		t.Error("an exclusion of GPL-3.0-only set aside a finding Trivy named GPL-3.0")
	}
	if !saga.WildcardMatch("license/GPL-3.0/*", "license/GPL-3.0/LICENSE") {
		t.Error("an exclusion naming the bare id does not set it aside")
	}
}

func TestGNUForm(t *testing.T) {
	for _, c := range []struct {
		a, b string
		same bool
	}{
		{"AGPL-3.0", "AGPL-3.0-only", true},
		{"LGPL-2.1+", "LGPL-2.1-or-later", true},
		{"GFDL-1.3-only", "GFDL-1.3", true},
		{"MPL-2.0", "MPL-2.0-only", false},
		{"Apache-2.0", "Apache-2.0", false}, // the same id matches before this is asked
		{"GPL-3.0-only", "GPL-3.0-or-later", false},
	} {
		if got := sameGNULicense(c.a, c.b); got != c.same {
			t.Errorf("sameGNULicense(%q, %q) = %v, want %v", c.a, c.b, got, c.same)
		}
	}
}
