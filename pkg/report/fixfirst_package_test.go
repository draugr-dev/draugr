package report

import (
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// One CVE in two packages of one image is two findings with the same rule, severity and location.
// Every view names the package, so the two rows read as two things to do rather than a duplicate,
// and the one with no release to move to still says why.
func TestFixFirstNamesThePackageOnEveryRow(t *testing.T) {
	result := func(name, installed, fixed string) sarif.Result {
		return sarif.Result{RuleID: "CVE-2024-6119", Level: sarif.LevelError, Score: 7.5, HasScore: true,
			Priority: "P1", Tool: "trivy", Location: sarif.Location{URI: "registry.example.com/web:1.4"},
			Message: "openssl: Possible denial of service in X.509 name checks",
			Package: &sarif.Package{Name: name, Version: installed, FixedVersion: fixed}}
	}
	d := Data{Run: engine.Result{Controls: map[string]plugin.ControlResult{
		"images": {Report: sarif.Report{Results: []sarif.Result{
			result("libssl3", "3.0.14-1~deb12u2", "3.0.18-1~deb12u2"),
			result("openssl", "3.0.14-1~deb12u2", ""),
		}}},
	}}}

	full := renderWith(t, consoleReporter{}, d)
	for _, want := range []string{
		"scanner trivy · libssl3 3.0.14-1~deb12u2 → 3.0.18-1~deb12u2",
		"scanner trivy · openssl 3.0.14-1~deb12u2 · fix no upgrade published",
	} {
		if !strings.Contains(full, want) {
			t.Errorf("full view: missing %q:\n%s", want, full)
		}
	}

	d.View = ViewCompact
	compact := renderWith(t, consoleReporter{}, d)
	for _, want := range []string{"libssl3 → 3.0.18-1~deb12u2", "openssl · no upgrade published"} {
		if !strings.Contains(compact, want) {
			t.Errorf("compact view: missing %q:\n%s", want, compact)
		}
	}
}

// A finding about no package keeps the phrase alone in both views.
func TestCompactFixKeepsThePhraseWithoutAPackage(t *testing.T) {
	f := finding{control: "secrets"}
	if got := compactFix(f); got != "rotate the credential" {
		t.Errorf("compactFix = %q, want the phrase", got)
	}
	if name, fixed := packageFix(finding{pkg: &sarif.Package{Name: "flask"}}, true); name != "flask" || fixed != "" {
		t.Errorf("packageFix with no version or fix = %q, %q", name, fixed)
	}
}
