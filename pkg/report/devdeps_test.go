package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// devData is a run in which config.controls.sca.devDependencies set aside two findings, a
// component's own setting a third, and config.exclude a fourth.
func devData() Data {
	pkg := func(dev bool) *sarif.Package {
		return &sarif.Package{Name: "nanoid", Version: "3.3.7", FixedVersion: "3.3.18", PURL: "pkg:npm/nanoid@3.3.7", Dev: dev}
	}
	setting := func(source string) *sarif.Suppression {
		return &sarif.Suppression{Kind: "external", Origin: sarif.OriginSetting,
			Justification: sarif.JustificationDevDependency, Source: source}
	}
	results := []sarif.Result{
		{Tool: "trivy", RuleID: "CVE-2026-67213", Level: sarif.LevelError, Component: "web", Package: pkg(true),
			Suppression: setting("config.controls.sca.devDependencies")},
		{Tool: "grype", RuleID: "CVE-2026-67214-nanoid", Level: sarif.LevelError, Component: "web", Package: pkg(true),
			Suppression: setting("config.controls.sca.devDependencies")},
		{Tool: "trivy", RuleID: "CVE-2026-67213", Level: sarif.LevelError, Component: "tools", Package: pkg(true),
			Suppression: setting(`components["tools"].controls.sca.devDependencies`)},
		{Tool: "trivy", RuleID: "CVE-2021-23337", Level: sarif.LevelError, Component: "web",
			Suppression: &sarif.Suppression{Kind: "external", Origin: sarif.OriginSaga, Justification: "accepted until the upgrade",
				Source: "draugr.saga.yaml", Line: 40}},
	}
	return Data{Run: engine.Result{
		Suppressed: 1, DevDependencies: 3,
		Controls: map[string]plugin.ControlResult{"sca": {Report: sarif.Report{Results: results}}},
	}}
}

// Each key that set findings aside is a row of its own in the accepted block, named by the key and
// the value it holds, with the count and the reason, over two components where one sets its own.
// The rows share the block's columns. The exclusion keeps its row and is the only decision listed.
func TestASettingIsAnAcceptedRowOfItsOwn(t *testing.T) {
	d := devData()
	var buf bytes.Buffer
	writeAccepted(&buf, tui.Plain(), d, true)
	out := buf.String()
	t.Logf("rendered:\n%s", out)
	rows := map[string]string{
		"config.exclude": "1 finding suppressed",
		"config.controls.sca.devDependencies: suppress":              "2 findings suppressed · development dependency",
		`components["tools"].controls.sca.devDependencies: suppress`: "1 finding suppressed · development dependency",
	}
	column := -1
	for _, line := range strings.Split(out, "\n") {
		for where, said := range rows {
			if !strings.HasPrefix(line, "  "+where+" ") || !strings.HasSuffix(line, said) {
				continue
			}
			at := strings.Index(line, said)
			if column >= 0 && at != column {
				t.Errorf("row %q starts its statement at column %d, the block's others at %d", where, at, column)
			}
			column = at
			delete(rows, where)
		}
	}
	for where, said := range rows {
		t.Errorf("accepted block has no row %q · %q:\n%s", where, said, out)
	}
	decs := decisions(d)
	if len(decs) != 1 || decs[0].reason != "accepted until the upgrade" {
		t.Errorf("decisions %+v, want the exclusion alone", decs)
	}
	if srcs := suppressionSources(d); len(srcs) != 1 || srcs[0].name != "draugr.saga.yaml" {
		t.Errorf("sources %+v, want the descriptor alone", srcs)
	}
	if via := acceptedVia(d.Run.Controls["sca"].Report.Results[2]); via != `components["tools"].controls.sca.devDependencies` {
		t.Errorf("accepted via %q, want the key", via)
	}

	var md bytes.Buffer
	writeEvidenceNotes(&md, d)
	if !strings.Contains(md.String(), "| `config.controls.sca.devDependencies: suppress` | 2 findings suppressed · development dependency |") {
		t.Errorf("markdown accepted table missing the setting's row:\n%s", md.String())
	}
}

// A row decided by the deprecated key states the value it holds there, false.
func TestASettingRowStatesTheDeprecatedKeysValue(t *testing.T) {
	r := settingRow{key: `components["web"].controls.sca.trivyFs.includeDevDeps`}
	if got := r.where(); got != `components["web"].controls.sca.trivyFs.includeDevDeps: false` {
		t.Errorf("where = %q", got)
	}
}

// A development dependency is labeled where the finding names its package, the way the scanner is
// labeled: in the block's facts and in the compact Fix cell. A runtime one is not.
func TestADevelopmentDependencyIsLabeledWhereItsPackageIsNamed(t *testing.T) {
	dev := finding{tool: "trivy", pkg: &sarif.Package{Name: "nanoid", Version: "3.3.7", FixedVersion: "3.3.18", Dev: true}}
	runtime := finding{tool: "trivy", pkg: &sarif.Package{Name: "lodash", Version: "4.17.20", FixedVersion: "4.17.21"}}

	var buf bytes.Buffer
	writeBlockFacts(&buf, tui.Plain(), dev, 120, false, false)
	if got := buf.String(); got != "      scanner trivy · dev dependency nanoid 3.3.7 → 3.3.18\n" {
		t.Errorf("facts %q, want the package labeled dev dependency", got)
	}
	buf.Reset()
	writeBlockFacts(&buf, tui.Plain(), runtime, 120, false, false)
	if got := buf.String(); strings.Contains(got, "dev ") {
		t.Errorf("facts %q label a runtime dependency", got)
	}
	if got := compactFix(dev); got != "dev nanoid → 3.3.18" {
		t.Errorf("compact fix %q, want the package labeled dev", got)
	}
	if got := compactFix(runtime); got != "lodash → 4.17.21" {
		t.Errorf("compact fix %q", got)
	}
}

// A dependency the runtime provides is labeled in the same two places, and one marked both
// development and provided wears the development label.
func TestAProvidedDependencyIsLabeledWhereItsPackageIsNamed(t *testing.T) {
	provided := finding{tool: "grype", pkg: &sarif.Package{Name: "commons-collections", Version: "3.2.1",
		FixedVersion: "3.2.2", Provided: true}}
	both := finding{tool: "grype", pkg: &sarif.Package{Name: "junit", FixedVersion: "4.13.1", Dev: true, Provided: true}}

	var buf bytes.Buffer
	writeBlockFacts(&buf, tui.Plain(), provided, 120, false, false)
	if got := buf.String(); got != "      scanner grype · provided dependency commons-collections 3.2.1 → 3.2.2\n" {
		t.Errorf("facts %q, want the package labeled provided dependency", got)
	}
	if got := compactFix(provided); got != "provided commons-collections → 3.2.2" {
		t.Errorf("compact fix %q, want the package labeled provided", got)
	}
	if got := compactFix(both); got != "dev junit → 4.13.1" {
		t.Errorf("compact fix %q, want the development label", got)
	}
}

// A package matched only by CPE is labeled in the same two places, and one that is also a
// development dependency wears the development label.
func TestACPEMatchIsLabeledWhereItsPackageIsNamed(t *testing.T) {
	cpe := finding{tool: "grype", pkg: &sarif.Package{Name: "Flutter", Version: "1.0.0", FixedVersion: "3.3.3", CPEMatch: true}}
	devToo := finding{tool: "grype", pkg: &sarif.Package{Name: "sentry", FixedVersion: "23.6.2", Dev: true, CPEMatch: true}}

	var buf bytes.Buffer
	writeBlockFacts(&buf, tui.Plain(), cpe, 120, false, false)
	if got := buf.String(); got != "      scanner grype · CPE match Flutter 1.0.0 → 3.3.3\n" {
		t.Errorf("facts %q, want the package labeled CPE match", got)
	}
	if got := compactFix(cpe); got != "cpe Flutter → 3.3.3" {
		t.Errorf("compact fix %q, want the package labeled cpe", got)
	}
	if got := compactFix(devToo); got != "dev sentry → 23.6.2" {
		t.Errorf("compact fix %q, want the development label", got)
	}
}

// The project's own package is labeled in the same two places, and wears that label over any other
// mark it carries, the reason its suppression records.
func TestTheProjectsOwnPackageIsLabeledWhereItIsNamed(t *testing.T) {
	own := finding{tool: "grype", pkg: &sarif.Package{Name: "telemetry", Version: "0.1.0", FixedVersion: "0.1.3", Own: true}}
	devToo := finding{tool: "trivy", pkg: &sarif.Package{Name: "Flutter", FixedVersion: "3.3.3", Own: true, Dev: true, CPEMatch: true}}

	var buf bytes.Buffer
	writeBlockFacts(&buf, tui.Plain(), own, 120, false, false)
	if got := buf.String(); got != "      scanner grype · own package telemetry 0.1.0 → 0.1.3\n" {
		t.Errorf("facts %q, want the package labeled own package", got)
	}
	if got := compactFix(own); got != "own telemetry → 0.1.3" {
		t.Errorf("compact fix %q, want the package labeled own", got)
	}
	if got := compactFix(devToo); got != "own Flutter → 3.3.3" {
		t.Errorf("compact fix %q, want the own label", got)
	}
}
