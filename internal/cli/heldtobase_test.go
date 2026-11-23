package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/skald"
)

// shopSaga is the two-component descriptor with sca on, api declared as apiDecl says (its exposure,
// criticality or controls, indented under the component) and the config block extra adds to.
func shopSaga(t *testing.T, apiDecl, extra string) string {
	t.Helper()
	return writeSaga(t, `
project: shop
release:
  version: "1.0"
config:
  controls:
    sca:
      enabled: true`+extra+`
components:
  - name: api`+apiDecl+`
    repositories:
      - url: `+apiRepo+`
  - name: web
    repositories:
      - url: `+webRepo+`
`)
}

const publicCritical = `
    exposure: public
    criticality: critical`

// scanAgainst runs the head descriptor against base with --fail-on-new typed, as the docs' workflows
// type it, and returns the error and the console.
func scanAgainst(t *testing.T, head, base, failOnNew string, reg *engine.Registry) (string, error) {
	t.Helper()
	var console bytes.Buffer
	err := runScan(context.Background(), head,
		scanOptions{outputDir: t.TempDir(), noPublish: true, base: base, failOnNew: failOnNew}, reg, &console)
	return console.String(), err
}

// A scan records what its descriptor declared in results.sarif: each component's classification,
// controls and repositories, and the exclusions in force.
func TestAScanRecordsWhatItsDescriptorDeclared(t *testing.T) {
	_, reg := stagedPair()
	rep, err := loadSARIF(scanBase(t, shopSaga(t, publicCritical, `
  exclude:
    - rules: [CVE-OLD]
      reason: "not reachable from the api"`), reg))
	if err != nil {
		t.Fatal(err)
	}
	d, ok := skald.DeclaredOfReport(rep)
	if !ok {
		t.Fatal("results.sarif records no declaration")
	}
	if len(d.Components) != 2 || d.Components[0].Name != "api" || d.Components[0].Exposure != "public" ||
		d.Components[0].Criticality != "critical" || strings.Join(d.Components[0].Controls, ",") != "sca" ||
		strings.Join(d.Components[0].Repositories, ",") != apiRepo {
		t.Errorf("components = %+v", d.Components)
	}
	if len(d.Exclusions) != 1 || strings.Join(d.Exclusions[0].Rules, ",") != "CVE-OLD" {
		t.Errorf("exclusions = %+v", d.Exclusions)
	}
}

// A pull request that declares its component less exposed and less critical is ranked by its base's
// classification until it merges. Under public and critical the head's new warning is P2; under the
// head's restricted and supporting it would be P4 and pass a typed P2 gate.
func TestAChangeCannotLowerTheRankOfWhatItAdds(t *testing.T) {
	s, reg := stagedPair()
	base := scanBase(t, shopSaga(t, publicCritical, ""), reg)
	introduce(s)
	head := shopSaga(t, `
    exposure: restricted
    criticality: supporting`, "")

	console, err := scanAgainst(t, head, base, "P2", reg)
	if err == nil || !strings.Contains(err.Error(), "fails on P2: 1 new finding since") {
		t.Fatalf("err = %v, want the warning ranked P2 by the base's classification\n%s", err, console)
	}
	if want := "2 new findings rank by the base's exposure and criticality, which this change lowers, until it merges."; !strings.Contains(console, want) {
		t.Errorf("console does not say %q:\n%s", want, console)
	}

	// And through `draugr diff`, which reads the same two files.
	headOut := t.TempDir()
	if err := runScan(context.Background(), head, scanOptions{outputDir: headOut, noPublish: true}, reg, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	out, err := diffIn(t, t.TempDir(), base, filepath.Join(headOut, "results.sarif"), "--fail-on-new", "P2")
	if err == nil || !strings.Contains(err.Error(), "differential gate: 1 new finding") {
		t.Fatalf("draugr diff: err = %v\n%s", err, out)
	}

	// A head that declares its component more exposed than the base ranks by its own.
	s, reg = stagedPair()
	stricter := scanBase(t, shopSaga(t, `
    exposure: restricted
    criticality: supporting`, ""), reg)
	introduce(s)
	console, err = scanAgainst(t, shopSaga(t, publicCritical, ""), stricter, "P2", reg)
	if err == nil || strings.Contains(console, "rank by the base's") {
		t.Errorf("a head stricter than its base: err = %v\n%s", err, console)
	}
}

// A pull request that turns a control off fails until it merges, because nothing it adds where the
// control ran was looked for, and the base's findings from that control are not fixed.
func TestAChangeThatTurnsAControlOffFails(t *testing.T) {
	s, reg := stagedPair()
	base := scanBase(t, shopSaga(t, "", ""), reg)
	introduce(s)
	head := shopSaga(t, `
    controls:
      sca:
        enabled: false`, "")

	console, err := scanAgainst(t, head, base, "P4", reg)
	if err == nil || !strings.Contains(err.Error(), "fails: this change stops sca on api, which the base ran since") {
		t.Fatalf("err = %v, want the dropped control named\n%s", err, console)
	}
	if want := "The base ran sca on api and this change does not, so nothing it adds there was looked for, and 1 finding from the base reads as not scanned rather than fixed."; !strings.Contains(console, want) {
		t.Errorf("console does not say %q:\n%s", want, console)
	}

	headOut := t.TempDir()
	if err := runScan(context.Background(), head, scanOptions{outputDir: headOut, noPublish: true}, reg, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	out, err := diffIn(t, t.TempDir(), base, filepath.Join(headOut, "results.sarif"), "--fail-on-new", "P4")
	if err == nil || err.Error() != "differential gate: this change stops sca on api, which the base ran" {
		t.Fatalf("draugr diff: err = %v\n%s", err, out)
	}
	if head, _, _ := strings.Cut(out, "\n"); strings.Contains(head, "fixed") {
		t.Errorf("draugr diff reports the unscanned finding as fixed:\n%s", out)
	}
}

// A pull request cannot accept the finding it adds with an exclusion of its own: the finding counts
// as new until the exclusion merges. One the base already had still accepts it.
func TestAChangeCannotExcuseWhatItAdds(t *testing.T) {
	const excludeNew = `
  exclude:
    - rules: [CVE-NEW]
      reason: "the warning is a false positive"`
	s, reg := stagedPair()
	base := scanBase(t, shopSaga(t, "", ""), reg)
	excusedBase := scanBase(t, shopSaga(t, "", excludeNew), reg)
	introduce(s)
	head := shopSaga(t, "", excludeNew)

	console, err := scanAgainst(t, head, base, "P2", reg)
	if err == nil || !strings.Contains(err.Error(), "fails on P2: 1 new finding since") {
		t.Fatalf("err = %v, want the self-excused warning counted\n%s", err, console)
	}
	if want := "1 new finding is excused by an exclusion this change adds, and counts as new until it merges."; !strings.Contains(console, want) {
		t.Errorf("console does not say %q:\n%s", want, console)
	}

	if console, err := scanAgainst(t, head, excusedBase, "P2", reg); err != nil {
		t.Errorf("an exclusion the base had: err = %v\n%s", err, console)
	}
}
