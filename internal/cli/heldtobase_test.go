package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"reflect"
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

// monorepoSaga is two components splitting one repository by paths, the shape of a monorepo, with
// webDecl indented under web and webPaths as web's paths.
func monorepoSaga(t *testing.T, webDecl, webPaths string) string {
	t.Helper()
	return writeSaga(t, `
project: shop
release:
  version: "1.0"
config:
  controls:
    sca:
      enabled: true
components:
  - name: api
    repositories:
      - url: `+apiRepo+`
        paths: [services/api]
  - name: web`+webDecl+`
    repositories:
      - url: `+apiRepo+`
        paths: [`+webPaths+`]
`)
}

// Turning a control off on one component of a monorepo fails like turning it off anywhere else. The
// repository is still scanned by sca for api, but nothing scans web's part of it, so a check that
// read the repository's URL alone would find it still covered and pass the change.
func TestAControlTurnedOffOnOnePartOfAMonorepoFails(t *testing.T) {
	s, reg := stagedPair()
	base := scanBase(t, monorepoSaga(t, "", "services/web"), reg)
	introduce(s)
	head := monorepoSaga(t, `
    controls:
      sca:
        enabled: false`, "services/web")

	console, err := scanAgainst(t, head, base, "P4", reg)
	if err == nil || !strings.Contains(err.Error(), "this change stops sca on web, which the base ran") {
		t.Fatalf("err = %v, want the dropped control named\n%s", err, console)
	}

	// web's paths written as a glob name the same subtree, and pass.
	if _, err := scanAgainst(t, monorepoSaga(t, "", "services/web/**"), base, "P1", reg); err != nil {
		t.Errorf("the same paths written as a glob failed: %v", err)
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

	// report.json says what the exit code said: the dropped control fails the gate on new findings,
	// though no new finding met it, since none could be looked for.
	judged := t.TempDir()
	if err := runScan(context.Background(), head,
		scanOptions{outputDir: judged, noPublish: true, base: base, failOnNew: "P4"}, reg, &bytes.Buffer{}); err == nil {
		t.Fatal("the scan passed")
	}
	newBlock, _ := gateOf(t, judged)["new"].(map[string]any)
	if newBlock["verdict"] != "fail" {
		t.Errorf("gate.new.verdict = %v, want fail", newBlock["verdict"])
	}
	if dropped, _ := newBlock["dropped"].([]any); len(dropped) != 1 ||
		!reflect.DeepEqual(dropped[0], map[string]any{"component": "api", "control": "sca"}) {
		t.Errorf("gate.new.dropped = %v, want sca on api", newBlock["dropped"])
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

// digestIn is the digest a run held to its base printed for the change's descriptor.
func digestIn(t *testing.T, console string) string {
	t.Helper()
	const lead = "add --trust-descriptor-change "
	_, rest, ok := strings.Cut(console, lead)
	if !ok {
		t.Fatalf("the run prints no digest to trust:\n%s", console)
	}
	digest, _, _ := strings.Cut(rest, " ")
	return digest
}

// A pull request that turns a control off on purpose gets through with the digest the failing run
// printed, typed in the pipeline. The digest names that descriptor alone: a later edit is held to
// its base again, and says why.
func TestADescriptorChangeIsTrustedByItsDigest(t *testing.T) {
	s, reg := stagedPair()
	base := scanBase(t, shopSaga(t, "", ""), reg)
	introduce(s)
	sweeping := `
    exposure: restricted
    criticality: supporting
    controls:
      sca:
        enabled: false`
	head := shopSaga(t, sweeping, "")

	console, err := scanAgainst(t, head, base, "P4", reg)
	if err == nil {
		t.Fatalf("the change passed untrusted:\n%s", console)
	}
	digest := digestIn(t, console)

	trusted := t.TempDir()
	var out bytes.Buffer
	err = runScan(context.Background(), head, scanOptions{outputDir: trusted, noPublish: true, base: base,
		failOnNew: "P4", trustDescriptorChange: digest}, reg, &out)
	if err != nil {
		t.Fatalf("the trusted change failed: %v\n%s", err, out.String())
	}
	for _, want := range []string{
		"--trust-descriptor-change: this change's descriptor decides the gate, not the base's.",
		"This change stops sca on api, which the base ran, so nothing it adds there was looked for",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("console does not say %q:\n%s", want, out.String())
		}
	}
	newBlock, _ := gateOf(t, trusted)["new"].(map[string]any)
	if newBlock["verdict"] != "pass" || newBlock["descriptorChangeTrusted"] != true || newBlock["dropped"] == nil {
		t.Errorf("gate.new = %v, want a pass that says the change was trusted and what it dropped", newBlock)
	}

	// draugr diff takes the same digest for the same two reports.
	headOut := t.TempDir()
	if err := runScan(context.Background(), head, scanOptions{outputDir: headOut, noPublish: true}, reg, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	headSARIF := filepath.Join(headOut, "results.sarif")
	if out, err := diffIn(t, t.TempDir(), base, headSARIF, "--fail-on-new", "P4", "--trust-descriptor-change", digest); err != nil {
		t.Errorf("draugr diff with the digest: %v\n%s", err, out)
	}

	// The switch left in the pipeline trusts no later edit of the descriptor.
	edited := shopSaga(t, strings.Replace(sweeping, "supporting", "important", 1), "")
	console, err = runScanTrusting(t, edited, base, digest, reg)
	if err == nil {
		t.Fatalf("a later edit passed on the old digest:\n%s", console)
	}
	if want := "--trust-descriptor-change " + digest + " names another descriptor than this change's ("; !strings.Contains(console, want) {
		t.Errorf("console does not say %q:\n%s", want, console)
	}

	// Without a base, or with a value that is no digest, the switch is refused rather than ignored.
	if _, err := diffIn(t, t.TempDir(), headSARIF, "--trust-descriptor-change", digest); err == nil ||
		!strings.Contains(err.Error(), "needs a base to compare against") {
		t.Errorf("no base: err = %v", err)
	}
	if _, err := diffIn(t, t.TempDir(), base, headSARIF, "--trust-descriptor-change", "true"); err == nil ||
		!strings.Contains(err.Error(), "is not a digest: copy the 16 lowercase") {
		t.Errorf("not a digest: err = %v", err)
	}
	if err := runScan(context.Background(), head, scanOptions{outputDir: t.TempDir(), noPublish: true,
		trustDescriptorChange: digest}, reg, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "needs a base to compare against") {
		t.Errorf("scan without --base: err = %v", err)
	}
}

// runScanTrusting scans path against base under a P4 gate on new findings with digest typed as
// --trust-descriptor-change, and returns the console and the error.
func runScanTrusting(t *testing.T, path, base, digest string, reg *engine.Registry) (string, error) {
	t.Helper()
	var console bytes.Buffer
	err := runScan(context.Background(), path, scanOptions{outputDir: t.TempDir(), noPublish: true, base: base,
		failOnNew: "P4", trustDescriptorChange: digest}, reg, &console)
	return console.String(), err
}
