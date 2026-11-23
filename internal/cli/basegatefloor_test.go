package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/diff"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/skald"
)

// noGateSaga is gateSaga with the gate block deleted, as a pull request that removes it carries.
const noGateSaga = `project: shop
components:
  - name: api
    repositories:
      - url: ` + apiRepo + "\n"

// baseWithGate is a base report holding one finding and recording the gate its scan ran under.
func baseWithGate(t *testing.T, failOnNew string) string {
	t.Helper()
	return writeFile(t, "base.sarif", `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Draugr","rules":[]}},
"properties":{"draugr/provenance":[{"tool":"draugr/gate","fields":{"failOnNew":"`+failOnNew+`"}}]},
"results":[{"ruleId":"CVE-1","level":"note","message":{"text":"CVE-1 msg"},
"locations":[{"physicalLocation":{"artifactLocation":{"uri":"img"}}}],
"properties":{"tool":"trivy","priority":"P4"}}]}]}`)
}

// A pull request that deletes config.gate.failOnNew from its descriptor is still judged by the gate
// its base recorded. The base fails on a new P1, the head's descriptor sets no gate and adds one P1,
// and the diff exits non-zero and says whose gate applied.
func TestAPullRequestThatDeletesTheGateIsJudgedByTheBases(t *testing.T) {
	base := baseWithGate(t, "P1")
	head := writeFile(t, "head.sarif", sarifDoc("CVE-2", "error", "img", "P1"))
	dir := t.TempDir()
	headSaga := putSaga(t, dir, "draugr.saga.yaml", noGateSaga)

	out, err := diffIn(t, dir, base, head, "--saga", headSaga)
	if err == nil || !strings.Contains(err.Error(), "differential gate: 1 new finding") {
		t.Fatalf("err = %v, want the base's P1 gate tripped\n%s", err, out)
	}
	for _, want := range []string{
		"Gate: fails on any P1 this change introduces.",
		"The base's config.gate.failOnNew is P1 and this change's sets none, so the base's gate applies until the change merges.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not say %q:\n%s", want, out)
		}
	}

	// The pull-request comment says it too.
	md, err := diffIn(t, dir, base, head, "--saga", headSaga, "--format", "markdown")
	if err == nil {
		t.Errorf("the markdown diff passed a new P1 its base gates on\n%s", md)
	}
	if want := "_The base's config.gate.failOnNew is P1 and this change's sets none"; !strings.Contains(md, want) {
		t.Errorf("markdown does not say %q:\n%s", want, md)
	}
}

// The stricter of the two gates decides. A head that loosens the gate is held to the base's and told
// so; a head as strict or stricter decides alone; a gate in the other vocabulary applies beside the
// base's; and a typed --fail-on-new is the pipeline's decision and replaces both.
func TestTheStricterOfTheBaseAndHeadGatesDecides(t *testing.T) {
	base := baseWithGate(t, "P2")
	head := writeFile(t, "head.sarif", sarifDoc("CVE-2", "warning", "img", "P2"))
	for _, tc := range []struct {
		name     string
		headGate string
		args     []string
		fails    bool
		note     string
	}{
		{name: "loosened", headGate: "P1", fails: true,
			note: "The base's config.gate.failOnNew is P2 and this change's sets P1, so the base's gate applies"},
		{name: "as strict", headGate: "P2", fails: true},
		{name: "stricter", headGate: "P3", fails: true},
		{name: "other vocabulary", headGate: "critical", fails: true,
			note: "The base's config.gate.failOnNew is P2 and this change's sets critical severity"},
		{name: "typed", headGate: "P1", args: []string{"--fail-on-new", "P1"}, fails: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			headSaga := putSaga(t, dir, "draugr.saga.yaml", gateSaga(tc.headGate))
			out, err := diffIn(t, dir, append([]string{base, head, "--saga", headSaga}, tc.args...)...)
			if (err != nil) != tc.fails {
				t.Fatalf("err = %v, want failing %v\n%s", err, tc.fails, out)
			}
			if tc.note != "" && !strings.Contains(out, tc.note) {
				t.Errorf("output does not say %q:\n%s", tc.note, out)
			}
			if tc.note == "" && strings.Contains(out, "The base's config.gate.failOnNew") {
				t.Errorf("the base's gate is named where the head's decided alone:\n%s", out)
			}
		})
	}
}

// A scan records its descriptor's config.gate.failOnNew in results.sarif, and none where it sets
// none, so a base written before this or without a gate changes nothing.
func TestAScanRecordsItsGateOnNewFindings(t *testing.T) {
	_, reg := stagedPair()
	gated, err := loadSARIF(scanBase(t, twoComponentSaga(t, "P3"), reg))
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := skald.GateOfReport(gated); !ok || got != "P3" {
		t.Errorf("recorded gate = %q, %v; want P3", got, ok)
	}
	ungated, err := loadSARIF(scanBase(t, twoComponentSaga(t, ""), reg))
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := skald.GateOfReport(ungated); ok {
		t.Errorf("recorded gate = %q for a descriptor that sets none", got)
	}
}

// The same hold on `draugr scan --base`, from real scans: the base's descriptor gates on P3, the
// head's sets nothing, and the head adds two findings at P3 or above.
func TestAScanGivenABaseIsHeldToTheBasesGate(t *testing.T) {
	s, reg := stagedPair()
	base := scanBase(t, twoComponentSaga(t, "P3"), reg)
	introduce(s)
	head := twoComponentSaga(t, "")

	out := t.TempDir()
	var console bytes.Buffer
	err := runScan(context.Background(), head, scanOptions{outputDir: out, noPublish: true, base: base}, reg, &console)
	if err == nil || !strings.Contains(err.Error(), "fails on P3: 2 new findings since") {
		t.Fatalf("err = %v, want the base's P3 gate tripped", err)
	}
	if gate := gateOf(t, out); gate["failOnNew"] != "P3" {
		t.Errorf("failOnNew = %v, want the base's P3", gate["failOnNew"])
	}
	if want := "fails on P3, the base's gate, which this scan's descriptor weakens"; !strings.Contains(console.String(), want) {
		t.Errorf("console does not say %q:\n%s", want, console.String())
	}

	// And through `draugr diff`, with the head's results.sarif and its descriptor.
	headOut := t.TempDir()
	if err := runScan(context.Background(), head, scanOptions{outputDir: headOut, noPublish: true}, reg, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if _, err := diffIn(t, t.TempDir(), base, filepath.Join(headOut, "results.sarif"), "--saga", head); err == nil {
		t.Error("draugr diff passed two new findings at P3 its base gates on")
	}
}

// withBaseGate across every vocabulary and a base that recorded nothing usable.
func TestWithBaseGate(t *testing.T) {
	recorded := func(v string) sarif.Report {
		p, _ := skald.GateProvenance(v)
		return sarif.Report{Provenance: []sarif.Provenance{p}}
	}
	gate := func(v string) *saga.GateConfig { return &saga.GateConfig{FailOnNew: v} }
	for _, tc := range []struct {
		name   string
		failOn sarif.Severity
		band   string
		head   *saga.GateConfig
		base   sarif.Report
		want   diff.Gate
	}{
		{name: "no record", band: "P2", head: gate("P2"), base: sarif.Report{}, want: diff.Gate{FailOnPriority: "P2"}},
		{name: "unreadable record", band: "P2", head: gate("P2"), base: recorded("urgent"), want: diff.Gate{FailOnPriority: "P2"}},
		{name: "severity loosened", failOn: sarif.SeverityCritical, head: gate("critical"), base: recorded("high"),
			want: diff.Gate{FailOn: sarif.SeverityHigh, Base: "high", Head: "critical"}},
		{name: "severity stricter at head", failOn: sarif.SeverityMedium, head: gate("medium"), base: recorded("high"),
			want: diff.Gate{FailOn: sarif.SeverityMedium}},
		{name: "severity deleted", base: recorded("high"), want: diff.Gate{FailOn: sarif.SeverityHigh, Base: "high"}},
		{name: "band beside severity", failOn: sarif.SeverityCritical, head: gate("critical"), base: recorded("P1"),
			want: diff.Gate{FailOn: sarif.SeverityCritical, FailOnPriority: "P1", Base: "P1", Head: "critical"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := withBaseGate(tc.failOn, tc.band, false, tc.head, tc.base); got != tc.want {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
	if got := withBaseGate("", "P1", true, gate("P1"), recorded("P4")); got != (diff.Gate{FailOnPriority: "P1"}) {
		t.Errorf("a typed --fail-on-new was held to the base's gate: %+v", got)
	}
}
