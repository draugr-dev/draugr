package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// asideRun holds one finding of each kind set aside, one in hand-written code and one under tests,
// all at the same band.
func asideRun() Data {
	at := func(control, tool, rule, uri, aside, nonShipping string) sarif.Result {
		return sarif.Result{Tool: tool, RuleID: rule, Level: sarif.LevelWarning, Message: "m", Control: control, Priority: "P1",
			Location: sarif.Location{URI: uri, StartLine: 3}, Aside: aside, NonShipping: nonShipping}
	}
	return Data{Run: engine.Result{Controls: map[string]plugin.ControlResult{
		"sast": {Report: sarif.Report{Results: []sarif.Result{
			at("sast", "gosec", "G115", "gen/sizes_gen.go", sarif.AsideGenerated, ""),
			at("sast", "semgrep", "mutable-action-tag", ".github/workflows/ci.yml", sarif.AsidePinned, ""),
			at("sast", "gosec", "G204", "main.go", "", ""),
			at("sast", "gosec", "G204", "tests/helper.go", "", "test"),
		}}},
		"sca": {Report: sarif.Report{Results: []sarif.Result{
			at("sca", "trivy", "CVE-2026-1", ".config/mise/locks/uv.lock", sarif.AsideTooling, ""),
		}}},
	}}}
}

// Findings set aside are listed after the hand-written code's and before those under tests, each
// with its reason beside its location, under a heading that does not call the order shipped code
// first; a generated file's fix points at the generator.
func TestFindingsSetAsideAreListedLastWithTheirReason(t *testing.T) {
	var buf bytes.Buffer
	if err := (consoleReporter{}).Render(&buf, asideRun()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	t.Logf("rendered:\n%s", out)
	order := []string{
		"      main.go:3\n",
		"      gen/sizes_gen.go:3 · generated\n",
		"      tests/helper.go:3 · test\n",
	}
	last := -1
	for _, want := range order {
		i := strings.Index(out, want)
		if i < 0 {
			t.Errorf("the console does not hold %q", want)
			continue
		}
		if i < last {
			t.Errorf("%q is listed before the row above it in %v", want, order)
		}
		last = i
	}
	for _, want := range []string{
		".github/workflows/ci.yml:3 · pinned by actions.lock",
		".config/mise/locks/uv.lock:3 · developer tool, runs in CI",
		"fix change the generator, then regenerate",
		"Pinned to a commit by .github/workflows/actions.lock",
		"fix keep actions.lock verified in CI",
		"generated code, developer tools, pinned actions and tests last, by priority",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the console does not hold %q", want)
		}
	}
	if strings.Contains(out, "shipped code first") {
		t.Error("the heading calls generated code not shipped")
	}

	buf.Reset()
	compact := asideRun()
	compact.View = ViewCompact
	if err := (consoleReporter{}).Render(&buf, compact); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "gen/sizes_gen.go:3 · generated") {
		t.Errorf("the compact view does not name the reason:\n%s", buf.String())
	}

	buf.Reset()
	listed := asideRun()
	listed.MinPriority = "P4"
	if err := (jsonReporter{}).Render(&buf, listed); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Findings []struct {
			Location string `json:"location"`
			Aside    string `json:"aside"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range doc.Findings {
		got[f.Location] = f.Aside
	}
	if got["gen/sizes_gen.go:3"] != "generated" || got[".config/mise/locks/uv.lock:3"] != "tooling" || got["main.go:3"] != "" {
		t.Errorf("report.json aside by location = %v", got)
	}

	buf.Reset()
	if err := (htmlReporter{}).Render(&buf, listed); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "pinned by actions.lock") {
		t.Error("the HTML report does not name the reason")
	}
}

// The reason survives a report written to SARIF and read back.
func TestAsideSurvivesTheSARIFFile(t *testing.T) {
	in := sarif.Report{Tool: "gosec", Results: []sarif.Result{{
		Tool: "gosec", RuleID: "G115", Level: sarif.LevelWarning, Message: "m",
		Location: sarif.Location{URI: "gen/sizes_gen.go", StartLine: 3}, Aside: sarif.AsideGenerated,
	}}}
	raw, err := in.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	out, err := sarif.FromSARIF(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := out.Results[0].Aside; got != sarif.AsideGenerated {
		t.Errorf("read back aside %q", got)
	}
}

func TestAsideNote(t *testing.T) {
	for in, want := range map[string]string{
		"": "", sarif.AsideGenerated: "generated", sarif.AsideTooling: "developer tool, runs in CI",
		sarif.AsidePinned: "pinned by actions.lock", "other": "other",
	} {
		if got := asideNote(in); got != want {
			t.Errorf("asideNote(%q) = %q, want %q", in, got, want)
		}
	}
}

// The heading names only what is listed last, in the order the rows come.
func TestLastKinds(t *testing.T) {
	fs := []finding{{aside: sarif.AsidePinned}, {nonShipping: "docs"}, {aside: sarif.AsideGenerated, nonShipping: "test"}, {}}
	if got := strings.Join(lastKinds(fs), ", "); got != "pinned actions, docs, tests" {
		t.Errorf("lastKinds = %q", got)
	}
}
