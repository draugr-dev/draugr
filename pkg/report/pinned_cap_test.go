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

// A pinned action held at P3 says why its band moved, as an unreachable verdict does: the console
// marks it, the HTML report offers it under Movement, and report.json and the SARIF keep the reason.
func TestAPinnedActionSaysWhyItsBandMoved(t *testing.T) {
	r := sarif.Result{Tool: "Semgrep OSS", RuleID: "yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag",
		Level: sarif.LevelError, Message: "m", Control: "sast", Priority: "P3", Aside: sarif.AsidePinned,
		PriorityCap: "pinned to a commit by .github/workflows/actions.lock",
		Location:    sarif.Location{URI: ".github/workflows/ci.yml", StartLine: 9}}
	d := Data{Run: engine.Result{Controls: map[string]plugin.ControlResult{"sast": {Report: sarif.Report{Results: []sarif.Result{r}}}}}}
	var buf bytes.Buffer
	if err := (consoleReporter{}).Render(&buf, d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "↓ pinned") {
		t.Errorf("the console does not mark the band:\n%s", buf.String())
	}

	listed := d
	listed.MinPriority = "P4"
	buf.Reset()
	if err := (htmlReporter{}).Render(&buf, listed); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "held at P3, pinned by actions.lock") {
		t.Error("the HTML Movement menu does not offer the pinned cap")
	}

	buf.Reset()
	if err := (jsonReporter{}).Render(&buf, listed); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Findings []struct {
			PriorityCap string `json:"priorityCap"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Findings) != 1 || doc.Findings[0].PriorityCap != r.PriorityCap {
		t.Errorf("report.json findings = %+v", doc.Findings)
	}

	raw, err := sarif.Report{Tool: "Semgrep OSS", Results: []sarif.Result{r}}.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	back, err := sarif.FromSARIF(raw)
	if err != nil {
		t.Fatal(err)
	}
	if back.Results[0].PriorityCap != r.PriorityCap {
		t.Errorf("read back cap %q", back.Results[0].PriorityCap)
	}
}
