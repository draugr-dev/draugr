package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A row whose message is only the upgrade note, as Trivy writes one for an advisory with no title,
// does not print it twice: the Finding cell shows a dash, as an empty cell does elsewhere. A message that goes on to the advisory's
// title keeps the title. The messages are in the shape trivyVulnMessage writes.
func TestTheFindingCellDoesNotRepeatTheUpgrade(t *testing.T) {
	at := func(rule, message, fixed string) sarif.Result {
		return sarif.Result{Tool: "trivy", RuleID: rule, Level: sarif.LevelWarning, Control: "images", Priority: "P2",
			Message: message, Location: sarif.Location{URI: "debian:12"},
			Package: &sarif.Package{Name: "dpkg", Version: "1.21.22", FixedVersion: fixed}}
	}
	d := Data{Run: engine.Result{Controls: map[string]plugin.ControlResult{"images": {Report: sarif.Report{Results: []sarif.Result{
		at("CVE-2026-1", "dpkg 1.21.22, no fix available", ""),
		at("CVE-2026-2", "dpkg 1.21.22 → 1.21.23", "1.21.23"),
		at("CVE-2026-3", "dpkg 1.21.22, no fix available: Arbitrary file overwrite in dpkg", ""),
	}}}}}}
	var buf bytes.Buffer
	if err := (markdownReporter{}).Render(&buf, d); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	t.Logf("rendered:\n%s", out)
	rows := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		for _, id := range []string{"CVE-2026-1", "CVE-2026-2", "CVE-2026-3"} {
			if strings.Contains(line, id) {
				rows[id] = line
			}
		}
	}
	if r := rows["CVE-2026-1"]; strings.Count(r, "no fix available") != 1 || !strings.HasSuffix(r, "| - |") {
		t.Errorf("a message that is only the upgrade note: %q", r)
	}
	if r := rows["CVE-2026-2"]; strings.Count(r, "1.21.23") != 1 || !strings.HasSuffix(r, "| - |") {
		t.Errorf("a message that is only the upgrade to make: %q", r)
	}
	if r := rows["CVE-2026-3"]; !strings.Contains(r, "| Arbitrary file overwrite in dpkg |") {
		t.Errorf("a message that says more: %q", r)
	}
}
