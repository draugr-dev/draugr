package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// advisoryRow is a finding named by its GitHub advisory, which relates CVE-2026-0009.
func advisoryRow() sarif.Result {
	res := xnet("GHSA-4rgh-jx4f-qfcq-golang.org/x/net", "api", "repo-api")
	res.Aliases = []string{"GHSA-4rgh-jx4f-qfcq", "CVE-2026-0009"}
	return res
}

// A row named by its advisory and raised or listed by KEV names the CVE the catalog lists, in the
// console, the markdown and the fix list. A row named by its CVE carries no second copy of it.
func TestARowNamedByItsAdvisoryNamesTheCVEKEVListed(t *testing.T) {
	t.Setenv("COLUMNS", "")
	raised := advisoryRow()
	raised.Level, raised.Score = sarif.LevelWarning, 7.5
	raised.Exploited = &sarif.Match{Signal: "kev", Detail: "on KEV", AsOf: "2026-10-30", CVE: "CVE-2026-0009"}
	raised.Escalation = &sarif.Escalation{From: sarif.SeverityHigh, To: sarif.SeverityCritical,
		Signal: "kev", Detail: "on KEV", AsOf: "2026-10-30", CVE: "CVE-2026-0009"}
	d := kevData([]sarif.Result{raised, listedBrotli("worker", "repo-worker")})

	var b bytes.Buffer
	if err := (consoleReporter{}).Render(&b, d); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "↑ KEV (CVE-2026-0009)") {
		t.Errorf("the advisory's row should name the CVE KEV listed:\n%s", out)
	}
	if strings.Contains(out, "(CVE-2026-111497)") {
		t.Errorf("a row named by its CVE should not repeat it:\n%s", out)
	}

	// The markdown lists actions, and an action whose findings KEV raised carries the mark that ranked
	// it, so a pull-request comment says which fix clears a flaw known to be exploited.
	b.Reset()
	if err := (markdownReporter{}).Render(&b, d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "↑ KEV (CVE-2026-0009)") {
		t.Errorf("the markdown row should name the CVE KEV listed:\n%s", b.String())
	}
	if !strings.Contains(b.String(), "brotli-libs 1.2.0-r1 → 1.2.1-r0 · KEV listed ·") {
		t.Errorf("a fix for a flaw on KEV that KEV did not raise should still say it is listed:\n%s", b.String())
	}

	actions := ActionsFor(map[string]sarif.Report{"sca": {Results: []sarif.Result{raised}}})
	if len(actions) != 1 || actions[0].Exploitation == nil || actions[0].Exploitation.CVE != "CVE-2026-0009" {
		t.Errorf("actions = %+v, want the exploitation evidence naming CVE-2026-0009", actions)
	}

	// Listed and not raised, being critical already.
	listed := advisoryRow()
	listed.Exploited = raised.Exploited
	if m := movedBy(findingOf("sca", sarif.Report{}, listed)); m == nil || m.text() != "KEV listed (CVE-2026-0009)" {
		t.Errorf("mark = %+v, want KEV listed naming the CVE", m)
	}
}

// A run whose only CVE is one a finding lists as an alias is a run KEV and EPSS could have raised,
// so a run that read neither says so.
func TestAnAliasCVEIsOneKEVCouldHaveRaised(t *testing.T) {
	d := kevData([]sarif.Result{advisoryRow()})
	d.Exploitability = nil
	rows, _ := signals(d, summarize(d))
	if len(rows) != 2 || rows[0].Did != "not read · --kev auto reads it" || rows[1].Did != "not read · --epss auto reads it" {
		t.Errorf("rows = %+v, want KEV and EPSS saying they were not read", rows)
	}
}
