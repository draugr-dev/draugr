package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// rankedMovesData holds one finding per move the prioritizer records, across two controls and two
// repositories, so a severity collapsed across either cannot pass.
func rankedMovesData() Data {
	const repoA, repoB = "https://github.com/acme/a.git", "https://github.com/acme/b.git"
	unreachable := func(rankedAs sarif.Severity) *sarif.Reachability {
		return &sarif.Reachability{State: sarif.ReachabilityUnreachable, Analyzer: "govulncheck",
			Method: sarif.MethodCallGraph, RankedAs: rankedAs}
	}
	sca := []sarif.Result{
		{RuleID: "CVE-2099-0001", Level: sarif.LevelError, Score: 7.5, HasScore: true, Priority: "P2",
			Tool: "trivy", Repository: repoA, Location: sarif.Location{URI: "go.mod", StartLine: 1},
			Message: "untouched"},
		{RuleID: "CVE-2021-44228", Level: sarif.LevelError, Score: 7.5, HasScore: true, Priority: "P1",
			Tool: "trivy", Repository: repoA, Location: sarif.Location{URI: "go.mod", StartLine: 2},
			Message: "raised by KEV",
			Escalation: &sarif.Escalation{From: sarif.SeverityHigh, To: sarif.SeverityCritical,
				Signal: "kev", Detail: "on KEV", AsOf: "2026-11-05"}},
		{RuleID: "CVE-2099-0002", Level: sarif.LevelError, Score: 9.8, HasScore: true, Priority: "P2",
			Tool: "govulncheck", Repository: repoB, Location: sarif.Location{URI: "go.mod", StartLine: 3},
			Message: "lowered as unreachable", Reachability: unreachable(sarif.SeverityHigh)},
		{RuleID: "CVE-2099-0003", Level: sarif.LevelNote, Score: 2.0, HasScore: true, Priority: "P4",
			Tool: "trivy", Repository: repoB, Location: sarif.Location{URI: "go.mod", StartLine: 4},
			Message: "raised by deprecation, then lowered",
			Escalation: &sarif.Escalation{From: sarif.SeverityLow, To: sarif.SeverityMedium,
				Signal: "deprecated", Detail: "deprecated", AsOf: "2026-11-05"},
			Reachability: unreachable(sarif.SeverityLow)},
	}
	secrets := []sarif.Result{
		{RuleID: "generic-api-key", Level: sarif.LevelWarning, Priority: "P1", SeverityFloor: sarif.SeverityHigh,
			Tool: "gitleaks", Repository: repoB, Location: sarif.Location{URI: "config.env", StartLine: 5},
			Message: "held at the floor"},
	}
	return Data{
		Project:     "acme",
		Release:     saga.Release{Version: "1.0.0"},
		MinPriority: "P4",
		View:        ViewFindings,
		Run: engine.Result{Controls: map[string]plugin.ControlResult{
			"sca":     {Control: "sca", Report: sarif.Report{Tool: "trivy", Results: sca}},
			"secrets": {Control: "secrets", Report: sarif.Report{Tool: "gitleaks", Results: secrets}},
		}},
		Verdict: norn.Result{Verdict: norn.Fail, Controls: []norn.ControlOutcome{
			{Control: "sca", Verdict: norn.Fail},
			{Control: "secrets", Verdict: norn.Fail},
		}},
	}
}

// The severity each human format prints beside the band is the accessor's, on every row and for
// every move, which is the value a severity gate judges.
func TestThePrintedSeverityIsTheRankedSeverity(t *testing.T) {
	d := rankedMovesData()
	var rows []sarif.Result
	for _, cr := range d.Run.Controls {
		rows = append(rows, cr.Report.Results...)
	}

	var console bytes.Buffer
	if err := (consoleReporter{}).Render(&console, d); err != nil {
		t.Fatal(err)
	}
	var markdown bytes.Buffer
	if err := (markdownReporter{}).Render(&markdown, d); err != nil {
		t.Fatal(err)
	}
	printed := map[string]string{
		"CVE-2099-0001":   "high",
		"CVE-2021-44228":  "critical",
		"CVE-2099-0002":   "high",
		"CVE-2099-0003":   "low",
		"generic-api-key": "high",
	}
	for _, res := range rows {
		want := string(res.RankedSeverity())
		if want != printed[res.RuleID] {
			t.Errorf("%s (%s): RankedSeverity %q, want %q", res.RuleID, res.Message, want, printed[res.RuleID])
		}
		line := lineNaming(console.String(), res.RuleID)
		if line == "" {
			t.Fatalf("no console row names %s:\n%s", res.RuleID, console.String())
		}
		if fields := strings.Fields(line); len(fields) < 2 || fields[1] != want {
			t.Errorf("%s (%s): console row %q, want severity %q beside the band", res.RuleID, res.Message, line, want)
		}
		// Markdown writes the mark after the severity, "critical ↑ KEV".
		md := lineNaming(markdown.String(), res.RuleID)
		cell := "| " + res.Priority + " | " + want
		if !strings.Contains(md, cell+" |") && !strings.Contains(md, cell+" ↑") && !strings.Contains(md, cell+" ↓") {
			t.Errorf("%s (%s): markdown row %q, want %q beside %s", res.RuleID, res.Message, md, want, res.Priority)
		}
	}
	// The same value the finding the renderers hold carries.
	s := summarize(d)
	for _, f := range s.findings {
		for _, res := range rows {
			if res.RuleID == f.ruleID && rankedSeverity(f) != res.RankedSeverity() {
				t.Errorf("%s: rankedSeverity %q, accessor %q", f.ruleID, rankedSeverity(f), res.RankedSeverity())
			}
		}
	}
}

// GitLab's approval policies gate on the security report's severity, so it carries the value
// Draugr's own severity gate judges: a KEV-listed high blocks a Critical policy, an unreachable
// critical does not, and a floored secret is High.
func TestGitLabCarriesTheRankedSeverity(t *testing.T) {
	d := rankedMovesData()
	sca := d.Run.Controls["sca"]
	for i := range sca.Report.Results {
		sca.Report.Results[i].Package = &sarif.Package{Name: "lib", Version: "1.0.0", FixedVersion: "1.0.1"}
	}
	d.Run.Controls["sca"] = sca
	want := map[string]string{
		"CVE-2099-0001":  "High",
		"CVE-2021-44228": "Critical",
		"CVE-2099-0002":  "High",
		"CVE-2099-0003":  "Low",
	}
	got := map[string]string{}
	for _, v := range decodeSecurity(t, renderGitLab(t, "gitlab-dependency-scanning", d)).Vulnerabilities {
		got[v.Name] = v.Severity
	}
	for rule, sev := range want {
		if got[rule] != sev {
			t.Errorf("%s: GitLab severity %q, want %q", rule, got[rule], sev)
		}
	}
	for _, c := range []struct {
		res  sarif.Result
		lead string
	}{
		{sca.Report.Results[1], "CRITICAL: "},
		{d.Run.Controls["secrets"].Report.Results[0], "HIGH: "},
	} {
		if desc := gitlabCodeQualityDescription(c.res); !strings.HasPrefix(desc, c.lead) {
			t.Errorf("code quality description %q, want it to lead with %q", desc, c.lead)
		}
	}
}

// lineNaming is the first line of out that contains id.
func lineNaming(out, id string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, id) {
			return line
		}
	}
	return ""
}
