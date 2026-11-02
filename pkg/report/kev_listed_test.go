package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/skald"
)

// onKEV is the listing the engine stamps on a finding whose CVE KEV lists.
var onKEV = &sarif.Match{Signal: "kev", Detail: "on KEV", AsOf: "2026-10-30"}

// listedBrotli is a critical finding on KEV, which KEV therefore raised nothing on, in one
// component's repository.
func listedBrotli(component, repository string) sarif.Result {
	return sarif.Result{
		Tool: "trivy", RuleID: "CVE-2026-111497", Level: sarif.LevelError, Score: 9.8, HasScore: true,
		Priority: "P1", Component: component, Repository: repository,
		Location:  sarif.Location{URI: "Dockerfile"},
		Message:   "brotli: Out-of-Bounds Write in Google Brotli Decoder",
		Package:   &sarif.Package{Name: "brotli-libs", Version: "1.2.0-r1", FixedVersion: "1.2.1-r0", Ecosystem: "apk"},
		Exploited: onKEV,
	}
}

// xnet is a critical finding in golang.org/x/net that no catalog lists.
func xnet(rule, component, repository string) sarif.Result {
	return sarif.Result{
		Tool: "trivy", RuleID: rule, Level: sarif.LevelError, Score: 9.1, HasScore: true,
		Priority: "P1", Component: component, Repository: repository,
		Location: sarif.Location{URI: "go.mod", StartLine: 7},
		Message:  "golang.org/x/net/http2: excessive memory use",
		Package:  &sarif.Package{Name: "golang.org/x/net", Version: "v0.58.0", FixedVersion: "v0.60.0", Ecosystem: "gomod"},
	}
}

// kevListedRun is two components in two repositories, each with a critical finding on KEV and a
// larger bump in the same band that clears three critical findings nobody is known to exploit.
func kevListedRun() []sarif.Result {
	var out []sarif.Result
	for _, c := range []struct{ component, repository string }{{"api", "repo-api"}, {"worker", "repo-worker"}} {
		out = append(out,
			xnet("CVE-2026-0001", c.component, c.repository),
			xnet("CVE-2026-0002", c.component, c.repository),
			xnet("CVE-2026-0003", c.component, c.repository),
			listedBrotli(c.component, c.repository),
		)
	}
	return out
}

func kevData(results []sarif.Result) Data {
	return Data{
		Verdict:        norn.Result{Verdict: norn.Fail},
		Exploitability: []FeedProvenance{{Name: "kev"}},
		Run: engine.Result{Controls: map[string]plugin.ControlResult{
			"sca": {Control: "sca", Report: sarif.Report{Tool: "trivy", Results: results}},
		}},
	}
}

// A finding the scanner already rated critical is on KEV and KEV raises nothing. The action that
// clears it still comes first in its band, ahead of a bump clearing more findings, and carries the
// listing as its exploitation evidence, in each component and each repository.
func TestAnActionClearingACriticalFindingOnKEVComesFirstInItsBand(t *testing.T) {
	got := ActionsFor(map[string]sarif.Report{"sca": {Results: kevListedRun()}})
	if len(got) != 4 {
		t.Fatalf("actions = %+v, want an upgrade of each package in each component", got)
	}
	seen := map[string]bool{}
	for i, a := range got[:2] {
		if a.Package != "brotli-libs" {
			t.Errorf("action %d upgrades %q, want brotli-libs ahead of the larger golang.org/x/net bumps", i, a.Package)
		}
		want := skald.ActionExploitation{Signal: "kev", RuleID: "CVE-2026-111497", Detail: "on KEV", AsOf: "2026-10-30"}
		if a.Exploitation == nil || *a.Exploitation != want {
			t.Errorf("action %d exploitation = %+v, want %+v", i, a.Exploitation, want)
		}
		if a.SeverityFrom != "" {
			t.Errorf("action %d severityFrom = %q; KEV moved nothing", i, a.SeverityFrom)
		}
		for _, l := range a.Locations {
			seen[a.Component+"@"+l.Repository] = true
		}
	}
	if !seen["api@repo-api"] || !seen["worker@repo-worker"] {
		t.Errorf("the KEV actions name %v, want one in each component's own repository", seen)
	}
	for i, a := range got[2:] {
		if a.Package != "golang.org/x/net" || a.Clears != 3 || a.Exploitation != nil {
			t.Errorf("action %d = %s clearing %d with exploitation %+v, want an x/net bump with none",
				i+2, a.Package, a.Clears, a.Exploitation)
		}
	}
}

// The console's KEV line counts the findings KEV lists, not only the ones it raised, so a run whose
// listed findings were already critical does not read "nothing raised".
func TestTheKEVLineCountsTheFindingsOnTheCatalog(t *testing.T) {
	t.Setenv("COLUMNS", "")
	d := kevData(kevListedRun())
	var b bytes.Buffer
	if err := (consoleReporter{}).Render(&b, d); err != nil {
		t.Fatal(err)
	}
	if out := b.String(); !strings.Contains(out, "\n  KEV  2 findings listed\n") {
		t.Errorf("the KEV line should count both listed findings and no raise:\n%s", out)
	}
	// Neither listed finding moved, so neither row wears a mark saying it did.
	if strings.Contains(b.String(), "↑ KEV") {
		t.Errorf("a finding KEV raised nothing on is marked as raised:\n%s", b.String())
	}

	d.View = ViewActions
	b.Reset()
	if err := (consoleReporter{}).Render(&b, d); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if first, bump := strings.Index(out, "brotli-libs"), strings.Index(out, "golang.org/x/net"); first < 0 || bump < 0 || first > bump {
		t.Errorf("the fix list should lead with the brotli-libs upgrade:\n%s", out)
	}
}

// A finding KEV raised is still recorded as raised: its row wears the mark, the line counts it among
// the raised as well as the listed, and report.json carries both the escalation and the listing.
func TestAFindingKEVRaisedStillSaysItWasRaised(t *testing.T) {
	t.Setenv("COLUMNS", "")
	raised := xnet("CVE-2026-0009", "api", "repo-api")
	raised.Level, raised.Score = sarif.LevelWarning, 7.5
	raised.Exploited = onKEV
	raised.Escalation = &sarif.Escalation{From: sarif.SeverityHigh, To: sarif.SeverityCritical,
		Signal: "kev", Detail: "on KEV", AsOf: "2026-10-30"}
	d := kevData([]sarif.Result{listedBrotli("worker", "repo-worker"), raised})

	var b bytes.Buffer
	if err := (consoleReporter{}).Render(&b, d); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "\n  KEV  2 findings listed · 1 raised\n") {
		t.Errorf("the KEV line should count two listed and one raised:\n%s", out)
	}
	if strings.Count(out, "↑ KEV") != 1 {
		t.Errorf("want one row marked as raised by KEV:\n%s", out)
	}

	// The document lists findings only under a --min-priority.
	d.MinPriority = "P4"
	var doc bytes.Buffer
	if err := (jsonReporter{}).Render(&doc, d); err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Findings []struct {
			RuleID     string            `json:"ruleId"`
			Escalation *sarif.Escalation `json:"escalation"`
			Exploited  *sarif.Match      `json:"exploited"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(doc.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Findings) != 2 {
		t.Fatalf("findings = %+v, want both", parsed.Findings)
	}
	for _, f := range parsed.Findings {
		if f.Exploited == nil || f.Exploited.Signal != "kev" {
			t.Errorf("%s: exploited = %+v, want the KEV listing", f.RuleID, f.Exploited)
		}
		if raisedByKEV := f.Escalation != nil; raisedByKEV != (f.RuleID == "CVE-2026-0009") {
			t.Errorf("%s: escalation = %+v, want one only on the finding KEV raised", f.RuleID, f.Escalation)
		}
	}
}

// A report written before the listing was recorded apart carries it only in the escalation, and
// reads the same.
func TestAnEscalationAloneStillCountsAsAListing(t *testing.T) {
	res := xnet("CVE-2026-0009", "api", "repo-api")
	res.Escalation = &sarif.Escalation{From: sarif.SeverityHigh, To: sarif.SeverityCritical,
		Signal: "kev", Detail: "on KEV", AsOf: "2026-08-01"}
	if m := exploitedOf(res); m == nil || *m != (sarif.Match{Signal: "kev", Detail: "on KEV", AsOf: "2026-08-01"}) {
		t.Errorf("exploitedOf = %+v, want the escalation's listing", m)
	}
	res.Escalation.Signal = "epss"
	if m := exploitedOf(res); m != nil {
		t.Errorf("exploitedOf = %+v for an EPSS raise, want nil", m)
	}
}

// A run that consulted KEV and found nothing on it says so, and one that never consulted it has no
// row.
func TestTheKEVLineSaysNothingListed(t *testing.T) {
	d := kevData([]sarif.Result{xnet("CVE-2026-0001", "api", "repo-api")})
	rows, _ := signals(d, summarize(d))
	if len(rows) != 1 || rows[0].Name != "KEV" || rows[0].Did != "nothing listed" {
		t.Errorf("rows = %+v, want KEV saying nothing listed", rows)
	}
	d.Exploitability = nil
	if rows, _ := signals(d, summarize(d)); len(rows) != 0 {
		t.Errorf("rows = %+v, want none for a run that never consulted KEV", rows)
	}
}
