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

// dropRun is an iac run over one component holding two repositories, each with a Dockerfile that sets
// no USER. Only the api repository's entrypoint drops root. A Terraform finding shares their band
// with a lower score, and a P2 follows.
func dropRun() Data {
	misconfig := func(repo, rule, msg, uri string, score float64, priority string, drop *sarif.PrivilegeDrop) sarif.Result {
		return sarif.Result{Tool: "Trivy", Scanner: "trivy-config", RuleID: rule, Level: sarif.LevelError,
			Message: msg, Control: "iac", Priority: priority, Component: "shop", Repository: repo,
			Location: sarif.Location{URI: uri, StartLine: 1}, Score: score, HasScore: true, PrivilegeDrop: drop}
	}
	userMsg := "Specify at least 1 USER command in Dockerfile with non-root user as argument"
	results := []sarif.Result{
		misconfig("https://example.com/shop/api", "DS-0002", userMsg, "Dockerfile", 8, "P1",
			&sarif.PrivilegeDrop{Command: "su-exec", User: "$PUID:$PGID", File: "entrypoint.sh", Line: 12}),
		misconfig("https://example.com/shop/worker", "DS-0002", userMsg, "Dockerfile", 8, "P1", nil),
		misconfig("https://example.com/shop/api", "AWS-0086", "No public access block so not blocking public acls",
			"main.tf", 7.5, "P1", nil),
		misconfig("https://example.com/shop/api", "AWS-0089", "Bucket has logging disabled", "logs.tf", 9.5, "P2", nil),
	}
	d := Data{Run: engine.Result{Controls: map[string]plugin.ControlResult{"iac": {Report: sarif.Report{Results: results}}}}}
	d.TopN = -1
	return d
}

// A Dockerfile finding whose entrypoint drops root is listed after the shipped findings of its band it
// would otherwise lead, in the findings list and in the fix list, keeps its band and its count, and
// names the line that drops root. The worker repository's copy of the same finding has no such line
// and keeps its place.
func TestAnEntrypointThatDropsRootListsTheFindingAfterItsBand(t *testing.T) {
	d := dropRun()
	s := summarize(d)
	var order []string
	for _, f := range s.findings {
		order = append(order, f.ruleID+"@"+shortRepository(f.repository)+" "+f.priority)
	}
	want := []string{"DS-0002@shop/worker P1", "AWS-0086@shop/api P1", "DS-0002@shop/api P1", "AWS-0089@shop/api P2"}
	if strings.Join(order, ", ") != strings.Join(want, ", ") {
		t.Errorf("findings = %v, want %v", order, want)
	}
	if s.p1 != 3 || s.p2 != 1 || s.controlFindings["iac"] != 4 {
		t.Errorf("counts p1 %d p2 %d iac %d, want 3, 1 and 4: the evidence moves no band and no count", s.p1, s.p2, s.controlFindings["iac"])
	}

	actions, _ := groupActions(s.findings, nil)
	order = order[:0]
	for _, a := range actions {
		order = append(order, a.findings[0].ruleID+"@"+shortRepository(a.findings[0].repository)+" "+a.priority)
	}
	if strings.Join(order, ", ") != strings.Join(want, ", ") {
		t.Errorf("fix list = %v, want %v", order, want)
	}

	var buf bytes.Buffer
	if err := (consoleReporter{}).Render(&buf, d); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	t.Logf("rendered:\n%s", out)
	evidence := "Dockerfile:1 · entrypoint drops root: su-exec in entrypoint.sh:12"
	if strings.Count(out, evidence) != 1 {
		t.Errorf("the console does not name the line that drops root once, %q", evidence)
	}
	if lead, dropped := strings.Index(out, "AWS-0086"), strings.Index(out, evidence); lead < 0 || dropped < lead {
		t.Errorf("the finding whose entrypoint drops root is not listed after AWS-0086")
	}
}

// report.json carries the evidence on the finding, counts it in its band, and lists the action that
// clears it after the rest of its band.
func TestReportJSONCarriesThePrivilegeDrop(t *testing.T) {
	d := dropRun()
	d.MinPriority = "P4"
	var buf bytes.Buffer
	if err := (jsonReporter{}).Render(&buf, d); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Priorities struct{ P1, P2 int } `json:"priorities"`
		Findings   []struct {
			RuleID        string               `json:"ruleId"`
			PrivilegeDrop *sarif.PrivilegeDrop `json:"privilegeDrop"`
		} `json:"findings"`
		Actions []struct {
			Priority string `json:"priority"`
			Title    string `json:"title"`
		} `json:"actions"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Priorities.P1 != 3 || doc.Priorities.P2 != 1 {
		t.Errorf("priorities %+v, want 3 P1 and 1 P2", doc.Priorities)
	}
	drops := 0
	for _, f := range doc.Findings {
		if f.PrivilegeDrop != nil {
			drops++
			if f.RuleID != "DS-0002" || f.PrivilegeDrop.File != "entrypoint.sh" || f.PrivilegeDrop.Line != 12 {
				t.Errorf("privilegeDrop %+v on %s", f.PrivilegeDrop, f.RuleID)
			}
		}
	}
	if drops != 1 {
		t.Errorf("%d findings carry privilegeDrop, want 1", drops)
	}
	if len(doc.Actions) != 4 || doc.Actions[2].Priority != "P1" || doc.Actions[3].Priority != "P2" {
		t.Errorf("actions %+v, want the dropped DS-0002 third, still P1", doc.Actions)
	}
}

// The evidence survives results.sarif, so a report read back orders the findings as the run did.
func TestPrivilegeDropSurvivesTheSARIFFile(t *testing.T) {
	in := sarif.Report{Tool: "Trivy", Results: []sarif.Result{{Tool: "Trivy", RuleID: "DS-0002", Level: sarif.LevelError,
		Message: "m", Location: sarif.Location{URI: "Dockerfile", StartLine: 1},
		PrivilegeDrop: &sarif.PrivilegeDrop{Command: "gosu", User: "app", File: "docker/entrypoint.sh", Line: 3}}}}
	before := in.Results[0].Fingerprint()
	raw, err := in.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	out, err := sarif.FromSARIF(raw)
	if err != nil {
		t.Fatal(err)
	}
	r := out.Results[0]
	if r.PrivilegeDrop == nil || *r.PrivilegeDrop != *in.Results[0].PrivilegeDrop {
		t.Errorf("read back privilegeDrop %+v", r.PrivilegeDrop)
	}
	in.Results[0].PrivilegeDrop = nil
	if in.Results[0].Fingerprint() != before {
		t.Error("the evidence changed the finding's identity")
	}
}

// A finding whose entrypoint drops root never shares a row with one whose image runs as root.
func TestARowNeverJoinsADroppedImageToARootOne(t *testing.T) {
	root := finding{priority: "P1", ruleID: "DS-0002", component: "shop", location: "a/Dockerfile:1"}
	dropped := root
	dropped.location = "b/Dockerfile:1"
	dropped.privilegeDrop = &sarif.PrivilegeDrop{Command: "su-exec", User: "app", File: "b/entrypoint.sh", Line: 2}
	if rows := foldFindings([]finding{root, dropped}); len(rows) != 2 {
		t.Errorf("rows = %d, want the two apart", len(rows))
	}
	if privilegeDropNote(nil) != "" {
		t.Error("a finding without evidence has a note")
	}
}
