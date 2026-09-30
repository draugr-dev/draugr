package cli

import (
	"fmt"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/publish"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
)

func reportFormatsForTest() []string  { return report.Formats() }
func publisherKindsForTest() []string { return publish.Kinds() }

// `validate` answers "will this descriptor work", and said yes to one that fails every run.
func TestValidateRejectsAFormatThisBuildDoesNotHave(t *testing.T) {
	err := checkReportNames(&saga.Model{Config: saga.Config{
		Publishers: []saga.PublisherConfig{{Kind: "file", Dir: "./out",
			Reports: []saga.ReportConfig{{Format: "sarif"}, {Format: "jsonn"}}}},
	}})
	if err == nil {
		t.Fatal("an unrenderable format validated cleanly")
	}
	if !strings.Contains(err.Error(), "jsonn") {
		t.Errorf("the error should name the format: %v", err)
	}
	// A near miss is nearly always a typo, and naming the neighbor saves a trip to the reference.
	if !strings.Contains(err.Error(), `did you mean "json"`) {
		t.Errorf("the error should suggest the neighbor: %v", err)
	}
	// And the list, so a reader who was not typoing has somewhere to go.
	if !strings.Contains(err.Error(), "formats:") {
		t.Errorf("the error should list what is available: %v", err)
	}
}

func TestValidateRejectsAPublisherThisBuildDoesNotHave(t *testing.T) {
	err := checkReportNames(&saga.Model{Config: saga.Config{
		Publishers: []saga.PublisherConfig{{Kind: "gitlab-mr-coment"}},
	}})
	if err == nil {
		t.Fatal("an unknown publisher kind validated cleanly")
	}
	if !strings.Contains(err.Error(), `did you mean "gitlab-mr-comment"`) {
		t.Errorf("the error should suggest the neighbor: %v", err)
	}
}

func TestValidateAcceptsWhatThisBuildActuallyHas(t *testing.T) {
	// Driven by the registries rather than a list written here, so a format that ships without
	// being accepted by validate fails this test rather than a user's pipeline.
	var reports []saga.ReportConfig
	for _, f := range append(reportFormatsForTest(), "template") {
		reports = append(reports, saga.ReportConfig{Format: f})
	}
	// Every kind, each carrying every format, and each distinguished from the next so the
	// duplicate check does not fire on a list whose point is coverage.
	var publishers []saga.PublisherConfig
	for i, k := range publisherKindsForTest() {
		p := saga.PublisherConfig{
			Kind: k, Dir: fmt.Sprintf("./out-%d", i), Repo: fmt.Sprintf("acme/r%d", i),
			Marker: fmt.Sprintf("<!-- %d -->", i), URL: fmt.Sprintf("https://h%d.example", i),
			Reports: reports,
		}
		if publish.IssueKind(k) {
			p.Reports = nil // an issue body is built from the run, so it takes no format
		}
		publishers = append(publishers, p)
	}
	if err := checkReportNames(&saga.Model{Project: "shop", Config: saga.Config{
		Publishers: publishers,
	}}); err != nil {
		t.Errorf("validate rejects something this build provides: %v", err)
	}
}

// An empty format is the descriptor's own required-field check; an empty kind is reported there
// too, so this must not double up on it.
func TestValidateOnEmptyNames(t *testing.T) {
	err := checkReportNames(&saga.Model{Config: saga.Config{
		Publishers: []saga.PublisherConfig{
			{Kind: "file", Dir: "./out", Reports: []saga.ReportConfig{{Format: ""}}},
			{Kind: ""},
		},
	}})
	if err == nil || !strings.Contains(err.Error(), "config.publishers[0].reports[0].format is required") {
		t.Errorf("a missing format should be named: %v", err)
	}
	if err != nil && strings.Contains(err.Error(), "config.publishers[0].kind:") {
		t.Errorf("an empty kind is already reported by the descriptor's own validation: %v", err)
	}
}

func TestCheckReportNamesOnNil(t *testing.T) {
	if err := checkReportNames(nil); err != nil {
		t.Errorf("nil model: %v", err)
	}
}

// The issue fields are held to the kind that reads them, and an issue publisher to what it needs.
func TestValidateIssueFieldsAgainstTheKind(t *testing.T) {
	model := func(project string, p saga.PublisherConfig) *saga.Model {
		return &saga.Model{Project: project, Components: []saga.Component{{Name: "web"}, {Name: "batch"}},
			Config: saga.Config{Publishers: []saga.PublisherConfig{p}}}
	}
	for _, c := range []struct {
		name  string
		model *saga.Model
		want  []string
	}{
		{"complete", model("shop", saga.PublisherConfig{Kind: "github-issue", Label: "sec",
			Select: &saga.PublisherSelect{Components: []string{"web", "batch"}}, Split: saga.SplitControl}), nil},
		{"issue fields on another kind", model("shop", saga.PublisherConfig{Kind: "github-pr-comment",
			Label: "sec", MinPriority: "P2"}),
			[]string{"the github-pr-comment publisher does not read label or minPriority"}},
		{"reports on an issue kind", model("shop", saga.PublisherConfig{Kind: "github-issue",
			Reports: []saga.ReportConfig{{Format: "markdown"}}}),
			[]string{"config.publishers[0].reports", "renders no report"}},
		{"no project", model("", saga.PublisherConfig{Kind: "github-issue"}),
			[]string{"names none; set project"}},
		{"unknown component", model("shop", saga.PublisherConfig{Kind: "github-issue",
			Select: &saga.PublisherSelect{Components: []string{"wbe", "zzz"}}}),
			[]string{`"wbe" is not a component of this descriptor, did you mean "web"?`, `"zzz" is not a component`}},
		{"a GitLab issue", model("shop", saga.PublisherConfig{Kind: "gitlab-issue",
			Item: &saga.IssueItem{Type: "incident", Confidential: new(bool)}}), nil},
		{"confidential on GitHub", model("shop", saga.PublisherConfig{Kind: "github-issue",
			Item: &saga.IssueItem{Confidential: new(bool)}}),
			[]string{"the github-issue publisher does not read item.confidential, which only gitlab-issue reads"}},
		{"a GitHub type on GitLab", model("shop", saga.PublisherConfig{Kind: "gitlab-issue",
			Item: &saga.IssueItem{Type: "Bug"}}),
			[]string{`config.publishers[0].item.type is "Bug", but a GitLab issue type is issue, incident or task`}},
		{"an Azure work item", model("shop", saga.PublisherConfig{Kind: "azure-work-item", Item: &saga.IssueItem{
			Type: "Bug", Tags: []string{"sec"}, AssignedTo: "a@example.com", AreaPath: `Shop\Web`, IterationPath: `Shop\S1`,
			Priority: new(2), Fields: map[string]string{"Custom.Team": "web"}}}), nil},
		{"GitHub keys on Azure", model("shop", saga.PublisherConfig{Kind: "azure-work-item",
			Item: &saga.IssueItem{Labels: []string{"sec"}, Milestone: "Q3"}}),
			[]string{"the azure-work-item publisher does not read item.labels, which only github-issue and gitlab-issue read",
				"does not read item.milestone"}},
		{"Azure keys on GitLab", model("shop", saga.PublisherConfig{Kind: "gitlab-issue",
			Item: &saga.IssueItem{Tags: []string{"sec"}, Priority: new(1)}}),
			[]string{"the gitlab-issue publisher does not read item.tags, which only azure-work-item reads", "item.priority"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := checkReportNames(c.model)
			if len(c.want) == 0 {
				if err != nil {
					t.Fatalf("rejected: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("accepted")
			}
			for _, w := range c.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("want %q in:\n%v", w, err)
				}
			}
		})
	}
}
