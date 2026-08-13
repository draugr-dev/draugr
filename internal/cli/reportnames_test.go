package cli

import (
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
		Reports: []saga.ReportConfig{{Format: "sarif"}, {Format: "jsonn"}},
	}})
	if err == nil {
		t.Fatal("an unrenderable format validated cleanly")
	}
	if !strings.Contains(err.Error(), "jsonn") {
		t.Errorf("the error should name the format: %v", err)
	}
	// A near miss is nearly always a typo, and naming the neighbour saves a trip to the reference.
	if !strings.Contains(err.Error(), `did you mean "json"`) {
		t.Errorf("the error should suggest the neighbour: %v", err)
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
		t.Errorf("the error should suggest the neighbour: %v", err)
	}
}

func TestValidateAcceptsWhatThisBuildActuallyHas(t *testing.T) {
	// Driven by the registries rather than a list written here, so a format that ships without
	// being accepted by validate fails this test rather than a user's pipeline.
	var reports []saga.ReportConfig
	for _, f := range append(reportFormatsForTest(), "template") {
		reports = append(reports, saga.ReportConfig{Format: f})
	}
	var publishers []saga.PublisherConfig
	for _, k := range publisherKindsForTest() {
		publishers = append(publishers, saga.PublisherConfig{Kind: k})
	}
	if err := checkReportNames(&saga.Model{Config: saga.Config{
		Reports: reports, Publishers: publishers,
	}}); err != nil {
		t.Errorf("validate rejects something this build provides: %v", err)
	}
}

// An empty format is the descriptor's own required-field check; an empty kind is reported there
// too, so this must not double up on it.
func TestValidateOnEmptyNames(t *testing.T) {
	err := checkReportNames(&saga.Model{Config: saga.Config{
		Reports:    []saga.ReportConfig{{Format: ""}},
		Publishers: []saga.PublisherConfig{{Kind: ""}},
	}})
	if err == nil || !strings.Contains(err.Error(), "config.reports[0].format is required") {
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
