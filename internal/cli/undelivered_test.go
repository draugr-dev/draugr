package cli

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
)

// TestUndeliveredReportsOnlyWhenThereIsNowhereToGo keeps the warning off runs that are fine.
//
// A line that appears when nothing is wrong is a line every reader learns to skip, and then they
// skip it on the day it means something.
func TestUndeliveredReportsOnlyWhenThereIsNowhereToGo(t *testing.T) {
	declared := &saga.Model{Config: saga.Config{
		Reports: []saga.ReportConfig{{Format: "html"}, {Format: "markdown"}},
	}}
	withPublisher := &saga.Model{Config: saga.Config{
		Reports:    []saga.ReportConfig{{Format: "html"}},
		Publishers: []saga.PublisherConfig{{Kind: "file"}},
	}}

	for _, c := range []struct {
		name  string
		model *saga.Model
		opts  scanOptions
		want  int
	}{
		{"nowhere to write them", declared, scanOptions{}, 2},
		{"an output directory takes them", declared, scanOptions{outputDir: "out"}, 0},
		{"a publisher delivers them", withPublisher, scanOptions{}, 0},
		{"nothing declared", &saga.Model{}, scanOptions{}, 0},
		{"no descriptor at all", nil, scanOptions{}, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := undeliveredReports(c.model, c.opts); len(got) != c.want {
				t.Errorf("got %v, want %d formats", got, c.want)
			}
		})
	}
}
