package engine

import (
	"context"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// coverageScanner finds something in the api component's target and nothing to analyze in web's,
// and names the database it read either way, as gosec and govulncheck do.
type coverageScanner struct{}

func (coverageScanner) Info() plugin.ScannerInfo { return plugin.ScannerInfo{Name: "cov"} }
func (coverageScanner) Scan(_ context.Context, t plugin.Target, _ plugin.Config) (sarif.Report, error) {
	rep := sarif.Report{Tool: "cov", Provenance: []sarif.Provenance{
		{Tool: "cov", Fields: []sarif.Field{{Key: "database", Value: "2026-10-04"}}},
	}}
	if t.(plugin.ImageTarget).Ref == "web" {
		rep.Provenance = append(rep.Provenance, sarif.Provenance{Tool: "cov",
			Fields: []sarif.Field{{Key: "coverage", Value: "no go.mod found, so nothing here was analyzed"}}})
		return rep, nil
	}
	rep.Results = []sarif.Result{{RuleID: "G101", Level: sarif.LevelError, Location: sarif.Location{URI: "main.go"}}}
	return rep, nil
}

// A coverage note is true of the target one job read. Two components, one with nothing to analyze:
// the note carries that component, and what is true of the tool wherever it ran is still one entry.
func TestACoverageNoteCarriesItsComponent(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "sast", scope: plugin.ScopeComponent, scanner: "cov"})
	reg.RegisterScanner(coverageScanner{})
	model := saga.Model{
		Config:     saga.Config{Controls: map[string]saga.ControllerSettings{"sast": {"enabled": true}}},
		Components: []saga.Component{{Name: "api"}, {Name: "web"}},
	}
	res, err := New(reg).Run(context.Background(), model)
	if err != nil {
		t.Fatal(err)
	}
	var coverage, database []sarif.Provenance
	for _, p := range res.Controls["sast"].Report.Provenance {
		switch p.Fields[0].Key {
		case "coverage":
			coverage = append(coverage, p)
		case "database":
			database = append(database, p)
		}
	}
	if len(coverage) != 1 || coverage[0].Component != "web" {
		t.Errorf("coverage = %+v, want one note, about web", coverage)
	}
	if len(database) != 1 || database[0].Component != "" {
		t.Errorf("database = %+v, want one entry for the tool, with no component", database)
	}
}
