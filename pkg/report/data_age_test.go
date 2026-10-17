package report

import (
	"strings"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
)

// Each source says what its tool reports and nothing it does not: a date the tool leaves out is
// absent rather than guessed, and a copy the tool refuses says so whatever else is known.
func TestEachDataSourceSaysWhatItsToolReports(t *testing.T) {
	published := time.Date(2026, 10, 10, 18, 59, 50, 0, time.UTC)
	downloaded := time.Date(2026, 10, 11, 0, 2, 0, 0, time.FixedZone("CDT", -5*3600))
	for _, tc := range []struct {
		name string
		d    engine.ScannerData
		want string
	}{
		{"both dates", engine.ScannerData{Tool: "trivy", DataState: plugin.DataState{Name: "vulnerability database",
			Version: "schema 2", Published: published, Downloaded: downloaded}},
			"trivy vulnerability database published 2026-10-10, downloaded 2026-10-11"},
		{"downloaded only", engine.ScannerData{Tool: "trivy", DataState: plugin.DataState{Name: "checks bundle",
			Version: "1583562f8b90", Downloaded: downloaded}},
			"trivy checks bundle downloaded 2026-10-11"},
		{"refused as too old", engine.ScannerData{Tool: "grype", DataState: plugin.DataState{Name: "vulnerability database",
			Published: published, TooOld: "the vulnerability database was built 6 days ago (max allowed age is 5 days)"}},
			"grype vulnerability database published 2026-10-10, refused as too old"},
		{"refused with no dates", engine.ScannerData{Tool: "grype", DataState: plugin.DataState{Name: "vulnerability database",
			TooOld: "too old"}},
			"grype vulnerability database refused as too old"},
		{"nothing known", engine.ScannerData{Tool: "nuclei", DataState: plugin.DataState{Name: "template set", Version: "v10.3.0"}}, ""},
	} {
		if got := DataSourceState(tc.d); got != tc.want {
			t.Errorf("%s: DataSourceState =\n %q\nwant\n %q", tc.name, got, tc.want)
		}
	}
}

// The row appears under --evidence, one source after another, and not in the default view.
func TestTheDataRowIsEvidence(t *testing.T) {
	d := goldenEvidenceData()
	want := "trivy vulnerability database published 2026-10-10, downloaded 2026-10-11 · retire advisory database downloaded 2026-10-11"
	if got := scannerDataLine(d.Run.Stats.Data); got != want {
		t.Errorf("scannerDataLine =\n %q\nwant\n %q", got, want)
	}
	if out := renderWith(t, consoleReporter{}, d); !strings.Contains(out, "  data        trivy vulnerability database") {
		t.Errorf("no data row in:\n%s", out)
	}
	d.Evidence = false
	if out := renderWith(t, consoleReporter{}, d); strings.Contains(out, "downloaded 2026-10-11") {
		t.Errorf("the default view carries the data row:\n%s", out)
	}
	if got := scannerDataLine(nil); got != "" {
		t.Errorf("scannerDataLine(nil) = %q", got)
	}
}
