package scanners_test

import (
	"context"
	"slices"
	"testing"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/scanners"
	"github.com/draugr-dev/draugr/pkg/plugin"
)

// noDataReaderYet names the scanners that keep data on this machine and have no reader for it yet,
// each with what is missing. An entry is a known gap rather than a pass, and the test fails once the
// scanner reports its data, so the entry goes when the reader arrives.
var noDataReaderYet = map[string]string{
	"cosign": "cosign keeps the Sigstore trust root under ~/.sigstore, and nothing reads its version or fetch time",
}

// Every registered scanner that keeps data on this machine reports how current it is, under the
// names it declares, so the report and the network list in doctor speak of the same thing.
//
// The scanners come from the registry rather than a list here, so one registered tomorrow is held
// to this the day it is registered. Data a tool fetches on every scan (PerScan) is exempt: there is
// no copy on the machine to date.
func TestEveryScannerReadingDatedDataReportsIt(t *testing.T) {
	scanners.FakeDataReaders(t)
	checked := 0
	for _, sc := range builtins.Registry().Scanners() {
		info := sc.Info()
		if gap, ok := noDataReaderYet[info.Name]; ok {
			if _, reports := sc.(plugin.DataStater); reports {
				t.Errorf("%s now reports its data; remove it from noDataReaderYet (%s)", info.Name, gap)
			}
			continue
		}
		var held, declared []string
		for _, d := range info.Data {
			declared = append(declared, d.Name)
			if !d.PerScan {
				held = append(held, d.Name)
			}
		}
		if len(held) == 0 {
			continue
		}
		checked++
		ds, ok := sc.(plugin.DataStater)
		if !ok {
			t.Errorf("%s reads %v and implements no plugin.DataStater, so a report cannot say how current it is",
				info.Name, held)
			continue
		}
		var reported []string
		for _, st := range ds.DataState(context.Background()) {
			reported = append(reported, st.Name)
			if !slices.Contains(declared, st.Name) {
				t.Errorf("%s reports %q, which it does not declare among %v", info.Name, st.Name, declared)
			}
		}
		for _, name := range held {
			if !slices.Contains(reported, name) {
				t.Errorf("%s reads its %s and does not report it (reported %v)", info.Name, name, reported)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no registered scanner declares data it keeps, so this test checked nothing")
	}
}
