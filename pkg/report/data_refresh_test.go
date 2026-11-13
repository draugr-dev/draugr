package report

import (
	"strings"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/engine"
)

var coldRefresh = []engine.DataRefresh{
	{Scanner: "trivy-config", Data: []string{"checks bundle"}, Took: 1388 * time.Millisecond},
	{Scanner: "trivy", Data: []string{"vulnerability database"}, Took: 4340 * time.Millisecond},
	{Scanner: "cosign", Data: []string{"Sigstore trust root"}, Took: 553 * time.Millisecond},
	{Scanner: "gitleaks", Took: 0},
}

// The title line is the verdict, what was scanned and how long it took, a cold run's included. How
// much of that time went to refreshing scanner data is --evidence's to say, on its run row.
func TestTheTitleLineKeepsARefreshOffIt(t *testing.T) {
	d := sampleData()
	d.Run.Stats.Duration = 16 * time.Second
	d.Run.Stats.Jobs = 3
	d.Run.Stats.DataRefresh = coldRefresh
	out := renderWith(t, consoleReporter{}, d)
	first, _, _ := strings.Cut(out, "\n")
	if strings.Contains(out, "refreshing") || !strings.HasSuffix(first, "16s") {
		t.Errorf("header = %q, want the duration alone and no refresh anywhere without --evidence", first)
	}
	d.Evidence = true
	if out := renderWith(t, consoleReporter{}, d); !strings.Contains(out, "5.7s refreshing scanner data") {
		t.Errorf("--evidence does not name the refresh:\n%s", out)
	}
}

// --evidence names each refresh worth mentioning, which data and how long, and leaves out the ones
// that found their data current.
func TestTheRunRowListsEachRefresh(t *testing.T) {
	st := engine.Stats{Jobs: 42, Duration: 16 * time.Second, DataRefresh: append(coldRefresh,
		engine.DataRefresh{Scanner: "grype", Data: []string{"vulnerability database"}, Took: 2 * time.Second, Failed: true})}
	want := "42 jobs in 16s · 7.7s refreshing scanner data: trivy-config checks bundle 1.388s, " +
		"trivy vulnerability database 4.34s, grype vulnerability database 2s, failed"
	if got := runLine(st); got != want {
		t.Errorf("runLine =\n %q\nwant\n %q", got, want)
	}
	if got := refreshSummary(nil); got != "" {
		t.Errorf("refreshSummary(nil) = %q", got)
	}
}
