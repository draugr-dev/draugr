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

// The header names the refresh only when it is why the run was slow, in one phrase that never
// grows. A warm run's header is the one it always had.
func TestTheHeaderNamesARefreshOnlyWhenItExplainsTheRun(t *testing.T) {
	for _, tc := range []struct {
		name string
		st   engine.Stats
		want string
	}{
		{"a cold run", engine.Stats{Duration: 16 * time.Second, DataRefresh: coldRefresh}, "5.7s refreshing scanner data"},
		{"a warm run", engine.Stats{Duration: 10 * time.Second, DataRefresh: []engine.DataRefresh{
			{Scanner: "trivy-config", Data: []string{"checks bundle"}, Took: 482 * time.Millisecond}}}, ""},
		{"under five seconds", engine.Stats{Duration: 8 * time.Second, DataRefresh: []engine.DataRefresh{
			{Scanner: "trivy", Took: 4 * time.Second}}}, ""},
		{"under a quarter of a long run", engine.Stats{Duration: 10 * time.Minute, DataRefresh: []engine.DataRefresh{
			{Scanner: "trivy", Took: 30 * time.Second}}}, ""},
		{"nothing refreshed", engine.Stats{Duration: 10 * time.Second}, ""},
	} {
		if got := refreshShare(tc.st); got != tc.want {
			t.Errorf("%s: refreshShare = %q, want %q", tc.name, got, tc.want)
		}
	}

	d := sampleData()
	d.Run.Stats.Duration = 16 * time.Second
	d.Run.Stats.DataRefresh = coldRefresh
	first, _, _ := strings.Cut(renderWith(t, consoleReporter{}, d), "\n")
	if !strings.HasSuffix(first, "16s · 5.7s refreshing scanner data") {
		t.Errorf("header = %q, want the duration and the refresh beside it", first)
	}
	d.Run.Stats.DataRefresh = nil
	first, _, _ = strings.Cut(renderWith(t, consoleReporter{}, d), "\n")
	if strings.Contains(first, "refreshing") || !strings.HasSuffix(first, "16s") {
		t.Errorf("header = %q, want the duration alone", first)
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
