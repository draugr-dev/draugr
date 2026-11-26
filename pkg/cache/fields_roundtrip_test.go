package cache

import (
	"slices"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/internal/fieldprobe"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// notCached are the fields of a scanner's Result the disk cache deliberately does not keep, each
// with the reason. A field kept out of a result's JSON, as `json:"-"` keeps HasScore and Uses, is
// lost on a cache hit unless the entry saves it beside the report, so a field the cache loses and
// this list does not name fails TestEveryResultFieldSurvivesTheCache.
var notCached = map[string]string{
	"Correlation.AlsoFoundBy[0].Location": "correlation runs over the run's merged findings after every cache read, so a scanner's cached report never carries one",
	"ImportedTool":                        "set only on alerts read from a service, which the engine reads again on every run and never caches",
}

// A cache hit has to give the run what the scan gave it: a field the cache drops makes a cached run
// rank, correlate or name a finding differently from the same run uncached.
func TestEveryResultFieldSurvivesTheCache(t *testing.T) {
	var want sarif.Result
	fieldprobe.Fill(&want, map[string]any{"Level": sarif.LevelError})
	c := NewLocal(t.TempDir(), time.Hour)
	if err := c.Put("k", sarif.Report{Results: []sarif.Result{want}}); err != nil {
		t.Fatal(err)
	}
	back, ok := c.Get("k")
	if !ok || len(back.Results) != 1 {
		t.Fatalf("cache hit = %v with %d results, want a hit with 1", ok, len(back.Results))
	}
	lost := fieldprobe.Lost(want, back.Results[0])
	for _, field := range lost {
		if _, listed := notCached[field]; !listed {
			t.Errorf("%s did not survive the cache: save it beside the entry, or list it in notCached with the reason", field)
		}
	}
	for field := range notCached {
		if !slices.Contains(lost, field) {
			t.Errorf("%s now survives the cache: take it off notCached", field)
		}
	}
}
