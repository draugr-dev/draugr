package report

import "testing"

func TestEveryViewSaysWhatItShows(t *testing.T) {
	views := Views()
	if len(views) == 0 || views[0] != ViewFindings {
		t.Fatalf("Views() = %v, want the default, %q, first", views, ViewFindings)
	}
	seen := map[View]bool{}
	for _, v := range views {
		if seen[v] {
			t.Errorf("%q is listed twice", v)
		}
		seen[v] = true
		if v.Summary() == "" {
			t.Errorf("%q has no summary, so the config schema offers it with nothing beside it", v)
		}
	}
	if got := View("grouped").Summary(); got != "" {
		t.Errorf("a name that is not a view has summary %q", got)
	}
}
