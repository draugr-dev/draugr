package engine

import "testing"

// TestTrulyUnscannedIgnoresTargetsAnotherScannerRead is the mirror of the bug this data exists to
// prevent, pointed the other way.
//
// Two scanners can serve one control and both plan a job for the same image. If one fails and the
// other succeeds, the image *was* examined — calling it unscanned is a claim about coverage that
// nothing established, and it would push a component to ERROR over a gap that does not exist.
func TestTrulyUnscannedIgnoresTargetsAnotherScannerRead(t *testing.T) {
	failed := []Unscanned{
		{Control: "images", Scanner: "grype", Kind: "image", Target: "r/a:1"},
		{Control: "images", Scanner: "grype", Kind: "image", Target: "r/b:1"},
	}
	// Trivy read the first one.
	examined := map[string]bool{"image\x00r/a:1": true}

	got := trulyUnscanned(failed, examined)
	if len(got) != 1 {
		t.Fatalf("want only the target nothing read, got %d: %+v", len(got), got)
	}
	if got[0].Target != "r/b:1" {
		t.Errorf("kept the wrong one: %+v", got[0])
	}
}

// TestTrulyUnscannedCountsATargetOnce: where every scanner fails on one target, it went
// unexamined once, not once per scanner — and a count of jobs would say "2/1 images not scanned".
func TestTrulyUnscannedCountsATargetOnce(t *testing.T) {
	failed := []Unscanned{
		{Control: "images", Scanner: "trivy", Kind: "image", Target: "r/a:1"},
		{Control: "images", Scanner: "grype", Kind: "image", Target: "r/a:1"},
	}
	if got := trulyUnscanned(failed, nil); len(got) != 1 {
		t.Errorf("one target failed twice should be one gap, got %d", len(got))
	}
}
