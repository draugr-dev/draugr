package scanpolicy

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A mutable-tag finding on a reference actions.lock pins is held at P3 with the reason recorded,
// the same finding unpinned keeps its band, and a pinned finding already at or below P3 records no
// cap.
func TestAPinnedActionIsHeldAtP3(t *testing.T) {
	p := DefaultPrioritizer(nil)
	tag := sarif.Result{RuleID: "yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag",
		Level: sarif.LevelError}
	pinned := tag
	pinned.Aside = sarif.AsidePinned

	open := p("sast", saga.ExposurePublic, saga.CriticalityCritical, tag)
	held := p("sast", saga.ExposurePublic, saga.CriticalityCritical, pinned)
	if open.Band != "P1" || open.Cap != "" {
		t.Fatalf("unpinned: band %s, cap %q; want P1 and no cap", open.Band, open.Cap)
	}
	if held.Band != "P3" || held.Cap != PinnedCap {
		t.Errorf("pinned: band %s, cap %q; want P3 and %q", held.Band, held.Cap, PinnedCap)
	}

	low := pinned
	low.Level = sarif.LevelNote
	if got := p("sast", saga.ExposureInternal, saga.CriticalitySupporting, low); got.Cap != "" {
		t.Errorf("a pinned finding already below P3 records a cap: band %s, cap %q", got.Band, got.Cap)
	}
}
