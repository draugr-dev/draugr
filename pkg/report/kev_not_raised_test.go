package report

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/exploit"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A finding on KEV that the catalog did not raise, being critical already, carries `KEV listed`,
// which reads apart from the `↑ KEV` of one it raised without leaning on color. It is no movement,
// so the Movement filter does not offer it, and a finding with no catalog listing carries neither.
func TestAFindingOnKEVSaysSoRaisedOrNot(t *testing.T) {
	onKEV := &sarif.Match{Signal: exploit.SignalKEV, Detail: "on KEV", AsOf: "2026-11-10"}
	listed := finding{priority: "P1", severity: sarif.SeverityCritical, exploited: onKEV}
	raised := finding{priority: "P1", severity: sarif.SeverityHigh, exploited: onKEV,
		escalation: &sarif.Escalation{From: sarif.SeverityHigh, To: sarif.SeverityCritical, Signal: exploit.SignalKEV, Detail: "on KEV"}}
	plain := finding{priority: "P1", severity: sarif.SeverityCritical}

	if m := movedBy(listed); m == nil || m.label != "KEV listed" || m.glyph != "" {
		t.Errorf("a finding on KEV it did not raise is marked %+v, want KEV listed", m)
	}
	if m := movedBy(raised); m == nil || m.glyph+" "+m.label != "↑ KEV" {
		t.Errorf("a finding KEV raised is marked %+v, want ↑ KEV", m)
	}
	if m := movedBy(plain); m != nil {
		t.Errorf("a finding on no catalog is marked %+v", m)
	}
	if got := movements(listed); len(got) != 1 || got[0] != moveUntouched {
		t.Errorf("movements = %v, want untouched: a listing moved no band", got)
	}
}

// Within a band, a finding on KEV comes before one EPSS scored, and that one before neither, as the
// fix list ranks its actions, whatever their severities say otherwise.
func TestTheFindingsListRanksExploitationWithinABand(t *testing.T) {
	kev := finding{priority: "P1", severity: sarif.SeverityCritical, score: 9.0, location: "kev",
		exploited: &sarif.Match{Signal: exploit.SignalKEV}}
	epss := finding{priority: "P1", severity: sarif.SeverityHigh, score: 7.5, location: "epss",
		escalation: &sarif.Escalation{From: sarif.SeverityHigh, To: sarif.SeverityCritical, Signal: exploit.SignalEPSS, Detail: "EPSS 0.9"}}
	none := finding{priority: "P1", severity: sarif.SeverityCritical, score: 9.8, location: "none"}
	p2 := finding{priority: "P2", severity: sarif.SeverityCritical, score: 9.9, location: "p2",
		exploited: &sarif.Match{Signal: exploit.SignalKEV}}
	fs := []finding{p2, none, epss, kev}
	sortFindings(fs)
	var got []string
	for _, f := range fs {
		got = append(got, f.location)
	}
	want := []string{"kev", "epss", "none", "p2"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}
