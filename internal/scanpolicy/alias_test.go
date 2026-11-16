package scanpolicy

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/exploit"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A finding named by its advisory is raised by the CVE it lists as an alias, and the record names
// that CVE, since the row does not. A finding whose rule id names the CVE is recorded as before.
func TestAnAliasCVEIsRaisedAndNamed(t *testing.T) {
	const cve = "CVE-2020-35669"
	rank := func(src *exploit.Source, res sarif.Result) (*sarif.Escalation, *sarif.Match) {
		got := DefaultPrioritizer(src)("sca", saga.ExposurePublic, saga.CriticalityCritical, res)
		return got.Escalation, got.Exploited
	}
	advisory := sarif.Result{RuleID: "GHSA-4rgh-jx4f-qfcq-http", Aliases: []string{"GHSA-4rgh-jx4f-qfcq", cve},
		Level: sarif.LevelWarning, Score: 6.1, HasScore: true}
	kev := exploit.New(map[string]bool{cve: true}, nil, 0.5)

	esc, listed := rank(kev, advisory)
	if esc == nil || esc.Signal != exploit.SignalKEV || esc.CVE != cve {
		t.Errorf("escalation = %+v, want raised on KEV naming %s", esc, cve)
	}
	if listed == nil || listed.CVE != cve {
		t.Errorf("listing = %+v, want one naming %s", listed, cve)
	}

	esc, _ = rank(exploit.New(nil, map[string]float64{cve: 0.9}, 0.5), advisory)
	if esc == nil || esc.Signal != exploit.SignalEPSS || esc.CVE != cve {
		t.Errorf("escalation = %+v, want raised on EPSS naming %s", esc, cve)
	}

	// Already critical: KEV raises nothing, and the listing still names the CVE it matched.
	critical := advisory
	critical.Level, critical.Score = sarif.LevelError, 9.8
	if esc, listed := rank(kev, critical); esc != nil || listed == nil || listed.CVE != cve {
		t.Errorf("escalation = %+v, listing = %+v, want a listing naming %s and no raise", esc, listed, cve)
	}

	// The rule id names the CVE, so the record does not repeat it.
	named := advisory
	named.RuleID = cve + "-http"
	if esc, listed := rank(kev, named); esc == nil || esc.CVE != "" || listed == nil || listed.CVE != "" {
		t.Errorf("escalation = %+v, listing = %+v, want both raised without naming the CVE again", esc, listed)
	}
}
