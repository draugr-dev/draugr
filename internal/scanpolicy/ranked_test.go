package scanpolicy

import (
	"testing"

	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/pkg/dephealth"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/exploit"
	"github.com/draugr-dev/draugr/pkg/prioritization"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// stamp records a prioritizer's answer on the finding the way the engine does, so the test reads
// the finding a report and a gate read.
func stamp(res sarif.Result, p engine.Priority) sarif.Result {
	res.Priority = p.Band
	res.Escalation = p.Escalation
	res.Exploited = p.Exploited
	res.PriorityFloor = p.Floor
	res.SeverityFloor = p.SeverityFloor
	if res.Reachability != nil {
		verdict := *res.Reachability
		verdict.RankedAs = p.RankedAs
		res.Reachability = &verdict
	}
	return res
}

// RankedSeverity read back from the stamped finding is the severity the band was computed from, for
// every move the prioritizer makes and under every classification. A band is checked under every
// exposure and criticality because two severities can share one band in a single tier, and the set
// of all tiers tells all four apart.
func TestRankedSeverityIsWhatTheBandWasComputedFrom(t *testing.T) {
	kev := exploit.New(map[string]bool{"CVE-2021-44228": true}, nil, 0)
	health := dephealth.New(map[string]dephealth.Package{
		"pkg:npm/old@1.0.0": {Findings: []dephealth.Finding{{Kind: dephealth.KindDeprecated, Reason: "unmaintained"}}},
		"pkg:npm/bad@1.0.0": {Findings: []dephealth.Finding{{Kind: dephealth.KindMalicious}}},
	}, "2026-11-05")
	unreachable := func() *sarif.Reachability {
		return &sarif.Reachability{State: sarif.ReachabilityUnreachable, Method: sarif.MethodCallGraph}
	}
	scored := func(rule string, score float64) sarif.Result {
		return sarif.Result{RuleID: rule, Level: sarif.LevelWarning, Score: score, HasScore: true}
	}
	withPkg := func(res sarif.Result, purl string) sarif.Result {
		res.Package = &sarif.Package{Name: "x", Version: "1.0.0", PURL: purl}
		return res
	}
	lowered := func(res sarif.Result) sarif.Result {
		res.Reachability = unreachable()
		return res
	}

	for _, c := range []struct {
		name    string
		control string
		res     sarif.Result
		want    sarif.Severity
		floor   sarif.Severity
	}{
		{"untouched", "sca", scored("CVE-2099-0001", 7.5), sarif.SeverityHigh, ""},
		{"raised by KEV", "sca", scored("CVE-2021-44228", 7.5), sarif.SeverityCritical, ""},
		{"lowered as unreachable", "sca", lowered(scored("CVE-2099-0001", 9.8)), sarif.SeverityHigh, ""},
		{"KEV overrules unreachable", "sca", lowered(scored("CVE-2021-44228", 7.5)), sarif.SeverityCritical, ""},
		{"held at the floor", "secrets", sarif.Result{RuleID: "token", Level: sarif.LevelWarning}, sarif.SeverityHigh, sarif.SeverityHigh},
		{"above the floor", "secrets", sarif.Result{RuleID: "token", Level: sarif.LevelError, Score: 9.1, HasScore: true}, sarif.SeverityCritical, ""},
		{"raised by a deprecated package", "sca", withPkg(scored("CVE-2099-0002", 5.0), "pkg:npm/old@1.0.0"), sarif.SeverityHigh, ""},
		// A low finding the deprecation would raise is not lowered by the verdict at its own band,
		// so the raise applies and the verdict then lowers the raised value: both records are on
		// the finding and the band came from the last one.
		{"deprecated, then lowered", "sca", lowered(withPkg(scored("CVE-2099-0003", 2.0), "pkg:npm/old@1.0.0")), sarif.SeverityLow, ""},
		{"malicious overrules unreachable", "sca", lowered(withPkg(scored("CVE-2099-0004", 5.0), "pkg:npm/bad@1.0.0")), sarif.SeverityCritical, ""},
	} {
		rank := PrioritizerWith(kev, health)
		matrices := prioritization.DefaultMatrices()
		for _, exposure := range saga.Exposures {
			for _, criticality := range saga.Criticalities {
				p := rank(c.control, exposure, criticality, c.res)
				got := stamp(c.res, p)
				if c.name == "deprecated, then lowered" && (p.Escalation == nil || p.RankedAs == "") {
					t.Fatalf("%s: want both an escalation and a rankedAs on the finding, got %+v", c.name, p)
				}
				if ranked := got.RankedSeverity(); ranked != c.want {
					t.Fatalf("%s: RankedSeverity = %q, want %q (%+v)", c.name, ranked, c.want, p)
				}
				if got.SeverityFloor != c.floor {
					t.Errorf("%s: SeverityFloor = %q, want %q", c.name, got.SeverityFloor, c.floor)
				}
				tier := matrices.ContextOf(exposure, criticality)
				if floor, _ := controllers.ContextFloor(c.control); floor.Rank() > tier.Rank() {
					tier = floor
				}
				if band := matrices.PriorityOf(tier, got.RankedSeverity()); string(band) != p.Band {
					t.Errorf("%s, %s %s: band %s, but %s at %s gives %s",
						c.name, exposure, criticality, p.Band, got.RankedSeverity(), tier, band)
				}
			}
		}
	}
}
