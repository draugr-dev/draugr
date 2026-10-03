package dephealth_test

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/dephealth"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func source(t *testing.T, pkgs map[string]dephealth.Package) *dephealth.Source {
	t.Helper()
	return dephealth.New(pkgs, "2026-09-20")
}

// A package somebody flagged as malicious is not a ranking nudge. It is the top band, whatever the
// scanner that happened to notice it thought the flaw was worth.
func TestMaliciousGoesStraightToCritical(t *testing.T) {
	s := source(t, map[string]dephealth.Package{
		"pkg:npm/evil": {Findings: []dephealth.Finding{{Kind: dephealth.KindMalicious}}},
	})
	got, why := s.Explain(sarif.SeverityLow, "pkg:npm/evil")
	if got != sarif.SeverityCritical {
		t.Errorf("a malicious package ranked %s, not critical", got)
	}
	if why == nil || why.Signal != dephealth.SignalMalicious {
		t.Fatalf("nothing explains the escalation: %+v", why)
	}
	if why.AsOf == "" {
		t.Error("the claim carries no date, so nobody can re-check it")
	}
}

// Deprecation is a statement by the publisher and moves one band, the way EPSS does. It is not the
// top band: an abandoned package is a reason to act sooner, not evidence that this flaw is worse.
func TestDeprecatedRaisesOneBandAndQuotesThePublisher(t *testing.T) {
	s := source(t, map[string]dephealth.Package{
		"pkg:npm/jquery@1.8.3": {Findings: []dephealth.Finding{{
			Kind:   dephealth.KindDeprecated,
			Reason: "This version is deprecated. Please upgrade to the latest version.",
		}}},
	})
	got, why := s.Explain(sarif.SeverityMedium, "pkg:npm/jquery@1.8.3")
	if got != sarif.SeverityHigh {
		t.Errorf("deprecated ranked %s, wanted one band up from medium", got)
	}
	if why == nil {
		t.Fatal("no escalation recorded")
	}
	if want := "deprecated by its publisher: This version is deprecated."; len(why.Detail) < len(want) ||
		why.Detail[:len(want)] != want {
		t.Errorf("the detail does not quote the publisher: %q", why.Detail)
	}
}

// Malicious outranks deprecated where both apply: one says do not install this, the other says
// nobody is looking after it, and only the first answers what to do right now.
func TestMaliciousOutranksDeprecated(t *testing.T) {
	s := source(t, map[string]dephealth.Package{
		"pkg:npm/both": {Findings: []dephealth.Finding{
			{Kind: dephealth.KindDeprecated, Reason: "unmaintained"},
			{Kind: dephealth.KindMalicious},
		}},
	})
	_, why := s.Explain(sarif.SeverityLow, "pkg:npm/both")
	if why == nil || why.Signal != dephealth.SignalMalicious {
		t.Errorf("deprecated won over malicious: %+v", why)
	}
}

// The two kinds read and deliberately not acted on. VULNERABLE is a flaw the scanners already
// reported, so raising on it counts one problem twice; REMEDIATION means a newer version exists,
// which is true of nearly everything and would fire on a third of a healthy dependency tree.
func TestTheInformationalKindsMoveNothing(t *testing.T) {
	for _, kind := range []string{dephealth.KindVulnerable, dephealth.KindRemediation, dephealth.KindLowUsage} {
		t.Run(kind, func(t *testing.T) {
			s := source(t, map[string]dephealth.Package{
				"pkg:pypi/x": {Findings: []dephealth.Finding{{Kind: kind}}},
			})
			got, why := s.Explain(sarif.SeverityLow, "pkg:pypi/x")
			if got != sarif.SeverityLow || why != nil {
				t.Errorf("%s moved a finding to %s (%+v)", kind, got, why)
			}
		})
	}
}

// Nothing known about a package, and nothing said about it. The common case by a wide margin: one
// package in 139 carried a finding on this project's own dependency tree.
func TestAPackageWithNothingKnownIsLeftAlone(t *testing.T) {
	s := source(t, map[string]dephealth.Package{})
	got, why := s.Explain(sarif.SeverityHigh, "pkg:golang/example.com/quiet@v1.0.0")
	if got != sarif.SeverityHigh || why != nil {
		t.Errorf("an unknown package was moved to %s (%+v)", got, why)
	}
	if !s.Empty() {
		t.Error("a source holding nothing does not report itself empty")
	}
	if s.Consulted() != nil {
		t.Error("a source holding nothing claims to have consulted something")
	}
}

// Already at the top band, so nothing was raised and there is nothing to explain. An escalation
// recorded here would claim a change that did not happen, and anything counting them would be
// counting the wrong thing.
func TestNothingIsRecordedWhenThereIsNowhereToGo(t *testing.T) {
	s := source(t, map[string]dephealth.Package{
		"pkg:npm/evil": {Findings: []dephealth.Finding{{Kind: dephealth.KindMalicious}}},
	})
	got, why := s.Explain(sarif.SeverityCritical, "pkg:npm/evil")
	if got != sarif.SeverityCritical || why != nil {
		t.Errorf("critical was 'raised' to %s (%+v)", got, why)
	}
}

// A qualifier says where a package came from, not which package it is, and the upstream data is
// keyed without one. Without this a Debian-qualified purl never matches anything.
func TestAQualifierDoesNotHideAMatch(t *testing.T) {
	s := source(t, map[string]dephealth.Package{
		"pkg:npm/jquery@1.8.3": {Findings: []dephealth.Finding{{Kind: dephealth.KindDeprecated}}},
	})
	if _, why := s.Explain(sarif.SeverityLow, "pkg:npm/jquery@1.8.3?arch=amd64"); why == nil {
		t.Error("a qualified purl matched nothing")
	}
}

// A source that consulted the data and found nothing wrong is a different statement from one that
// never ran, and the evidence has to be able to tell them apart.
func TestConsultedSaysHowMuchWasChecked(t *testing.T) {
	s := source(t, map[string]dephealth.Package{
		"pkg:npm/a": {}, "pkg:npm/b": {},
	})
	got := s.Consulted()
	if len(got) != 1 {
		t.Fatalf("consulted %d datasets, wanted 1: %+v", len(got), got)
	}
	if got[0].Entries != 2 {
		t.Errorf("checked 2 packages, reported %d", got[0].Entries)
	}
	if got[0].AsOf != "2026-09-20" {
		t.Errorf("no date on the evidence: %q", got[0].AsOf)
	}
}

// A nil source is what a run with the signal switched off carries, and every method has to survive
// it: the caller is the scan path, and a panic there fails a run over an enrichment nobody asked for.
func TestANilSourceIsInert(t *testing.T) {
	var s *dephealth.Source
	if !s.Empty() {
		t.Error("nil is not empty")
	}
	if got, why := s.Explain(sarif.SeverityHigh, "pkg:npm/x"); got != sarif.SeverityHigh || why != nil {
		t.Errorf("nil source moved a finding to %s (%+v)", got, why)
	}
	if s.Enrich(sarif.SeverityLow, "pkg:npm/x") != sarif.SeverityLow {
		t.Error("nil source enriched something")
	}
	if s.Consulted() != nil || s.Purls() != nil {
		t.Error("nil source reported data")
	}
	if _, ok := s.Lookup("pkg:npm/x"); ok {
		t.Error("nil source answered a lookup")
	}
}

// Sorted, so evidence produced twice from one run is byte-identical.
func TestPurlsAreOrdered(t *testing.T) {
	s := source(t, map[string]dephealth.Package{
		"pkg:npm/c": {}, "pkg:npm/a": {}, "pkg:npm/b": {},
	})
	got := s.Purls()
	for i, want := range []string{"pkg:npm/a", "pkg:npm/b", "pkg:npm/c"} {
		if got[i] != want {
			t.Fatalf("purls out of order: %v", got)
		}
	}
}

// A publisher's reason can be a paragraph and a report row cannot.
func TestALongReasonIsCutToOneLine(t *testing.T) {
	long := ""
	for range 40 {
		long += "words and more words "
	}
	s := source(t, map[string]dephealth.Package{
		"pkg:npm/x": {Findings: []dephealth.Finding{{Kind: dephealth.KindDeprecated, Reason: long}}},
	})
	_, why := s.Explain(sarif.SeverityLow, "pkg:npm/x")
	if why == nil {
		t.Fatal("no escalation")
	}
	if len(why.Detail) > 160 {
		t.Errorf("the detail runs to %d characters: %q", len(why.Detail), why.Detail)
	}
}

// Deprecated with nothing said about why still has to read as a sentence.
func TestDeprecatedWithNoReasonStillExplainsItself(t *testing.T) {
	s := source(t, map[string]dephealth.Package{
		"pkg:npm/x": {Findings: []dephealth.Finding{{Kind: dephealth.KindDeprecated}}},
	})
	_, why := s.Explain(sarif.SeverityLow, "pkg:npm/x")
	if why == nil || why.Detail != "deprecated by its publisher" {
		t.Errorf("unhelpful detail: %+v", why)
	}
}

// The prioritizer is handed a source before a scan and the packages are only known after one, so
// this pointer is filled in between. A source that could not be filled has to stay inert rather
// than half-answer.
func TestLoadFillsASourceHandedOutEmpty(t *testing.T) {
	s := dephealth.New(nil, "")
	if !s.Empty() {
		t.Fatal("a source with nothing in it is not empty")
	}
	if _, why := s.Explain(sarif.SeverityLow, "pkg:npm/evil"); why != nil {
		t.Error("an unfilled source moved a finding")
	}

	s.Load(map[string]dephealth.Package{
		"pkg:npm/evil": {Findings: []dephealth.Finding{{Kind: dephealth.KindMalicious}}},
	}, "2026-09-20")

	if s.Empty() {
		t.Error("a filled source still reports itself empty")
	}
	got, why := s.Explain(sarif.SeverityLow, "pkg:npm/evil")
	if got != sarif.SeverityCritical || why == nil {
		t.Errorf("a filled source did not rank: %s %+v", got, why)
	}
	if why.AsOf != "2026-09-20" {
		t.Errorf("the date handed to Load was lost: %q", why.AsOf)
	}
}

// A nil source is what a run with the signal off carries into the same call.
func TestLoadOnNilIsHarmless(t *testing.T) {
	var s *dephealth.Source
	s.Load(map[string]dephealth.Package{"pkg:npm/x": {}}, "2026-09-20")
	if !s.Empty() {
		t.Error("loading nil produced something")
	}
}
