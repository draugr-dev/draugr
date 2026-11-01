package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/skald"
)

// bandedSARIF writes a report of two components in two repositories, one finding in each band, kept
// at or above band as a narrowed artifact keeps them, and stamped with that band. "" writes it whole.
func bandedSARIF(t *testing.T, name, band string) string {
	t.Helper()
	var results []sarif.Result
	for _, c := range []struct{ component, repo string }{{"api", "repo-api"}, {"web", "repo-web"}} {
		for _, p := range []string{"P1", "P2", "P3", "P4"} {
			if band != "" && rankOf(p) < rankOf(band) {
				continue
			}
			results = append(results, sarif.Result{
				Tool: "trivy", RuleID: "CVE-2026-000" + p[1:], Level: sarif.LevelError, Message: "x",
				Component: c.component, Repository: c.repo, Priority: p,
				Location: sarif.Location{URI: "go.mod"},
			})
		}
	}
	rep := sarif.Report{Tool: "draugr", Results: results}
	if prov, ok := skald.MinPriorityProvenance(band); ok {
		rep.Provenance = append(rep.Provenance, prov)
	}
	data, err := rep.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A base narrowed to P2 holds no P3 or P4 finding, so compared with a whole head each of those reads
// as new and a gate on them fails a change that introduced nothing. The diff refuses, naming both
// reports' bands and the two ways out.
func TestDiffRefusesABaseNarrowedAboveWhatItJudges(t *testing.T) {
	base, head := bandedSARIF(t, "base.sarif", "P2"), bandedSARIF(t, "head.sarif", "")
	err := runDiff(t.Context(), base, head, diffOptions{format: "console", failOnNew: "P3"}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("a base narrowed to P2 compared with a whole head must be refused")
	}
	for _, want := range []string{"not narrowed to the same band", "was narrowed to P2", "holds every band",
		"every P3 or P4 finding in the head would be reported as new", "--min-priority P2"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error should contain %q: %v", want, err)
		}
	}
}

// A comparison narrowed to the base's band, or above it, judges only what the base holds.
func TestDiffComparesANarrowedBaseWithinMinPriority(t *testing.T) {
	base, head := bandedSARIF(t, "base.sarif", "P2"), bandedSARIF(t, "head.sarif", "")
	for _, band := range []string{"P2", "P1"} {
		var out bytes.Buffer
		if err := runDiff(t.Context(), base, head, diffOptions{format: "console", minPriority: band}, &out); err != nil {
			t.Errorf("--min-priority %s against a base narrowed to P2: %v", band, err)
		}
	}
}

// Two reports narrowed to the same band compare as two whole ones do.
func TestDiffComparesTwoReportsNarrowedAlike(t *testing.T) {
	base, head := bandedSARIF(t, "base.sarif", "P2"), bandedSARIF(t, "head.sarif", "P2")
	if err := runDiff(t.Context(), base, head, diffOptions{format: "console"}, &bytes.Buffer{}); err != nil {
		t.Errorf("two reports narrowed to P2 are comparable: %v", err)
	}
}

// A head narrowed above the base leaves out findings the base holds, and each would read as fixed.
func TestDiffRefusesAHeadNarrowedAboveTheBase(t *testing.T) {
	for _, baseBand := range []string{"", "P3"} {
		base, head := bandedSARIF(t, "base.sarif", baseBand), bandedSARIF(t, "head.sarif", "P2")
		err := runDiff(t.Context(), base, head, diffOptions{format: "console"}, &bytes.Buffer{})
		if err == nil {
			t.Fatalf("a head narrowed to P2 against a base narrowed to %q must be refused", baseBand)
		}
		for _, want := range []string{"head.sarif was narrowed to P2", "every P3 or P4 finding in the base would be reported as fixed", "Narrow the base to P2 too"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("base %q: the error should contain %q: %v", baseBand, want, err)
			}
		}
	}
}

// Narrowed to P4, a report holds every banded finding and keeps the unbanded ones, which is what a
// whole report holds, so it compares with one either way round.
func TestAReportNarrowedToP4ComparesAsAWholeOne(t *testing.T) {
	whole, p4 := bandedSARIF(t, "whole.sarif", ""), bandedSARIF(t, "p4.sarif", "P4")
	for _, pair := range [][2]string{{p4, whole}, {whole, p4}} {
		if err := runDiff(t.Context(), pair[0], pair[1], diffOptions{format: "console"}, &bytes.Buffer{}); err != nil {
			t.Errorf("%s against %s: %v", filepath.Base(pair[0]), filepath.Base(pair[1]), err)
		}
	}
}

// A scan holds every band, so a narrowed base is refused before anything is scanned, and the
// message offers no --min-priority, which a scan's comparison does not take.
func TestScanRefusesANarrowedBaseBeforeScanning(t *testing.T) {
	base := bandedSARIF(t, "base.sarif", "P2")
	_, err := newBaseGate(scanOptions{base: base, failOnNew: "P3"}, nil, engine.Scope{})
	if err == nil {
		t.Fatal("a scan given a base narrowed to P2 must be refused")
	}
	for _, want := range []string{"was narrowed to P2", "this scan holds every band",
		"every P3 or P4 finding in the head would be reported as new", "Write the base without narrowing it"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error should contain %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "--min-priority") {
		t.Errorf("a scan was offered --min-priority, which does not narrow its comparison: %v", err)
	}
}

func TestBandsBelow(t *testing.T) {
	for band, want := range map[string]string{"P1": "P2, P3 or P4", "P2": "P3 or P4", "P3": "P4"} {
		if got := bandsBelow(band); got != want {
			t.Errorf("bandsBelow(%s) = %q, want %q", band, got, want)
		}
	}
}
