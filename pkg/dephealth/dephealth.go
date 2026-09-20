// Package dephealth ranks a finding by what is known about the dependency it is in, rather than
// only by what is known about the flaw.
//
// A CVE in a package whose publisher has walked away is a different problem from the same CVE in
// one that ships a fix next week, and no scanner reports the difference because it is not in the
// code. This is the third enrichment beside exploitability and reachability, and it reads the same
// kind of fact: something true about the world that the repository cannot tell you.
//
// # What moves a band, and what does not
//
// Only statements, never scores. A package flagged by the OSSF Malicious Packages Project and a
// version its own publisher has deprecated are both assertions by somebody who can be named. A
// health score is a heuristic, and the evidence against ranking on one is strong enough to be worth
// stating: Zahan et al. found reported vulnerability counts *rose* with OpenSSF Scorecard's
// aggregate score, with an R² of 9% to 12%, and Scorecard's own `Maintained` check scores PyYAML
// zero because it reads a 90-day activity window and PyYAML is stable rather than abandoned.
// Ranking a CVE up because a maintainer commits rarely would be wrong, and wrong in a way the
// people who depend on that package would notice first.
//
// So: MALICIOUS and DEPRECATED move a finding. Everything else is carried as context on a finding
// already ranked by something else.
//
// # Why a recommended version is not always an upgrade
//
// The upstream data offers a version to move to, and it is not always ahead of the one in use.
// `github.com/golang/protobuf@v1.5.4` is deprecated in favor of a *different module*, and the
// recommendation offered against it is v1.5.1, which is older. Rendering that as the fix would tell
// somebody to downgrade for no reason, so a recommendation is carried only when it can be shown to
// be strictly newer, and the publisher's own reason is the part that always travels.
package dephealth

import (
	"sort"
	"strconv"
	"strings"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// The signals a Source can raise on, as they appear in an Escalation.
const (
	// SignalMalicious is a package the OSSF Malicious Packages Project has flagged. It applies to
	// every version of the package rather than to one of them.
	SignalMalicious = "malicious"
	// SignalDeprecated is a version its own publisher has marked as no longer supported.
	SignalDeprecated = "deprecated"
)

// Finding types, as the upstream data names them.
const (
	KindMalicious  = "MALICIOUS"
	KindDeprecated = "DEPRECATED"
	KindLowUsage   = "LOW_USAGE"
	// KindVulnerable and KindRemediation are read and deliberately not acted on. The first is a
	// vulnerability the scanners already reported, so counting it again would double what the
	// report says was found. The second means a newer version exists, which is true of nearly
	// every dependency and moves nothing.
	KindVulnerable  = "VULNERABLE"
	KindRemediation = "REMEDIATION"
)

// Finding is one statement about a package version.
type Finding struct {
	// Kind is the finding type, e.g. "DEPRECATED".
	Kind string
	// Reason is what the publisher said, where they said anything. Only DEPRECATED carries one.
	Reason string
}

// Package is what is known about one package version.
type Package struct {
	Findings []Finding
	// Recommended is a version to move to, and is set only when it is strictly newer than the one
	// asked about. See the package comment for why that check is not optional.
	Recommended string
}

// Source answers what is known about the packages a scan found.
//
// Keyed on package identity rather than on a rule id, which is the difference from exploitability:
// the subject is the dependency, and the finding is only how the problem came to somebody's
// attention.
type Source struct {
	byPurl map[string]Package
	asOf   string
}

// New returns a Source over what was looked up, with the day it was obtained.
//
// asOf is not decoration. "This package is deprecated" is a claim that can change, and a verdict
// nobody can date is a verdict nobody can re-check.
func New(byPurl map[string]Package, asOf string) *Source {
	return &Source{byPurl: byPurl, asOf: asOf}
}

// Load fills in a source that was handed out before the answers were known.
//
// The prioritizer is built before a scan and the packages are only known after it, so this is a
// pointer somebody already holds being given its contents once, between aggregation and ranking. It
// is not a cache and must not be called twice: a second call would change how findings rank halfway
// through a run.
func (s *Source) Load(byPurl map[string]Package, asOf string) {
	if s == nil {
		return
	}
	s.byPurl, s.asOf = byPurl, asOf
}

// Empty reports whether this source can say anything at all.
func (s *Source) Empty() bool { return s == nil || len(s.byPurl) == 0 }

// Consulted names what this source answered from, for the evidence block.
//
// Recorded even when nothing was raised, because silence otherwise covers two unrelated cases: the
// packages were checked and are fine, and nobody checked. Only the first is reassuring.
func (s *Source) Consulted() []sarif.Consulted {
	if s.Empty() {
		return nil
	}
	return []sarif.Consulted{{
		Signal: "dependency-health", AsOf: s.asOf, Entries: len(s.byPurl),
	}}
}

// Lookup returns what is known about a package, and whether anything is.
func (s *Source) Lookup(purl string) (Package, bool) {
	if s == nil {
		return Package{}, false
	}
	p, ok := s.byPurl[normalize(purl)]
	return p, ok
}

// Explain raises base where the dependency itself is the problem, and says why.
//
// Malicious outranks deprecated: one is a package that should not be installed at all, the other is
// one nobody is maintaining, and where both are true the first is what somebody needs to read.
func (s *Source) Explain(base sarif.Severity, purl string) (sarif.Severity, *sarif.Escalation) {
	pkg, ok := s.Lookup(purl)
	if !ok {
		return base, nil
	}
	kinds := map[string]Finding{}
	for _, f := range pkg.Findings {
		kinds[f.Kind] = f
	}

	if _, bad := kinds[KindMalicious]; bad {
		if base == sarif.SeverityCritical {
			return base, nil
		}
		return sarif.SeverityCritical, &sarif.Escalation{
			From: base, To: sarif.SeverityCritical,
			Signal: SignalMalicious, AsOf: s.asOf,
			Detail: "the package is flagged as malicious",
		}
	}

	if f, dep := kinds[KindDeprecated]; dep {
		raised := base.Escalate()
		if raised == base {
			return base, nil
		}
		return raised, &sarif.Escalation{
			From: base, To: raised,
			Signal: SignalDeprecated, AsOf: s.asOf,
			Detail: deprecatedDetail(f.Reason),
		}
	}
	return base, nil
}

// Enrich is Explain without the reason, for a caller that only wants the severity.
func (s *Source) Enrich(base sarif.Severity, purl string) sarif.Severity {
	out, _ := s.Explain(base, purl)
	return out
}

// deprecatedDetail is the sentence a reader meets beside a band.
//
// The publisher's own words where there are any, because "deprecated" is a status and "use the
// google.golang.org/protobuf module instead" is an instruction. Trimmed to one line: some reasons
// are a paragraph, and a report is not where a paragraph belongs.
func deprecatedDetail(reason string) string {
	reason = strings.Join(strings.Fields(reason), " ")
	if reason == "" {
		return "deprecated by its publisher"
	}
	const most = 120
	if len(reason) > most {
		reason = strings.TrimSpace(reason[:most]) + "…"
	}
	return "deprecated by its publisher: " + reason
}

// normalize makes two spellings of one package match.
//
// Qualifiers and subpaths are dropped because they describe where a package came from rather than
// which package it is, and the upstream data is keyed without them.
func normalize(purl string) string {
	if i := strings.IndexAny(purl, "?#"); i >= 0 {
		purl = purl[:i]
	}
	return strings.TrimSpace(purl)
}

// Newer reports whether candidate is a later version than current, and whether that could be
// decided at all.
//
// Deliberately narrow. It compares dotted numeric segments, with an optional leading "v" and any
// pre-release suffix ignored, which covers the ecosystems this data indexes. Anything it cannot
// read confidently returns ok=false, and a caller that cannot tell must say nothing rather than
// guess: the cost of a wrong "upgrade to" is somebody downgrading a working dependency.
func Newer(current, candidate string) (newer, ok bool) {
	a, aok := numeric(current)
	b, bok := numeric(candidate)
	if !aok || !bok {
		return false, false
	}
	for i := 0; i < len(a) || i < len(b); i++ {
		x, y := 0, 0
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			return y > x, true
		}
	}
	return false, true // identical
}

// numeric splits a version into its leading run of dotted integers.
func numeric(v string) ([]int, bool) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	// A pre-release or build suffix ends the part that can be compared as numbers.
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	if v == "" {
		return nil, false
	}
	var out []int
	for _, part := range strings.Split(v, ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

// Purls returns the package identities this source holds, sorted, so two runs over the same inputs
// produce the same evidence.
func (s *Source) Purls() []string {
	if s == nil {
		return nil
	}
	out := make([]string, 0, len(s.byPurl))
	for p := range s.byPurl {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
