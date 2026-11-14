package report

import (
	"cmp"
	"fmt"
	"sort"
	"strings"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// unsettledEvidenceFlag is where the console lists the checks a scanner did not decide, said beside
// their count in a view that does not list them.
const unsettledEvidenceFlag = "--evidence lists them"

// The kinds of check a scanner did not decide, as the coverage line and the evidence word them. A
// denial and a precondition are read off the unread checks, which the caveats also name; the rest are
// the unsettled checks.
const (
	kindDenied      = "denied"
	kindPartly      = "partly read"
	kindManual      = sarif.UnsettledManual
	kindNoResources = sarif.UnsettledNoResources
	kindExcluded    = "excluded"
)

// undecidedKinds are the kinds the coverage line counts, in the order it says them, each beside
// what it says of a count. A denial, a precondition and a check read in part are not among them:
// the caveats name each, with what clears it, and the line counts what no caveat says.
var undecidedKinds = []struct {
	kind  string
	words func(n int) string
}{
	{kindManual, func(n int) string { return fmt.Sprintf("%d left for a person", n) }},
	{kindNoResources, func(n int) string { return fmt.Sprintf("%d with nothing to check", n) }},
	{kindExcluded, func(n int) string { return fmt.Sprintf("%d excluded", n) }},
}

// undecided is one check a scanner did not decide, of either list, as the evidence names it.
type undecided struct {
	component, location, id, kind, said string
}

// undecidedOf is every check one scanner did not decide about one component, where the provenance
// names one, of the kinds the console counts.
func undecidedOf(d Data, control string, p sarif.Provenance) []undecided {
	rep := d.Run.Controls[control].Report
	var out []undecided
	for _, u := range rep.UnsettledChecks {
		if u.Scanner != p.Tool || (p.Component != "" && u.Component != p.Component) {
			continue
		}
		out = append(out, unsettledEntry(u))
	}
	for _, u := range rep.Unchecked {
		if u.Scanner != p.Tool || (p.Component != "" && u.Component != p.Component) {
			continue
		}
		out = append(out, uncheckedEntry(u, ""))
	}
	return counted(out)
}

// counted keeps the kinds undecidedKinds names.
func counted(us []undecided) []undecided {
	keep := map[string]bool{}
	for _, k := range undecidedKinds {
		keep[k.kind] = true
	}
	out := us[:0]
	for _, u := range us {
		if keep[u.kind] {
			out = append(out, u)
		}
	}
	return out
}

func unsettledEntry(u sarif.UnsettledCheck) undecided {
	e := undecided{component: u.Component, location: u.Location, id: u.RuleID, kind: u.Kind, said: u.Title}
	if u.Suppression != nil {
		e.kind, e.said = kindExcluded, u.Suppression.Justification
	}
	return e
}

func uncheckedEntry(u sarif.Unchecked, location string) undecided {
	kind := u.Kind
	switch {
	case u.PartlyRead:
		kind = kindPartly
	case kind == "":
		kind = kindDenied
	}
	// As config.exclude takes it: a bare check name is the scanner's, as its unsettled ones are named.
	id := u.Check
	if !strings.Contains(id, "/") {
		id = u.Scanner + "/" + id
	}
	return undecided{component: u.Component, location: location, id: id, kind: kind, said: u.Reason}
}

// countWords is the counts of us by kind, in undecidedKinds' order, worded.
func countWords(us []undecided) []string {
	by := map[string]int{}
	for _, u := range us {
		by[u.kind]++
	}
	var parts []string
	for _, k := range undecidedKinds {
		if n := by[k.kind]; n > 0 {
			parts = append(parts, k.words(n))
		}
	}
	return parts
}

// withUnsettled is p's fields with the counts of the checks it did not decide beside its coverage,
// which counts only what it decided. A scanner stating no coverage gets the counts as a field of
// their own, so a run where it is the only one still says the checks are there. Every format shows
// these lines; where the checks are listed is the console's to say, beside them (see measuredText).
func withUnsettled(d Data, control string, p sarif.Provenance, fields []sarif.Field) []sarif.Field {
	note := unsettledNote(d, control, p)
	if note == "" {
		return fields
	}
	out := make([]sarif.Field, len(fields))
	copy(out, fields)
	for i := range out {
		if out[i].Key == "coverage" {
			out[i].Value += ", " + note
			return out
		}
	}
	return append(out, sarif.Field{Value: note})
}

// unsettledNote counts the checks a scanner did not decide, by kind, or is empty where it decided
// every one.
func unsettledNote(d Data, control string, p sarif.Provenance) string {
	var asks []undecided
	for _, u := range undecidedOf(d, control, p) {
		// A check with nothing to check asks nothing of anybody: --evidence lists it, and the
		// coverage line beside the verdict counts only what somebody does or decided.
		if u.kind != kindNoResources {
			asks = append(asks, u)
		}
	}
	return strings.Join(countWords(asks), ", ")
}

// undecidedChecks is every check the run did not decide, of the kinds the console counts, by
// component and location. An unread check carries no location, and takes the one the same
// component's unsettled checks name.
func undecidedChecks(d Data) []undecided {
	var out []undecided
	for _, name := range sortedControlNames(d) {
		rep := d.Run.Controls[name].Report
		where := map[string]string{}
		for _, u := range rep.UnsettledChecks {
			where[u.Scanner+"\x00"+u.Component] = u.Location
			out = append(out, unsettledEntry(u))
		}
		for _, u := range rep.Unchecked {
			if !undecidedScanner(rep, u.Scanner) {
				continue
			}
			loc := where[u.Scanner+"\x00"+u.Component]
			if loc == "" {
				loc = u.Component
			}
			out = append(out, uncheckedEntry(u, loc))
		}
	}
	out = counted(out)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].component != out[j].component {
			return out[i].component < out[j].component
		}
		return out[i].location < out[j].location
	})
	return out
}

// undecidedScanner reports whether a scanner states coverage as checks decided, which is where its
// unread checks belong beside the unsettled ones. A scanner reading files, such as headers, says
// what it did not read in the caveats alone.
func undecidedScanner(rep sarif.Report, scanner string) bool {
	for _, p := range rep.Provenance {
		if p.Tool != scanner {
			continue
		}
		for _, f := range p.Fields {
			if f.Key == "coverage" && strings.Contains(f.Value, "checks decided") {
				return true
			}
		}
	}
	return false
}

// kindWords are what a row of the evidence calls each kind: the words the count above the rows uses
// for it, so the head's "5 left for a person" and the rows under it read in one vocabulary rather
// than the head in words and the rows in report.json's kind names.
var kindWords = map[string]string{
	sarif.UncheckedDenied:       "denied",
	sarif.UncheckedPrecondition: "precondition",
	kindPartly:                  "partly read",
	sarif.UnsettledManual:       "left for a person",
	sarif.UnsettledNoResources:  "nothing to check",
	kindExcluded:                "excluded",
}

// rowWords are a row's kind and what follows it. A denial's reason opens with the word its kind
// is, "denied list rolebindings", so the reason goes on without it rather than say it twice.
func rowWords(u undecided) (kind, said string) {
	kind = cmp.Or(kindWords[u.kind], u.kind)
	said = u.said
	if u.kind == sarif.UncheckedDenied {
		said = strings.TrimPrefix(said, sarif.UncheckedDenied+" ")
	}
	return kind, said
}

// unsettledRows are the EVIDENCE block's rows for the checks the run did not decide: a row per target
// counting them by kind, then a row per check, its id as config.exclude takes it, its kind, and its
// title or why.
func unsettledRows(d Data) (heads []string, checks [][]string) {
	all := undecidedChecks(d)
	idWidth, kindWidth := 0, 0
	for _, u := range all {
		kind, _ := rowWords(u)
		idWidth = max(idWidth, len([]rune(u.id)))
		kindWidth = max(kindWidth, len(kind))
	}
	for i := 0; i < len(all); {
		first := all[i]
		var group []undecided
		for ; i < len(all) && all[i].component == first.component && all[i].location == first.location; i++ {
			group = append(group, all[i])
		}
		// Kind by kind, in the order the head counts them.
		sort.SliceStable(group, func(a, b int) bool { return undecidedRank(group[a].kind) < undecidedRank(group[b].kind) })
		var rows []string
		for _, u := range group {
			kind, said := rowWords(u)
			rows = append(rows, strings.TrimRight(fmt.Sprintf("%-*s  %-*s  %s", idWidth, u.id, kindWidth, kind, said), " "))
		}
		heads = append(heads, first.location+" · "+strings.Join(countWords(group), ", "))
		checks = append(checks, rows)
	}
	return heads, checks
}

// undecidedRank is a kind's place in undecidedKinds.
func undecidedRank(kind string) int {
	for i, k := range undecidedKinds {
		if k.kind == kind {
			return i
		}
	}
	return len(undecidedKinds)
}
