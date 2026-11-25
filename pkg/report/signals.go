package report

import (
	"fmt"
	"html/template"
	"sort"
	"strconv"
	"strings"

	"github.com/draugr-dev/draugr/internal/english"
	"github.com/draugr-dev/draugr/pkg/dephealth"
	"github.com/draugr-dev/draugr/pkg/exploit"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// signalRow is one row of the Signals section: something that argued with this run's ranking, how
// it moves a finding, and what it did in this run.
type signalRow struct {
	// Name is the signal as every report names it: KEV, EPSS, malicious, deprecated, floor,
	// reachability.
	Name string
	// Moves is how the signal moves a finding.
	Moves signalMove
	// Did is what the signal did in this run, as the console prints it.
	Did string
	// Links are the counts in Did that name findings in the list, each with the narrowing that
	// shows them. The HTML report makes each one a link to the findings it counts.
	Links []signalLink
	// Unread is a dataset the run did not read and could have, the one kind of row the compact view
	// keeps: it says the bands are less than they could be, which a dense view never drops.
	Unread bool
}

// signalLink is one count in a row's Did: the words as Did holds them, the key a finding carries in
// its data-sig when the count includes it (see signalKeys), and the title of the narrowing it opens.
type signalLink struct {
	Text, Key, Title string
}

// didLine is one line a signal contributes to the section, and the counts in it that name findings.
type didLine struct {
	text   string
	links  []signalLink
	unread bool
}

// plainDid is a line with no count to follow.
func plainDid(text string) didLine { return didLine{text: text} }

// DidHTML is Did with each of its links drawn as a link into the findings list. A link whose words
// are not in Did is left out rather than drawn somewhere else.
func (r signalRow) DidHTML() template.HTML {
	var b strings.Builder
	rest := r.Did
	for _, l := range r.Links {
		i := strings.Index(rest, l.Text)
		if i < 0 {
			continue
		}
		b.WriteString(template.HTMLEscapeString(rest[:i]))
		fmt.Fprintf(&b, `<a class="sig-go" href="#findings-h" data-sig="%s" data-title="%s">%s</a>`,
			template.HTMLEscapeString(l.Key), template.HTMLEscapeString(l.Title), template.HTMLEscapeString(l.Text))
		rest = rest[i+len(l.Text):]
	}
	b.WriteString(template.HTMLEscapeString(rest))
	return template.HTML(b.String()) // #nosec G203 -- every piece is escaped above
}

// signalMove is how one signal moves a finding: the change, in the outlined mark a finding row
// wears, and then the condition it applies under.
//
// The words are the ones the Signals table in docs/concepts/prioritization.md uses for the same
// signals, so the report and the concept cannot describe one rule two ways. A signal moves severity
// by a level, "severity one level"; "band" is kept for P1 to P4.
type signalMove struct {
	// Up is a signal that raises a finding; the rest lower one.
	Up bool
	// Change is what moves and how far: "severity to critical".
	Change string
	// Condition is when the change applies, up to Value where there is one.
	Condition string
	// Value is a setting of this run named inside the condition, the EPSS threshold, and Rest the
	// text after it. Both empty for a signal with no setting.
	Value, Rest string
}

// Glyph is the arrow a finding row's mark carries for the same movement.
func (m signalMove) Glyph() string {
	if m.Up {
		return "↑"
	}
	return "↓"
}

// Dir is the class the HTML report colors a mark by, the one a finding row's mark carries.
func (m signalMove) Dir() string {
	if m.Up {
		return "up"
	}
	return "down"
}

// signalKind is one signal the Signals section can list: what it is called, how it moves a finding,
// and what it did in a run.
type signalKind struct {
	name string
	// moves says how the signal moves a finding. It takes the run because one signal's rule has a
	// setting, and the report states the value the run used rather than a default.
	moves func(d Data) signalMove
	// did is one line per row the signal contributes, and the notes that qualify them. No lines
	// leaves the signal out of the section.
	did func(d Data, s summary) (did []didLine, notes []string)
}

// signalKinds is every signal the Signals section can list, in the order it lists them: the ones
// that raise, then the one that lowers.
//
// One table for the console, the HTML report and the markdown report, so a signal one of them lists
// is listed by all three, and none of them can list a signal without saying how it moves a finding.
// TestEverySignalSaysHowItMovesAFinding holds every entry to that.
var signalKinds = []signalKind{
	{
		name: "KEV",
		moves: func(Data) signalMove {
			return signalMove{Up: true, Change: "severity to critical",
				Condition: "when it is on CISA's Known Exploited Vulnerabilities catalog"}
		},
		did: kevDid,
	},
	{name: "EPSS", moves: epssMoves, did: feedDid(exploit.SignalEPSS, "raised by EPSS", "--epss auto")},
	{
		// Named as a finding's mark names them, so a reader can match the row to the marks it counts.
		name: "malicious",
		moves: func(Data) signalMove {
			return signalMove{Up: true, Change: "severity to critical",
				Condition: "when the package is in the OSSF Malicious Packages Project"}
		},
		did: healthDid(dephealth.SignalMalicious, "raised as malicious"),
	},
	{
		name: "deprecated",
		moves: func(Data) signalMove {
			return signalMove{Up: true, Change: "severity one level",
				Condition: "when the publisher has marked the version as no longer supported"}
		},
		did: healthDid(dephealth.SignalDeprecated, "raised as deprecated"),
	},
	{
		name: "floor",
		// The context floor, which the `↑ floor` mark counts, and not the minimum severity, which
		// draws no mark. P1 because it ranks a finding at the tier of a public, critical component
		// and the only control that declares one holds every finding at high or above;
		// TestEveryFlooredFindingIsP1 in internal/scanpolicy fails the day that stops being true.
		moves: func(Data) signalMove {
			return signalMove{Up: true, Change: "priority to P1",
				Condition: "for a leaked credential, whatever its component declares; severity unchanged"}
		},
		did: floorDid,
	},
	{
		// Named for what it is rather than for the tool that did it. "govulncheck" in the first
		// column tells a reader which binary ran and not what it decided, and this is the one signal
		// whose name they have no reason to know.
		name: "reachability",
		moves: func(Data) signalMove {
			return signalMove{Change: "severity one level",
				Condition: "when analysis finds no path from your code to it"}
		},
		did: reachabilityDid,
	},
}

// signals is what argued with this run's ranking, one row for each thing that did, and the notes
// that qualify the rows.
//
// Counted over every finding rather than the listed ones. `--top` and `--min-priority` narrow what
// is shown, and this answers what the signals did, not what fitted on the page.
func signals(d Data, s summary) (rows []signalRow, notes []string) {
	for _, k := range signalKinds {
		did, n := k.did(d, s)
		for _, line := range did {
			rows = append(rows, signalRow{Name: k.name, Moves: k.moves(d), Did: line.text, Links: line.links, Unread: line.unread})
		}
		notes = append(notes, n...)
	}
	if note := lookupNote(d, s); note != "" {
		notes = append(notes, note)
	}
	if note := advisoriesNote(d, s); note != "" {
		notes = append(notes, note)
	}
	if note := unresolvedNote(d, s); note != "" {
		notes = append(notes, note)
	}
	if note := sourcesNote(s); note != "" {
		notes = append(notes, note)
	}
	return rows, notes
}

// sourceLicense is the database an OSV.dev record came from and the license it is under.
type sourceLicense struct{ source, license string }

// countUp adds one to m[k], making m where it is nil.
func countUp(m map[string]int, k string) map[string]int {
	if m == nil {
		m = map[string]int{}
	}
	m[k]++
	return m
}

// osvEcosystemOrder is the order ecosystems are named in, the order config.exploitability.advisories
// documents them.
var osvEcosystemOrder = []string{"npm", "PyPI", "crates.io", "Go"}

// advisoriesOff are the ecosystems whose findings name only an advisory id and whose OSV.dev
// advisories this run did not read, with how many findings each holds. Go's findings are left to
// lookupNote where the Go vulnerability database was not read either, since that is the lookup
// every Go run can make.
func advisoriesOff(d Data, s summary) (ecos []string, counts []int) {
	return advisoryEcosystems(s, func(eco string) bool {
		return !consulted(d, "osv-"+strings.ToLower(eco)) && (eco != "Go" || consulted(d, exploit.DatasetGoVulnDB))
	})
}

// advisoriesUnresolved are the ecosystems whose OSV.dev advisories this run read and whose findings
// still name only an advisory id: their records list no CVE, or the records a finding's ids lead to
// disagree on one, which resolves nothing.
func advisoriesUnresolved(d Data, s summary) (ecos []string, counts []int) {
	return advisoryEcosystems(s, func(eco string) bool { return consulted(d, "osv-"+strings.ToLower(eco)) })
}

// advisoryEcosystems are the ecosystems keep accepts that hold findings naming only an advisory id,
// with how many each holds, in osvEcosystemOrder.
func advisoryEcosystems(s summary, keep func(eco string) bool) (ecos []string, counts []int) {
	for _, eco := range osvEcosystemOrder {
		if n := s.byEcosystem[eco]; n > 0 && keep(eco) {
			ecos, counts = append(ecos, eco), append(counts, n)
		}
	}
	return ecos, counts
}

// countedByEcosystem renders "2 npm and 1 crates.io findings", and the ecosystems' values as
// config.exploitability.advisories spells them.
func countedByEcosystem(ecos []string, counts []int) (phrase string, values []string) {
	var parts []string
	total := 0
	for i, eco := range ecos {
		parts = append(parts, fmt.Sprintf("%d %s", counts[i], eco))
		values = append(values, strings.ToLower(eco))
		total += counts[i]
	}
	return english.And(parts) + " " + english.Choose(total, "finding", "findings"), values
}

// unresolvedNote says how many findings KEV and EPSS could not check although their ecosystem's
// OSV.dev advisories were read, because no record gave them one CVE.
func unresolvedNote(d Data, s summary) string {
	if !consulted(d, exploit.SignalKEV) && !consulted(d, exploit.SignalEPSS) {
		return ""
	}
	ecos, counts := advisoriesUnresolved(d, s)
	if len(ecos) == 0 {
		return ""
	}
	phrase, _ := countedByEcosystem(ecos, counts)
	return fmt.Sprintf("KEV and EPSS did not check %s with an advisory id and no CVE: OSV.dev's records "+
		"of their ids list no CVE, or different ones, so they are ranked without KEV or EPSS.", phrase)
}

// advisoriesNote says how many findings KEV and EPSS could not check because they name only an
// advisory id and the run read no OSV.dev advisories for their ecosystem, and which entries of
// config.exploitability.advisories would look their CVEs up.
//
// Empty where neither KEV nor EPSS was read, which their own rows already say.
func advisoriesNote(d Data, s summary) string {
	if !consulted(d, exploit.SignalKEV) && !consulted(d, exploit.SignalEPSS) {
		return ""
	}
	ecos, counts := advisoriesOff(d, s)
	if len(ecos) == 0 {
		return ""
	}
	phrase, values := countedByEcosystem(ecos, counts)
	return fmt.Sprintf("KEV and EPSS did not check %s with an advisory id and no CVE. "+
		"config.exploitability.advisories: [%s] looks up their CVEs.", phrase, strings.Join(values, ", "))
}

// sourcesNote credits the databases whose OSV.dev records gave findings their CVE, with each
// record's license, which for most of them asks that the source be named. Each finding's record is
// linked from its cveLookup in report.json and results.sarif.
func sourcesNote(s summary) string {
	if len(s.bySource) == 0 {
		return ""
	}
	keys := make([]sourceLicense, 0, len(s.bySource))
	total := 0
	for k, n := range s.bySource {
		keys = append(keys, k)
		total += n
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].source != keys[j].source {
			return keys[i].source < keys[j].source
		}
		return keys[i].license < keys[j].license
	})
	named := func(k sourceLicense) string {
		if k.license == "" {
			return k.source
		}
		return k.source + " (" + k.license + ")"
	}
	if len(keys) == 1 {
		return fmt.Sprintf("CVE from OSV.dev for %s, from the %s", english.Count(total, "finding"), named(keys[0]))
	}
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%d from the %s", s.bySource[k], named(k)))
	}
	return fmt.Sprintf("CVE from OSV.dev for %s: %s", english.Count(total, "finding"), strings.Join(parts, ", "))
}

// lookupNote says how many findings KEV and EPSS could not check because they name only a Go or
// GitHub advisory id and no copy of the Go vulnerability database was read to find their CVE.
//
// Empty where neither dataset was read, which their own rows already say, and where the database was
// read: a finding it gave no CVE has none it lists, which is not something a fetch would change.
// Without the note, a run that could not look a finding up reads like one that looked and found it
// on neither list.
func lookupNote(d Data, s summary) string {
	if s.needsLookup == 0 || consulted(d, exploit.DatasetGoVulnDB) ||
		(!consulted(d, exploit.SignalKEV) && !consulted(d, exploit.SignalEPSS)) {
		return ""
	}
	head := fmt.Sprintf("KEV and EPSS did not check %s named only by a Go or GitHub advisory id.",
		english.Count(s.needsLookup, "finding"))
	if !fromFeedCache(d) {
		// A file given as a path reads no cache, so fetching the database would change nothing here.
		return head + " The lookup reads the feed cache, which a file path does not: use --kev auto or --epss auto."
	}
	return head + " Run draugr feeds update govulndb, then scan again, to look up their CVEs."
}

// fromFeedCache reports whether KEV or EPSS came from the feed cache rather than a file the operator
// gave as a path, which records no URL. Only a run that reads the cache can read the Go
// vulnerability database beside it.
func fromFeedCache(d Data) bool {
	for _, f := range d.Exploitability {
		if (f.Name == exploit.SignalKEV || f.Name == exploit.SignalEPSS) && f.URL != "" {
			return true
		}
	}
	return false
}

// feedDid is what an exploitability dataset did: listed whenever the run consulted it, and as not
// read where it could have raised something. flag is what reads it.
//
// "nothing raised" is a result rather than an absence. Without it the only way to learn a feed
// changed nothing is to read every finding looking for a mark that is not there.
func feedDid(name, title, flag string) func(Data, summary) ([]didLine, []string) {
	return func(d Data, s summary) ([]didLine, []string) {
		n := s.bySignal[name]
		if n == 0 && !consulted(d, name) {
			return notRead(s, flag), nil
		}
		return []didLine{raisedLine(n, "", raisedKey(name), title)}, nil
	}
}

// kevDid is what the KEV catalog did: how many findings it lists, and how many of those it raised.
// Listed whenever the run consulted it.
//
// Listed first because a listed finding's fix comes first in its band whether or not KEV raised
// it, and one the scanner already rated critical raises nothing. A count of raised findings alone
// reads "nothing raised" over a run whose most urgent finding is on the catalog.
//
// Qualified by noCVENotes wherever it has a row, the one place the run says which findings neither
// dataset could reach.
func kevDid(d Data, s summary) ([]didLine, []string) {
	lines := kevLines(d, s)
	if len(lines) == 0 {
		return nil, nil
	}
	return lines, noCVENotes(d, s)
}

// noCVENotes says how many imported findings about a vulnerability name no CVE, the key KEV and
// EPSS are looked up by, in their rule id or among the identifiers their file lists. Grype, for one,
// names a finding by its GitHub or Go advisory and writes no CVE into its SARIF.
//
// Said once for both datasets, because "nothing listed" over a run where they could not be asked
// reads as a clean answer, and a scanner Draugr runs states the CVE where an imported file may not.
func noCVENotes(d Data, s summary) []string {
	n := s.importedNoCVE
	if lookupNote(d, s) != "" {
		// The lookup note already counts those a lookup would match, and says what to run.
		n -= s.importedNeedsLookup
	}
	// So do the advisories notes, by ecosystem.
	var counted []string
	if advisoriesNote(d, s) != "" {
		counted, _ = advisoriesOff(d, s)
	}
	if unresolvedNote(d, s) != "" {
		unresolved, _ := advisoriesUnresolved(d, s)
		counted = append(counted, unresolved...)
	}
	for _, eco := range counted {
		n -= s.importedByEcosystem[eco]
	}
	if n == 0 {
		return nil
	}
	return []string{"not checked against KEV or EPSS: " + english.Count(n, "imported finding") + " " +
		english.Choose(n, "names", "name") + " no CVE"}
}

// kevLines is the KEV row's line, or none where the run neither read the catalog nor holds a finding
// it could have listed.
func kevLines(d Data, s summary) []didLine {
	// A finding KEV raised is one it lists, so a raise is never counted without a listing.
	if s.onKEV == 0 {
		if !consulted(d, exploit.SignalKEV) {
			return notRead(s, "--kev auto")
		}
		return []didLine{plainDid("nothing listed")}
	}
	listed := english.Count(s.onKEV, "finding") + " listed"
	line := didLine{text: listed, links: []signalLink{{Text: listed, Key: signalKeyKEVListed, Title: "on the KEV catalog"}}}
	if n := s.bySignal[exploit.SignalKEV]; n > 0 {
		raised := fmt.Sprintf("%d raised", n)
		line.text += " · " + raised
		line.links = append(line.links, signalLink{Text: raised, Key: raisedKey(exploit.SignalKEV), Title: "raised by KEV"})
	}
	return []didLine{line}
}

// notRead is the row for a dataset the run did not read, where the run has a finding the dataset
// could have raised: a finding naming a CVE, in its rule id or among its aliases, which is what KEV
// and EPSS are keyed on.
//
// A scan reads neither unless a flag or config.exploitability asks, so nothing is fetched without
// somebody choosing it. Without this row, a run that read neither says nothing about either, and
// "nothing here is being exploited" cannot be told from "nobody checked". A run with no CVE has
// nothing either could raise, and gets no row.
func notRead(s summary, flag string) []didLine {
	if s.matchable == 0 {
		return nil
	}
	return []didLine{{text: "not read · " + flag + " reads it", unread: true}}
}

// healthDid is what one of dependency health's two signals did: listed whenever the lookup answered,
// for the reason a feed is listed when it raised nothing.
func healthDid(signal, title string) func(Data, summary) ([]didLine, []string) {
	return func(d Data, s summary) ([]didLine, []string) {
		n := s.bySignal[signal]
		if n == 0 && !healthConsulted(d) {
			return nil, nil
		}
		return []didLine{raisedLine(n, "", raisedKey(signal), title)}, nil
	}
}

// healthConsulted reports whether this run's dependency-health lookup answered. The engine records
// it only then, so a lookup that failed, or that knew none of the packages, lists nothing.
func healthConsulted(d Data) bool {
	for _, c := range d.Run.Consulted {
		if c.Signal == dephealth.DatasetName {
			return true
		}
	}
	return false
}

// floorDid is what the control floor did: listed whenever a control that declares one ran, for the
// reason a feed is listed when it raised nothing.
func floorDid(d Data, s summary) ([]didLine, []string) {
	if s.floored == 0 && !floorApplied(d) {
		return nil, nil
	}
	return []didLine{raisedLine(s.floored, " by a control's own rule", signalKeyFloor, "floored by a control")}, nil
}

// raisedLine is a signal's count in the words every row uses, with the count linked to the findings
// it names. Nothing raised names none, and links nowhere.
func raisedLine(n int, by, key, title string) didLine {
	if n == 0 {
		return plainDid("nothing raised")
	}
	count := english.Count(n, "finding") + " raised"
	return didLine{text: count + by, links: []signalLink{{Text: count, Key: key, Title: title}}}
}

// floorApplied reports whether a control that declares a context floor ran in this run.
func floorApplied(d Data) bool {
	for _, control := range d.Run.ContextFloors {
		if _, ran := d.Run.Controls[control]; ran {
			return true
		}
	}
	return false
}

// reachabilityDid is a row per analyzer that ran, and the note that qualifies them.
//
// Each verdict's count links to the findings the analyzer gave that verdict.
func reachabilityDid(d Data, _ summary) ([]didLine, []string) {
	rows, notes := reachabilityBlock(d)
	did := make([]didLine, 0, len(rows))
	byName := map[string]AnalyzerCounts{}
	for _, a := range d.Run.Reachability.Analyzers {
		byName[a.Analyzer] = AnalyzerCounts{a.Reachable, a.Unreachable, a.Unknown}
	}
	for _, row := range rows {
		analyzer, said, _ := strings.Cut(row, "  ")
		analyzer = strings.TrimSpace(analyzer)
		line := didLine{text: analyzer + " · " + strings.TrimSpace(said)}
		c := byName[analyzer]
		for _, v := range []struct {
			n     int
			state sarif.ReachabilityState
		}{{c.Reachable, sarif.ReachabilityReachable}, {c.Unreachable, sarif.ReachabilityUnreachable}, {c.Unknown, sarif.ReachabilityUnknown}} {
			if v.n == 0 {
				continue
			}
			words := fmt.Sprintf("%d %s", v.n, v.state)
			line.links = append(line.links, signalLink{Text: words, Key: reachKey(v.state, analyzer),
				Title: fmt.Sprintf("%s per %s", v.state, analyzer)})
		}
		did = append(did, line)
	}
	return did, notes
}

// epssMoves states the EPSS rule with the threshold this run measured against, which the flag,
// the descriptor or the default set.
//
// Read from what the run consulted rather than assumed: a report that printed the default beside a
// run with a different threshold would explain a band by a rule the run did not apply. A run that
// did not record one says "this run's threshold" without a number.
func epssMoves(d Data) signalMove {
	m := signalMove{Up: true, Change: "severity one level",
		Condition: "when its predicted exploitation is at or above this run's threshold"}
	for _, c := range d.Run.Consulted {
		if c.Signal != exploit.SignalEPSS {
			continue
		}
		m.Condition = "when its predicted exploitation is at or above"
		m.Value = strconv.FormatFloat(c.Threshold, 'f', -1, 64)
		m.Rest = ", this run's threshold"
		// Zero is how a descriptor turns the raise off while keeping KEV, and "at or above 0"
		// alone reads as every finding.
		if c.Threshold <= 0 {
			m.Rest += ", which turns it off"
		}
	}
	return m
}

// AnalyzerCounts is one analyzer's verdicts in this run, by state.
type AnalyzerCounts struct{ Reachable, Unreachable, Unknown int }

// The keys a finding carries in the HTML report's data-sig, one for each count in the Signals
// section that includes it, so a count followed from there narrows the list to exactly those.
const (
	signalKeyKEVListed = "kev-listed"
	signalKeyFloor     = "floor"
)

// raisedKey is the key of a finding a signal raised.
func raisedKey(signal string) string { return "raised-" + signal }

// reachKey is the key of a finding an analyzer gave a verdict.
func reachKey(state sarif.ReachabilityState, analyzer string) string {
	return "reach-" + string(state) + "-" + analyzer
}

// signalKeys is every key a finding carries, counted as the Signals section counts: on the KEV
// catalog whether or not that raised it, raised by the signal its escalation names, floored by a
// control, and the verdict an analyzer gave it.
func signalKeys(f finding) []string {
	var keys []string
	if f.exploited != nil {
		keys = append(keys, signalKeyKEVListed)
	}
	if f.escalation != nil {
		keys = append(keys, raisedKey(f.escalation.Signal))
	}
	if f.controlFloor() {
		keys = append(keys, signalKeyFloor)
	}
	if r := f.reachability; r != nil {
		keys = append(keys, reachKey(r.State, r.Analyzer))
	}
	return keys
}
