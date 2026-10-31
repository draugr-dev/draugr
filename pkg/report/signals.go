package report

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/draugr-dev/draugr/internal/english"
	"github.com/draugr-dev/draugr/pkg/dephealth"
	"github.com/draugr-dev/draugr/pkg/exploit"
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
}

// signalMove is how one signal moves a finding: the change, in the outlined mark a finding row
// wears, and then the condition it applies under.
//
// The words are the ones docs/concepts/prioritization.md and docs/concepts/reducing-the-noise.md
// use for the same signals, so the report and the concept cannot describe one rule two ways.
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
	did func(d Data, s summary) (did []string, notes []string)
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
		did: feedDid(exploit.SignalKEV),
	},
	{name: "EPSS", moves: epssMoves, did: feedDid(exploit.SignalEPSS)},
	{
		// Named as a finding's mark names them, so a reader can match the row to the marks it counts.
		name: "malicious",
		moves: func(Data) signalMove {
			return signalMove{Up: true, Change: "severity to critical",
				Condition: "when the package is in the OSSF Malicious Packages Project"}
		},
		did: healthDid(dephealth.SignalMalicious),
	},
	{
		name: "deprecated",
		moves: func(Data) signalMove {
			return signalMove{Up: true, Change: "severity one band",
				Condition: "when the publisher has marked the version as no longer supported"}
		},
		did: healthDid(dephealth.SignalDeprecated),
	},
	{
		name: "floor",
		// The context floor, which the `↑ floor` mark counts, and not the severity floor, which
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
			return signalMove{Change: "severity one band",
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
			rows = append(rows, signalRow{Name: k.name, Moves: k.moves(d), Did: line})
		}
		notes = append(notes, n...)
	}
	return rows, notes
}

// feedDid is what an exploitability dataset did: listed whenever the run consulted it.
//
// "nothing raised" is a result rather than an absence. Without it the only way to learn a feed
// changed nothing is to read every finding looking for a mark that is not there.
func feedDid(name string) func(Data, summary) ([]string, []string) {
	return func(d Data, s summary) ([]string, []string) {
		n := s.bySignal[name]
		if n == 0 && !consulted(d, name) {
			return nil, nil
		}
		return []string{raisedCount(n, "")}, nil
	}
}

// healthDid is what one of dependency health's two signals did: listed whenever the lookup answered,
// for the reason a feed is listed when it raised nothing.
func healthDid(signal string) func(Data, summary) ([]string, []string) {
	return func(d Data, s summary) ([]string, []string) {
		n := s.bySignal[signal]
		if n == 0 && !healthConsulted(d) {
			return nil, nil
		}
		return []string{raisedCount(n, "")}, nil
	}
}

// healthConsulted reports whether this run's dependency-health lookup answered. The engine records
// it only then, so a lookup that failed, or that knew none of the packages, lists nothing.
func healthConsulted(d Data) bool {
	for _, c := range d.Run.Consulted {
		if c.Signal == dephealth.ConsultedSignal {
			return true
		}
	}
	return false
}

// floorDid is what the control floor did: listed whenever a control that declares one ran, for the
// reason a feed is listed when it raised nothing.
func floorDid(d Data, s summary) ([]string, []string) {
	if s.floored == 0 && !floorApplied(d) {
		return nil, nil
	}
	return []string{raisedCount(s.floored, " by a control's own rule")}, nil
}

// raisedCount is a signal's count in the words every row uses.
func raisedCount(n int, by string) string {
	if n == 0 {
		return "nothing raised"
	}
	return fmt.Sprintf("%s raised%s", english.Count(n, "finding"), by)
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
func reachabilityDid(d Data, _ summary) ([]string, []string) {
	rows, notes := reachabilityBlock(d)
	did := make([]string, 0, len(rows))
	for _, row := range rows {
		analyzer, said, _ := strings.Cut(row, "  ")
		did = append(did, strings.TrimSpace(analyzer)+" · "+strings.TrimSpace(said))
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
	m := signalMove{Up: true, Change: "severity one band",
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
