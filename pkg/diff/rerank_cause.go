package diff

import (
	"strings"

	"github.com/draugr-dev/draugr/pkg/prioritization"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/skald"
)

// The inputs to a band that a cause can name, as Cause.Input holds them.
const (
	causeExposure     = "exposure"
	causeCriticality  = "criticality"
	causeSeverity     = "severity"
	causeMinimum      = "minimum"
	causeEscalation   = "escalation"
	causeFloor        = "floor"
	causeReachability = "reachability"
	causeCap          = "cap"
)

// Cause is one input to a finding's band that the two scans recorded differently: what the
// component declared, what the scanner rated it, or a signal that moved it in one scan and not the
// other.
//
// Read from what each scan stamped on the finding, so a cause is only ever a difference both reports
// record. A band that moved with every recorded input the same, as a change to the ranking's own
// settings moves one, has no cause, and the row says nothing rather than guessing.
type Cause struct {
	// Input is what changed: exposure, criticality, severity (the scanner's own rating), minimum
	// (the control's minimum severity), escalation (a signal that raised the severity), floor (a
	// band held up by the control or a converter), reachability (an unreachable verdict that lowered
	// it) or cap (a band held down because a lockfile pins the reference).
	Input string `json:"input"`
	// From and To are the input as the base and the head recorded it. Empty where that scan recorded
	// none: a component that declared no exposure, a finding no signal raised.
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
	// Text is the cause as the console prints it: `exposure public → internal`, `↑ KEV`.
	Text string `json:"text"`
}

// context reports whether the cause is the component's declared classification, which every
// finding of the component shares.
func (c Cause) context() bool { return c.Input == causeExposure || c.Input == causeCriticality }

// Causes is what the two scans recorded differently among the inputs to this finding's band, in the
// order the ranking applies them: the component's classification, the rating, then each signal.
// Nil where the base copy is not known or nothing recorded differs.
func (r Rerank) Causes() []Cause {
	if r.Was.RuleID == "" {
		return nil
	}
	return causes(r.Was, r.Result, !r.classUnknown)
}

// causes compares the inputs was and now record, the classification only where withClass says the
// base recorded it.
func causes(was, now sarif.Result, withClass bool) []Cause {
	var out []Cause
	add := func(c Cause, ok bool) {
		if ok {
			out = append(out, c)
		}
	}
	if withClass {
		addClass(add, was, now)
	}
	// The scanner's own rating, compared only between two copies one tool reported. A flaw carried
	// over from another scanner's copy in the base is rated by two tools, and their ratings differing
	// says nothing about what moved the band.
	if was.Tool == now.Tool {
		if a, b := was.Severity(""), now.Severity(""); a != b {
			out = append(out, Cause{Input: causeSeverity, From: string(a), To: string(b),
				Text: "severity " + string(a) + " → " + string(b)})
		}
	}
	add(markCause(causeMinimum, string(was.SeverityFloor), string(now.SeverityFloor), "↑",
		func(v string) string { return "minimum severity " + v }))
	add(markCause(causeEscalation, escalationOf(was), escalationOf(now), "↑", asRecorded))
	add(markCause(causeFloor, floorOf(was), floorOf(now), "↑", asRecorded))
	add(markCause(causeReachability, unreachableOf(was), unreachableOf(now), "↓", asRecorded))
	// The cap records why the lockfile pins the reference, and the mark is the same whatever it says.
	add(markCause(causeCap, was.PriorityCap, now.PriorityCap, "↓", func(string) string { return "pinned" }))
	return out
}

// addClass adds the changes to the component's classification between was and now.
func addClass(add func(Cause, bool), was, now sarif.Result) {
	add(classCause(causeExposure, was.Exposure, now.Exposure, func(v string) (string, bool) {
		e, assumed := prioritization.RankedExposure(saga.Exposure(v))
		return string(e), assumed
	}))
	add(classCause(causeCriticality, was.Criticality, now.Criticality, func(v string) (string, bool) {
		c, assumed := prioritization.RankedCriticality(saga.Criticality(v))
		return string(c), assumed
	}))
}

// recordsClassification reports whether a report can say what its components declared: it records
// its descriptor's declarations, or one of its findings carries an exposure or criticality.
//
// A finding with neither is ranked as public and critical, and a release that stamped no
// classification on any finding wrote the same empty fields whatever was declared. Read as assumed,
// such a base would name a change from public to whatever the head declares that the base may never
// have made.
func recordsClassification(rep sarif.Report) bool {
	for _, p := range rep.Provenance {
		if p.Tool == skald.DeclaredProvenanceTool {
			return true
		}
	}
	for _, r := range rep.Results {
		if r.Exposure != "" || r.Criticality != "" {
			return true
		}
	}
	return false
}

// classCause compares one half of the component's classification as the ranking read it, an
// undeclared value as the level it assumed. A declaration that names the level already assumed moved
// nothing, so it is no cause.
func classCause(input, was, now string, ranked func(string) (string, bool)) (Cause, bool) {
	a, aAssumed := ranked(was)
	b, bAssumed := ranked(now)
	if a == b {
		return Cause{}, false
	}
	word := func(v string, assumed bool) string {
		if assumed {
			return v + " (assumed)"
		}
		return v
	}
	return Cause{Input: input, From: was, To: now,
		Text: input + " " + word(a, aAssumed) + " → " + word(b, bAssumed)}, true
}

// markCause compares a mark the scan's console prints beside a band, `↑ KEV` or `↓ pinned`, where
// was and now are what each scan recorded for it and label is the mark's words for a recorded value.
// Two values the mark words the same, as two reasons for one cap, moved nothing a reader could name.
//
// A mark the head no longer carries is named without its arrow: the arrow says which way the mark
// pushes, and beside a band that moved the other way it would read as the direction of the move.
func markCause(input, was, now, glyph string, label func(string) string) (Cause, bool) {
	if label(was) == label(now) && (was == "") == (now == "") {
		return Cause{}, false
	}
	var text string
	switch {
	case was == "":
		text = glyph + " " + label(now)
	case now == "":
		text = "no longer " + label(was)
	default:
		text = glyph + " " + label(now) + " (was " + was + ")"
	}
	return Cause{Input: input, From: was, To: now, Text: text}, true
}

// asRecorded labels a mark by the value the scan recorded.
func asRecorded(v string) string { return v }

// escalationOf names the signal that raised the finding's severity, as `draugr scan` marks it, or
// "" where none did or an unreachable verdict lowered it again.
func escalationOf(r sarif.Result) string {
	if r.Escalation == nil || r.Escalation.To == "" || unreachableOf(r) != "" {
		return ""
	}
	switch s := r.Escalation.Signal; s {
	case "kev", "epss":
		return strings.ToUpper(s)
	default:
		return s
	}
}

// floorOf is the floor that held the band up, by who held it: the control, or a declared converter
// by its name.
func floorOf(r sarif.Result) string {
	switch {
	case r.PriorityFloor == "":
		return ""
	case r.RaisedByConverter():
		return "converter " + r.Converter.Name
	default:
		return "floor"
	}
}

// unreachableOf is "unreachable" where a reachability verdict lowered the finding's severity.
func unreachableOf(r sarif.Result) string {
	if r.Reachability != nil && r.Reachability.State == sarif.ReachabilityUnreachable && r.Reachability.RankedAs != "" {
		return "unreachable"
	}
	return ""
}

// rerankWhy is what the reranked listing says about each row's causes: a line for each component
// whose every row moved for the same declared classification, and each row's causes that line does
// not already name.
type rerankWhy struct {
	// components is one line per component, "worker: exposure public → internal, criticality …",
	// in the order the rows first name them.
	components []string
	// rows are the causes left to each row, by its index in the rows given, joined for printing.
	rows []string
}

// explainReranks sorts the rows' causes into the lines above the table and the notes under the rows.
//
// The classification is the component's, so a component that declared a new exposure moves every
// finding it holds for the same reason. Said once for the component, the reader reads it once
// instead of on every row; what moved one finding alone stays beside that finding.
func explainReranks(rs []Rerank) rerankWhy {
	all := make([][]Cause, len(rs))
	var order []string
	byComponent := map[string][]int{}
	for i, r := range rs {
		all[i] = r.Causes()
		if _, seen := byComponent[r.Component]; !seen {
			order = append(order, r.Component)
		}
		byComponent[r.Component] = append(byComponent[r.Component], i)
	}
	shared := map[string]bool{}
	var out rerankWhy
	for _, comp := range order {
		idx := byComponent[comp]
		ctx := contextText(all[idx[0]])
		if comp == "" || ctx == "" {
			continue
		}
		same := true
		for _, i := range idx[1:] {
			if contextText(all[i]) != ctx {
				same = false
				break
			}
		}
		if same {
			shared[comp] = true
			out.components = append(out.components, comp+": "+ctx)
		}
	}
	out.rows = make([]string, len(rs))
	for i, r := range rs {
		var texts []string
		for _, c := range all[i] {
			if c.context() && shared[r.Component] {
				continue
			}
			texts = append(texts, c.Text)
		}
		out.rows[i] = strings.Join(texts, ", ")
	}
	return out
}

// contextText is the classification causes among cs, joined as a line prints them.
func contextText(cs []Cause) string {
	var texts []string
	for _, c := range cs {
		if c.context() {
			texts = append(texts, c.Text)
		}
	}
	return strings.Join(texts, ", ")
}

// anyRow reports whether any row has a cause of its own.
func (w rerankWhy) anyRow() bool {
	for _, s := range w.rows {
		if s != "" {
			return true
		}
	}
	return false
}
