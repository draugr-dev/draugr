package report

import "github.com/draugr-dev/draugr/pkg/sarif"

// CodeLine is the findings at one line of code as the fix list groups them: one action, however
// many rules flag the line.
//
// For a caller outside this package that lists its own actions, `draugr diff` among them. The
// keying, the title and the rules come from the functions the fix list itself uses, so a line is
// one action with the same title wherever it is listed.
type CodeLine struct {
	// Key identifies the line: its component, repository and location. Results sharing a key are
	// one action.
	Key string
	// Component and Repository the line belongs to, and Location, its path and line.
	Component, Repository, Location string
	// Title is what to do about the line, in the imperative.
	Title string
	// Summary is the scanner's description of the flaw, for a title that names a rule rather than
	// quoting the description. Empty where the title quotes it.
	Summary string
	// Rules are each scanner and the rules of its that flag the line, starting with the rule the
	// title quotes.
	Rules []LineRules
}

// LineRules is one scanner's rules at a line of code.
type LineRules struct {
	// Tool is the scanner as it names itself, without its edition unless the edition is what tells
	// two scanners at the line apart.
	Tool  string
	Rules []LineRule
}

// LineRule is one rule at a line of code.
type LineRule struct {
	// ID is the rule's identifier, Name the part of it that names the rule, and HelpURI where the
	// rule is documented, empty when nothing is.
	ID, Name, HelpURI string
}

// Where is the line's location, led by its repository when withRepository is set: the same path in
// two repositories is two lines, and a list spanning several names which one.
func (l CodeLine) Where(withRepository bool) string {
	if withRepository {
		return inRepository(l.Repository, l.Location)
	}
	return l.Location
}

// PlaceLines is results with every result at a line of code that names no repository placed in
// the repository the rest of its component was scanned in, as the fix list places them. Call it
// over every result being grouped before LineKey, so an imported SARIF file's finding joins the
// other findings at its line. The results are copied, never changed in place.
func PlaceLines(results []sarif.Result) []sarif.Result {
	fs := make([]finding, len(results))
	for i, res := range results {
		fs[i] = findingOf("", sarif.Report{}, res)
	}
	placed := placeLines(fs)
	out := make([]sarif.Result, len(results))
	for i, res := range results {
		res.Repository = placed[i].repository
		out[i] = res
	}
	return out
}

// LineKey is the key a result groups under when it is a flaw at one line of code, a sast finding
// with a line, and false for any other result. Two results with the same key are one action.
func LineKey(res sarif.Result) (string, bool) {
	f := findingOf("", sarif.Report{}, res)
	if !onALine(f) {
		return "", false
	}
	return lineKeyOf(f), true
}

// LineOf titles the results at one line of code, every one sharing a LineKey. rules is what the
// scanners published about the rules the results cite, which titles the line where a rule's
// description says more than its findings' messages. Empty results give an empty CodeLine.
func LineOf(rules map[string]sarif.Rule, results []sarif.Result) CodeLine {
	if len(results) == 0 {
		return CodeLine{}
	}
	rep := sarif.Report{Rules: rules}
	fs := make([]finding, len(results))
	for i, res := range results {
		fs[i] = findingOf("", rep, res)
	}
	sortFindings(fs)
	a := action{key: lineKeyOf(fs[0]), findings: fs}
	out := CodeLine{
		Key: a.key, Component: fs[0].component, Repository: fs[0].repository, Location: fs[0].location,
	}
	out.Title, out.Summary = lineTitle(fs)
	for _, g := range a.rulesByTool() {
		group := LineRules{Tool: g.tool}
		for _, f := range g.rules {
			group.Rules = append(group.Rules, LineRule{ID: f.ruleID, Name: shortRuleName(f.ruleID), HelpURI: f.helpURI})
		}
		out.Rules = append(out.Rules, group)
	}
	return out
}
