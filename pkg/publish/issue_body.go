package publish

import (
	"fmt"
	"html"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/draugr-dev/draugr/internal/english"
	"github.com/draugr-dev/draugr/pkg/report"
)

// oneChangeRows is how many findings an action that is one change lists before the count of the
// rest. Each is cleared by the same edit, so the rest add length and no instruction.
const oneChangeRows = 10

// acceptDocs is where the body sends a reader who decides a finding is acceptable.
const acceptDocs = "https://draugr.dev/docs/latest/reference/saga-schema/#configexclude"

// issueBody is one item's body before it is rendered: everything a renderer needs and nothing it
// has to work out.
type issueBody struct {
	Marker      string
	Failing     int
	Accepted    int
	Gate        issueGate
	Incomplete  bool
	Controls    []controlCount
	Errors      []issueError
	Actions     []report.Action
	Run         issueRun
	ClosesOn    []string
	MinPriority string
	// Lead opens the Actions section of a parent whose actions do not all have a child.
	Lead string
	// Child is set on a child's body, and replaces the verdict with the child's own line.
	Child *childHead
}

// childHead is what a child's body opens with: its priority, control, findings and gate, and for
// a child per action, the action itself.
type childHead struct {
	Priority string
	Control  string
	Clears   int
	// Gate is the band the child's control is judged against.
	Gate string
	// Action is set on a child per action, whose findings the body tables directly.
	Action *report.Action
}

// issueGate is the threshold the part is judged against: the gate's own, and each covered
// control's where it differs.
type issueGate struct {
	Default   string
	Overrides []controlBand
}

type controlBand struct{ Control, Band string }

type controlCount struct {
	Control string
	Count   int
}

// issueRun is the run that produced the body. Empty fields are left out of the rendered table.
type issueRun struct {
	JobID, JobURL string
	Commits       []issueCommit
	Descriptor    string
	Version       string
}

type issueCommit struct{ Revision, Repository string }

// newIssueBody gathers what one part's body shows.
func newIssueBody(data report.Data, scope string, entry issueEntry, part issuePart) issueBody {
	b := issueBody{
		Marker:      issueMarker(data.ProjectName(), scope, entry, part),
		Failing:     part.failingTotal(),
		Accepted:    part.Accepted,
		Gate:        gateFor(data.Gate, part),
		Incomplete:  data.Incomplete,
		Errors:      part.Errors,
		Run:         runOf(data),
		ClosesOn:    entry.ClosesOn,
		MinPriority: entry.MinPriority,
	}
	// A part split by control is one control, named in the title, so a line counting it would
	// repeat the verdict.
	for control, n := range part.Failing {
		if n > 0 && part.Split != splitControl {
			b.Controls = append(b.Controls, controlCount{control, n})
		}
	}
	sort.Slice(b.Controls, func(i, j int) bool {
		if b.Controls[i].Count != b.Controls[j].Count {
			return b.Controls[i].Count > b.Controls[j].Count
		}
		return b.Controls[i].Control < b.Controls[j].Control
	})
	for _, a := range report.ActionsFor(part.Reports) {
		if atOrAbove(a.Priority, entry.MinPriority) {
			b.Actions = append(b.Actions, a)
		}
	}
	return b
}

// gateFor is the gate in the vocabulary it asks in, with the overrides of the controls this part
// covers.
func gateFor(g report.GateSettings, part issuePart) issueGate {
	covered := map[string]bool{}
	for c := range part.Reports {
		covered[c] = true
	}
	for _, e := range part.Errors {
		covered[e.Control] = true
	}
	policy := report.Data{Gate: g}.GateForReport().Policy
	out := issueGate{Default: policy.PriorityBand()}
	overrides := g.PerControlBand
	if policy.GatesOnSeverity() {
		out.Default = string(g.Threshold)
		overrides = make(map[string]string, len(g.PerControl))
		for c, sev := range g.PerControl {
			overrides[c] = string(sev)
		}
	}
	for _, c := range sortedKeys(overrides) {
		if covered[c] && overrides[c] != "" && overrides[c] != out.Default {
			out.Overrides = append(out.Overrides, controlBand{c, overrides[c]})
		}
	}
	return out
}

// runOf is the job, commits, descriptor and version the run records.
func runOf(data report.Data) issueRun {
	var r issueRun
	if data.CI != nil {
		r.JobID, r.JobURL = data.CI.RunID, data.CI.URL
	}
	for _, repo := range data.Repositories {
		if repo.Revision == "" {
			continue
		}
		rev := repo.Revision
		if len(rev) > 7 {
			rev = rev[:7]
		}
		r.Commits = append(r.Commits, issueCommit{rev, repositoryName(repo.URL)})
	}
	if data.Descriptor != nil {
		r.Descriptor = data.Descriptor.Digest
		if algo, hex, ok := strings.Cut(r.Descriptor, ":"); ok && len(hex) > 12 {
			r.Descriptor = algo + ":" + hex[:12]
		}
	}
	r.Version = data.Version
	return r
}

// repositoryName is the owner and name at the end of a repository URL.
func repositoryName(url string) string {
	s := strings.TrimSuffix(url, ".git")
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	parts := strings.Split(strings.Trim(s, "/"), "/")
	if len(parts) > 2 {
		parts = parts[len(parts)-2:]
	}
	return strings.Join(parts, "/")
}

// issueFormat is how a body is written. The body's structure lives once, in render, and a format
// only spells it.
type issueFormat interface {
	// text is scanner or author text, safe to place anywhere but the start of a line.
	text(s string) string
	// code is an identifier in a code span.
	code(s string, inTable bool) string
	link(label, url string) string
	bold(s string) string
	para(s string) string
	heading(s string) string
	table(head []string, rows [][]string) string
	list(items []string) string
	details(summary, body string) string
	rule() string
	// separator joins blocks.
	separator() string
}

// markdownFormat writes the Markdown every forge renders. Every line it emits starts with a
// character it wrote, so no line can start with scanner text and run as a GitLab quick action.
type markdownFormat struct{}

func (markdownFormat) text(s string) string               { return mdText(s) }
func (markdownFormat) code(s string, inTable bool) string { return mdCode(s, inTable) }
func (markdownFormat) link(label, url string) string      { return "[" + label + "](" + url + ")" }
func (markdownFormat) bold(s string) string               { return "**" + s + "**" }
func (markdownFormat) para(s string) string               { return s }
func (markdownFormat) heading(s string) string            { return "### " + s }
func (markdownFormat) rule() string                       { return "---" }
func (markdownFormat) separator() string                  { return "\n\n" }

func (markdownFormat) table(head []string, rows [][]string) string {
	lines := []string{"| " + strings.Join(head, " | ") + " |", strings.Repeat("|---", len(head)) + "|"}
	for _, r := range rows {
		lines = append(lines, "| "+strings.Join(r, " | ")+" |")
	}
	return strings.Join(lines, "\n")
}

func (markdownFormat) list(items []string) string {
	lines := make([]string, len(items))
	for i, it := range items {
		lines[i] = "- " + it
	}
	return strings.Join(lines, "\n")
}

func (markdownFormat) details(summary, body string) string {
	return "<details><summary>" + summary + "</summary>\n\n" + body + "\n\n</details>"
}

// htmlCode is an identifier in a `<code>` element. A forge links no mention or reference inside
// one, so the text is escaped and not broken.
func htmlCode(s string) string { return "<code>" + html.EscapeString(flatten(s)) + "</code>" }

// render writes the body in a format, within a budget of characters.
//
// Every action stays listed while it can. Over the budget, the lowest-priority actions, which are
// the last, lose their findings tables first; if the list alone is still over, the last actions
// are left out and a line says how many and where the full list is.
func (b issueBody) render(f issueFormat, budget int) string {
	if b.Child != nil && b.Child.Action != nil {
		return b.renderAction(f, budget)
	}
	head := b.head(f)
	tail := b.tail(f)
	full := make([]string, len(b.Actions))
	short := make([]string, len(b.Actions))
	for i, a := range b.Actions {
		full[i] = b.action(f, a)
		short[i] = f.list([]string{actionSummary(a)})
	}
	shown := append([]string(nil), full...)
	stripped, omitted := 0, 0

	// assemble is the body as it stands, measured and returned by the same code so the two cannot
	// disagree.
	assemble := func() []string {
		listed := shown[:len(shown)-omitted]
		blocks := append([]string(nil), head...)
		if len(listed) > 0 || b.Lead != "" {
			blocks = append(blocks, f.heading("Actions"))
		}
		if b.Lead != "" {
			blocks = append(blocks, f.para(b.Lead))
		}
		blocks = append(blocks, listed...)
		if n := stripped - omitted; n == 1 {
			blocks = append(blocks, f.para("Findings of the last action are left out for size, and listed in "+b.runRef(f)+"."))
		} else if n > 1 {
			blocks = append(blocks, f.para(fmt.Sprintf("Findings of the last %d actions are left out for size, and listed in %s.",
				n, b.runRef(f))))
		}
		if omitted > 0 {
			blocks = append(blocks, f.para(fmt.Sprintf("And %d more %s, left out for size, listed in %s.",
				omitted, english.Noun(omitted, "action"), b.runRef(f))))
		}
		return append(blocks, tail...)
	}
	size := func() int { return joinedSize(f, assemble()) }
	for i := len(shown) - 1; i >= 0 && size() > budget; i-- {
		shown[i] = short[i]
		stripped++
	}
	for omitted < len(shown) && size() > budget {
		omitted++
	}
	return strings.Join(assemble(), f.separator())
}

// joinedSize is the length of blocks joined by the format's separator, in characters.
func joinedSize(f issueFormat, blocks []string) int {
	n := (len(blocks) - 1) * utf8.RuneCountInString(f.separator())
	for _, s := range blocks {
		n += utf8.RuneCountInString(s)
	}
	return n
}

// renderAction writes a child per action: its line, the scanner's description, and its findings
// table, cut to the budget from the least urgent finding, which is the last.
func (b issueBody) renderAction(f issueFormat, budget int) string {
	a := *b.Child.Action
	head := b.head(f)
	tail := b.tail(f)
	rows := make([][]string, len(a.Findings))
	for i, af := range a.Findings {
		rows[i] = findingRow(f, af)
	}
	shown := len(rows)
	same := 0
	if a.OneChange && shown > oneChangeRows {
		same = shown - oneChangeRows
		shown = oneChangeRows
	}
	cut := 0
	assemble := func() []string {
		blocks := append([]string(nil), head...)
		if a.Summary != "" {
			blocks = append(blocks, "<p>"+htmlText(a.Summary)+"</p>")
		}
		if n := shown - cut; n > 0 {
			blocks = append(blocks, f.heading("Findings"), f.table([]string{"Priority", "Finding", "Where"}, rows[:n]))
		}
		if same > 0 {
			blocks = append(blocks, f.para(fmt.Sprintf("And %d more, cleared by the same action.", same)))
		}
		if cut > 0 {
			blocks = append(blocks, f.para(fmt.Sprintf("And %d more, left out for size, listed in %s.", cut, b.runRef(f))))
		}
		return append(blocks, tail...)
	}
	for cut < shown && joinedSize(f, assemble()) > budget {
		cut++
	}
	return strings.Join(assemble(), f.separator())
}

// head is the marker, the verdict, the failing controls and any errors. A child's is the marker,
// its priority for the next run to compare, and its own line.
func (b issueBody) head(f issueFormat) []string {
	blocks := []string{b.Marker}
	if c := b.Child; c != nil {
		line := []string{}
		if c.Priority != "" {
			blocks = append(blocks, priorityPrefix+c.Priority+" -->")
			line = append(line, f.bold(c.Priority))
		}
		if c.Control != "" {
			line = append(line, f.code(c.Control, false))
		}
		line = append(line, english.Count(c.Clears, "finding"), "gate "+c.Gate)
		if c.Action != nil && len(c.Action.FixedVersions) > 0 {
			fixed := make([]string, len(c.Action.FixedVersions))
			for i, v := range c.Action.FixedVersions {
				fixed[i] = f.code(v, false)
			}
			line = append(line, "fixed in "+strings.Join(fixed, ", "))
		}
		return append(blocks, f.para(strings.Join(line, " · ")))
	}

	verdict := []string{f.bold(failingPhrase(b.Failing))}
	gate := "gate " + b.Gate.Default
	for _, o := range b.Gate.Overrides {
		gate += ", " + o.Band + " for " + f.code(o.Control, false)
	}
	verdict = append(verdict, gate)
	if b.Accepted > 0 {
		verdict = append(verdict, fmt.Sprintf("%d accepted", b.Accepted))
	}
	if b.Incomplete {
		verdict = append(verdict, "incomplete")
	}
	blocks = append(blocks, f.para(strings.Join(verdict, " · ")))

	if len(b.Controls) > 0 {
		counts := make([]string, len(b.Controls))
		for i, c := range b.Controls {
			counts[i] = fmt.Sprintf("%s %d", f.code(c.Control, false), c.Count)
		}
		blocks = append(blocks, f.para(strings.Join(counts, " · ")))
	}

	if len(b.Errors) > 0 {
		items := make([]string, len(b.Errors))
		for i, e := range b.Errors {
			items[i] = f.code(e.Control, false) + ": " + f.text(e.Message)
		}
		blocks = append(blocks, f.heading("Errors"), f.list(items))
	}
	return blocks
}

// tail is the run, how to accept a finding, and when the item closes.
func (b issueBody) tail(f issueFormat) []string {
	var blocks []string

	var head []string
	var row []string
	if b.Run.JobURL != "" || b.Run.JobID != "" {
		head = append(head, "Job")
		row = append(row, b.jobCell(f))
	}
	if len(b.Run.Commits) > 0 {
		cells := make([]string, len(b.Run.Commits))
		for i, c := range b.Run.Commits {
			cells[i] = f.code(c.Revision, true)
			if len(b.Run.Commits) > 1 && c.Repository != "" {
				cells[i] += " " + f.text(c.Repository)
			}
		}
		head = append(head, "Commit")
		row = append(row, strings.Join(cells, "<br>"))
	}
	if b.Run.Descriptor != "" {
		head = append(head, "Descriptor")
		row = append(row, f.code(b.Run.Descriptor, true))
	}
	if b.Run.Version != "" {
		head = append(head, "Draugr")
		row = append(row, f.code(b.Run.Version, true))
	}
	if len(head) > 0 {
		blocks = append(blocks, f.heading("Run"), f.table(head, [][]string{row}))
	}

	blocks = append(blocks, f.heading("Accept"), f.para("A "+f.link(f.code("config.exclude", false), acceptDocs)+
		" entry in the descriptor accepts a finding. It stays in the report, marked accepted."))

	closes := "Closes itself when the gate passes on " + b.branches(f)
	if b.MinPriority != "" {
		closes += " or no finding at or above " + b.MinPriority + " fails it"
	}
	switch {
	case b.Child != nil && b.Child.Action != nil:
		closes += ", or when a run no longer reports this action"
	case b.Child != nil:
		closes += ", or when a run no longer reports an action for this control"
	}
	return append(blocks, f.rule(), f.para(closes+"."))
}

// branches names the branches whose passing run closes the item.
func (b issueBody) branches(f issueFormat) string {
	if len(b.ClosesOn) == 0 {
		return "the default branch"
	}
	names := make([]string, len(b.ClosesOn))
	for i, br := range b.ClosesOn {
		names[i] = f.code(br, false)
	}
	if len(names) == 1 {
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + " or " + names[len(names)-1]
}

// jobCell is the job, linked when the run recorded where it is.
func (b issueBody) jobCell(f issueFormat) string {
	label := b.Run.JobID
	if label == "" {
		label = "job"
	}
	if u := safeURL(b.Run.JobURL); u != "" {
		return f.link(f.text(label), u)
	}
	return f.text(label)
}

// runRef is where the full list of actions can be read.
func (b issueBody) runRef(f issueFormat) string {
	if u := safeURL(b.Run.JobURL); u != "" {
		label := "the job"
		if b.Run.JobID != "" {
			label = "job " + b.Run.JobID
		}
		return f.link(f.text(label), u)
	}
	return "the scan report"
}

// action is one action, collapsed: the summary line, the rule's description, and its findings.
func (b issueBody) action(f issueFormat, a report.Action) string {
	var parts []string
	if a.Summary != "" {
		// An HTML paragraph in either format, so the line starts with a tag Draugr wrote.
		parts = append(parts, "<p>"+htmlText(a.Summary)+"</p>")
	}
	findings := a.Findings
	rest := 0
	if a.OneChange && len(findings) > oneChangeRows {
		rest = len(findings) - oneChangeRows
		findings = findings[:oneChangeRows]
	}
	rows := make([][]string, len(findings))
	for i, af := range findings {
		rows[i] = findingRow(f, af)
	}
	parts = append(parts, f.table([]string{"Priority", "Finding", "Where"}, rows))
	if rest > 0 {
		parts = append(parts, f.para(fmt.Sprintf("And %d more, cleared by the same action.", rest)))
	}
	return f.details(actionSummary(a), strings.Join(parts, f.separator()))
}

// actionSummary is an action's summary line, in HTML because a forge does not parse Markdown
// inside `<summary>`.
func actionSummary(a report.Action) string {
	var s string
	if a.Priority != "" {
		s = "<b>" + html.EscapeString(a.Priority) + "</b> "
	}
	s += htmlText(a.Title)
	if a.Control != "" {
		s += " · " + htmlCode(a.Control)
	}
	return s + " · " + english.Count(a.Clears, "finding")
}

// findingRow is one finding: its band, the rule and message, and where it is.
func findingRow(f issueFormat, af report.ActionFinding) []string {
	band := strings.TrimSpace(af.Priority + " " + string(af.Severity))

	finding := f.text(af.Message)
	if af.RuleID != "" {
		rule := f.code(af.RuleID, true)
		if u := safeURL(af.HelpURI); u != "" {
			rule = f.link(rule, u)
		}
		if af.Message != "" {
			rule += "<br>" + finding
		}
		finding = rule
	}

	var who []string
	if af.Component != "" {
		who = append(who, f.code(af.Component, true))
	}
	if af.Tool != "" {
		who = append(who, f.text(af.Tool))
	}
	where := strings.Join(who, " · ")
	if af.Location != "" {
		if where != "" {
			where += "<br>"
		}
		where += f.code(af.Location, true)
	}
	return []string{f.text(band), finding, where}
}

func failingPhrase(n int) string {
	switch n {
	case 0:
		return "No finding fails the gate"
	case 1:
		return "1 finding fails the gate"
	}
	return fmt.Sprintf("%d findings fail the gate", n)
}

// withoutRun is a rendered body without its Run section, which names the run that last wrote it.
// Two bodies that differ only there describe the same findings, and rewriting one would notify
// everybody watching the item for nothing.
func withoutRun(f issueFormat, body string) string {
	body = strings.ReplaceAll(body, "\r\n", "\n")
	start := strings.Index(body, f.heading("Run"))
	end := strings.Index(body, f.heading("Accept"))
	if start >= 0 && end > start {
		body = body[:start] + body[end:]
	}
	return strings.TrimSpace(body)
}

// bodyChanged reports whether a rendered body describes something the item's current body does
// not.
func bodyChanged(f issueFormat, current, next string) bool {
	return withoutRun(f, current) != withoutRun(f, next)
}
