package report

import (
	"cmp"
	"fmt"
	"io"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/draugr-dev/draugr/internal/english"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/skald"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// The run's shortfalls, in two blocks, because they mean different things to the verdict.
//
// A target no scanner could read is an error: it is what makes a run incomplete, and the run fails
// unless --allow-scan-errors accepted it. It is said once, by target, with the components it leaves
// unscanned, rather than once per control that tried, which at scale is the same missing repository
// repeated under every control that reads repositories.
//
// A caveat does not fail the run: a declared surface no enabled control looks at, a file a scan with
// no descriptor found whose scanner could not run here, a scanner that cannot honor a component's
// scope, a dependency file inside a repository that was read. Each makes the run cover less than it
// appears to, so each is shown, in every view, apart from the errors.

// errorRowsShown caps both blocks, as the findings are capped: --top 0 shows every row.
const errorRowsShown = 10

// whyWidth keeps a row's reason to one line beside its other columns. The whole of it is in
// --format json.
const whyWidth = 80

// notReached is the run's targets every scanner tried and failed to read, by kind in the order a
// descriptor declares them and then by address, so twenty images from one registry that is down
// sit together. A target no scanner was run for is a caveat, under `not-measured`, because nothing
// failed.
func notReached(d Data) []engine.TargetOutcome {
	var out []engine.TargetOutcome
	for _, t := range d.Run.Targets {
		if t.Status == engine.TargetFailed {
			out = append(out, t)
		}
	}
	rank := func(kind string) int {
		if i := slices.Index(kindOrder, kind); i >= 0 {
			return i
		}
		return len(kindOrder)
	}
	slices.SortStableFunc(out, func(a, b engine.TargetOutcome) int {
		if c := cmp.Compare(rank(a.Kind), rank(b.Kind)); c != 0 {
			return c
		}
		return cmp.Compare(a.Target, b.Target)
	})
	return out
}

// kindOrder is the order a component declares its targets in.
var kindOrder = []string{"repository", "image", "host", "cluster", "account", "file"}

// bareFailure matches a clause that says something failed and not what.
var bareFailure = regexp.MustCompile(`^(?i:fatal|error|exit status \d+)$`)

// identifierOnly matches a clause that is only an identifier: a UUID, a request id, a digest.
var identifierOnly = regexp.MustCompile(`^(?:sha256:)?[0-9a-fA-F]{8,}(?:-[0-9a-fA-F]{4,})*$`)

// quotedSpan matches a single-quoted address or path inside a clause.
var quotedSpan = regexp.MustCompile(`'[^']*'`)

// kubeForbidden matches the Kubernetes API server's refusal of a request: `User "<identity>" cannot
// <verb> resource "<resource>" in API group "<group>"`, then `at the cluster scope` or `in the
// namespace "<namespace>"`. The identity is quoted the way Go quotes a string.
var kubeForbidden = regexp.MustCompile(
	`User "(?:[^"\\]|\\.)*" cannot (\S+) resource "([^"]*)" in API group "([^"]*)" (at the cluster scope|in the namespace "[^"]*")`)

// kubeRefusal says what a Kubernetes refusal withheld, from kubeForbidden's match: "cannot list
// clusterrolebindings (rbac.authorization.k8s.io) at the cluster scope". The core API group is
// named by an empty string, which is left out rather than shown as "()".
func kubeRefusal(m []string) string {
	verb, resource, group, where := m[1], m[2], m[3], m[4]
	if group != "" {
		resource += " (" + group + ")"
	}
	return "cannot " + verb + " " + resource + " " + where
}

// shortReason is the part of a failure that says what went wrong, in the scanner's words: its last
// clause, or the one before when the last only repeats the address. "git clone: exit status 128:
// remote: Repository not found. fatal: repository 'https://…' not found" says "Repository not
// found". The whole message is in --format json.
func shortReason(detail string, width int) string {
	line := strings.Join(strings.Fields(detail), " ")
	// The API server's refusal opens with the identity the request was made as, which the reader
	// chose when they ran the scan and which can take most of the width. What they have to grant is
	// the verb, the resource, its API group and where, so the reason is those.
	if m := kubeForbidden.FindStringSubmatch(line); m != nil {
		return truncate(kubeRefusal(m), width)
	}
	parts := strings.Split(line, ": ")
	reason := strings.TrimSpace(parts[len(parts)-1])
	// A registry closes its refusal with a reference for its own logs, "CorrelationId: 5bf38f62-…",
	// which identifies the request and says nothing about it. The clause before says what went
	// wrong, less the label of the reference.
	if identifierOnly.MatchString(reason) && len(parts) > 1 {
		prev := strings.TrimSpace(parts[len(parts)-2])
		if k := strings.LastIndex(prev, ". "); k > 0 && !strings.Contains(prev[k+2:], " ") {
			prev = prev[:k]
		}
		// "…, visit https://… for more information" points somewhere else for the reason.
		var kept []string
		for _, c := range strings.Split(prev, ", ") {
			if strings.Contains(c, "://") {
				break
			}
			kept = append(kept, c)
		}
		if len(kept) > 0 {
			prev = strings.Join(kept, ", ")
		}
		return truncate(strings.TrimSuffix(prev, "."), width)
	}
	if (strings.Contains(reason, "://") || strings.Contains(reason, "'")) && len(parts) > 1 {
		prev := strings.TrimSpace(parts[len(parts)-2])
		if k := strings.Index(prev, ". "); k > 0 {
			prev = prev[:k]
		}
		// The clause before can be git's `fatal` or an exit status, which say only that it failed.
		// The last clause then carries the meaning, with the address taken out.
		if bareFailure.MatchString(prev) {
			reason = strings.Join(strings.Fields(quotedSpan.ReplaceAllString(reason, "")), " ")
		} else {
			reason = prev
		}
	}
	return truncate(strings.TrimSuffix(reason, "."), width)
}

// targetError reports whether a control's error is a failure to reach a target, which the errors
// block says once, by target, instead of under every control that tried.
func targetError(d Data, control, msg string) bool {
	for _, f := range d.Run.Stats.Failures {
		if f.Control == control && strings.TrimSpace(msg) == f.Detail {
			return true
		}
	}
	return false
}

// caveat is one shortfall in what the run covered. It fails the run only when the gate lists its
// key in failOnCaveats.
type caveat struct {
	component, what, detail string
	// key is the kind as gate.failOnCaveats names it, and the word the console's group heading
	// opens with, so a reader who wants a kind to fail the run copies it from there into the setting.
	key saga.CaveatKind
	// by is what detail closes with in parentheses: the controls whose reason it is. Empty for a
	// caveat that names none. The console says it once, in the group heading, and drops it from
	// each row.
	by string
	// folded says the row stands for several files, which --evidence names one by one.
	folded bool
	// byReason says the console folded the row from several files of one reason, which --top 0
	// names one by one.
	byReason bool
	// controls are the controls the caveat concerns, where it names any. locations are the files or
	// image it names, by their own paths: what is a label, shortened or folded for a reader.
	controls  []string
	locations []sarif.NotificationLocation
	// repository says the caveat is about a repository rather than a component, so its heading
	// names no component.
	repository bool
}

// unreadDetail is a service's row: the checks with no result, the checks read in part, and the
// denial, as `1 check unread · 4 checks partly read · denied s3:GetAccountPublicAccessBlock`.
func unreadDetail(g engine.UnreadChecks) string {
	var parts []string
	if len(g.Checks) > 0 {
		parts = append(parts, english.Count(len(g.Checks), "check")+" unread")
	}
	if len(g.PartlyRead) > 0 {
		parts = append(parts, english.Count(len(g.PartlyRead), "check")+" partly read")
	}
	return strings.Join(append(parts, g.Reason), " · ")
}

// caveats gathers what was declared and not checked, the files whose scanner could not run, what
// could not be measured, and the files and checks that were not read, by component.
func caveats(d Data) []caveat {
	var out []caveat
	for _, g := range d.Uncovered {
		out = append(out, caveat{component: g.Component, what: g.Surface,
			detail: "controls off: " + strings.Join(g.Controls, ", "), key: saga.CaveatNotChecked,
			controls: g.Controls})
	}
	for _, u := range d.Unexamined {
		c := caveat{component: u.Component, what: u.Files, detail: u.Why, key: saga.CaveatNotChecked}
		for _, p := range u.Paths {
			c.locations = append(c.locations, sarif.NotificationLocation{URI: p})
		}
		out = append(out, c)
	}
	for _, sk := range d.Run.Skipped {
		out = append(out, caveat{component: sk.Component, what: sk.Scanner, detail: sk.Reason, key: saga.CaveatNotMeasured,
			controls: []string{sk.Control}})
	}
	// A service's checks the scan could not evaluate, one row per service, because one granted
	// permission clears all of them. The control is not named: the service says which one it is.
	for _, g := range d.Run.UnreadChecks {
		out = append(out, caveat{component: g.Component, what: g.Group, detail: unreadDetail(g),
			key: saga.CaveatUnreadChecks, controls: []string{g.Control}})
	}
	// An imported file that names no revision: read, but nothing shows it describes the code this
	// run scanned.
	for _, u := range unboundImports(d) {
		out = append(out, caveat{component: u.component, what: u.file,
			detail: "names no commit, so nothing ties its findings to this code", key: saga.CaveatUnboundImports,
			controls: u.controls, locations: []sarif.NotificationLocation{{URI: u.file}}})
	}
	out = append(out, uncommittedCaveats(d.Repositories)...)
	for _, g := range unreadByComponent(d.Run.Inputs, d.Run.Targets) {
		for _, r := range unreadRows(g) {
			by := strings.Join(r.controls, ", ")
			c := caveat{component: g.component, what: r.what,
				detail: fmt.Sprintf("%s (%s)", r.reason, by), key: saga.CaveatUnreadFiles, by: by,
				folded: len(r.files) > 0, controls: r.controls}
			for _, f := range r.places {
				c.locations = append(c.locations, sarif.NotificationLocation{URI: f.path, Repository: f.repository})
			}
			out = append(out, c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].component < out[j].component })
	return out
}

// uncommittedCaveats is a row for each local repository whose uncommitted changes the scan did not
// read, because it read the committed revision.
//
// A caveat because it is the shortfall a reader does not expect: they fix a finding, scan again,
// and the finding is still there. Named by repository only where more than one has changes left
// out, since one row with a name nobody needs pushes the reason along the line.
func uncommittedCaveats(repos []RepositoryProvenance) []caveat {
	var dirty []RepositoryProvenance
	for _, r := range repos {
		if !r.WorkingTree && r.Uncommitted > 0 {
			dirty = append(dirty, r)
		}
	}
	out := make([]caveat, 0, len(dirty))
	for _, r := range dirty {
		what := english.Count(r.Uncommitted, "uncommitted file")
		if len(dirty) > 1 {
			what = repositoryName(r.URL) + ": " + what
		}
		detail := "not in the committed revision"
		if rev := r.Short(); rev != "" {
			detail = "not in commit " + rev
		}
		out = append(out, caveat{what: what, detail: detail + " · --working-tree reads them",
			key: saga.CaveatUncommittedFiles, repository: true})
	}
	return out
}

// cleanRunLine is what a run with no findings and no control in error closes on, in every human
// format, and whether it closes on a tick.
//
// A caveat is a part of the run that was not checked, so a tick after one would read as a clean
// result for that part too. Uncommitted files left out are the exception that says where the tick
// stops: the run did check the commit, and a developer's checkout nearly always holds an
// uncommitted file, so withholding the tick would take it from nearly every local clean run. The
// line names the commit instead, which the caveat above says the files are not in. A gate that
// fails on uncommitted-files gets no tick.
func cleanRunLine(d Data) (line string, tick bool) {
	cs := caveats(d)
	if len(cs) == 0 {
		return "No findings. ✓", true
	}
	var dirty []RepositoryProvenance
	for _, c := range cs {
		if c.key != saga.CaveatUncommittedFiles || c.fails(d) {
			return noFindingsWithCaveats, false
		}
	}
	for _, r := range d.Repositories {
		if !r.WorkingTree && r.Uncommitted > 0 {
			dirty = append(dirty, r)
		}
	}
	if len(dirty) == 1 && dirty[0].Short() != "" {
		return "No findings in commit " + dirty[0].Short() + ". ✓", true
	}
	return "No findings in what is committed. ✓", true
}

// reason is detail without the controls it closes with, which the console's group heading names.
func (c caveat) reason() string {
	if c.by == "" {
		return c.detail
	}
	r, _ := strings.CutSuffix(c.detail, " ("+c.by+")")
	return r
}

// heading is what every caveat in a console group shares: its kind, its controls where it names
// any, and its component, as `unread-files · licenses, sca · server`. A caveat no component claims
// is headed `no component`, as the HTML report groups it.
func (c caveat) heading() string {
	return joinSlots(c.headingSlots(), func(int) bool { return true })
}

// headingSlots are a group heading's fields in the order it names them: the kind, the controls,
// and the component. A field the caveat does not name is empty: the controls of a caveat that names
// none, the component of one about a repository.
func (c caveat) headingSlots() [3]string {
	s := [3]string{string(c.key), c.by, cmp.Or(c.component, "no component")}
	if c.repository {
		s[2] = ""
	}
	return s
}

// joinSlots names the heading fields keep selects, as a heading does.
func joinSlots(s [3]string, keep func(int) bool) string {
	var parts []string
	for i, v := range s {
		if v != "" && keep(i) {
			parts = append(parts, v)
		}
	}
	return strings.Join(parts, " · ")
}

// sharedSlots reports which heading fields hold one value in every group, which the console says
// once over the block instead of on each heading. With one group there is nothing to say once, and
// a group whose own heading would be left empty keeps the whole of it.
func sharedSlots(groups []shownGroup) (shared [3]bool, ok bool) {
	if len(groups) < 2 {
		return shared, false
	}
	first := groups[0].rows[0].headingSlots()
	for i := range first {
		shared[i] = first[i] != ""
		for _, g := range groups[1:] {
			if g.rows[0].headingSlots()[i] != first[i] {
				shared[i] = false
			}
		}
		ok = ok || shared[i]
	}
	if !ok {
		return shared, false
	}
	for _, g := range groups {
		if joinSlots(g.rows[0].headingSlots(), func(i int) bool { return !shared[i] }) == "" {
			return shared, false
		}
	}
	return shared, true
}

// sameGroup reports whether two caveats sit under one heading.
func sameGroup(a, b caveat) bool { return compareGroups(a, b) == 0 }

// compareGroups orders caveats by kind, in the order the setting lists the kinds, then by
// controls, then by component.
func compareGroups(a, b caveat) int {
	return cmp.Or(cmp.Compare(kindRank(a.key), kindRank(b.key)), cmp.Compare(a.by, b.by),
		cmp.Compare(a.component, b.component))
}

// kindRank is a kind's place in saga.CaveatKinds, with an unknown kind last.
func kindRank(k saga.CaveatKind) int {
	if i := slices.Index(saga.CaveatKinds, k); i >= 0 {
		return i
	}
	return len(saga.CaveatKinds)
}

// shownGroup is one group of the console's caveats: the rows it draws and how many it leaves out.
type shownGroup struct {
	rows []caveat
	left int
}

// shownCaveatGroups is the run's caveats in the groups the console draws, each cut to the rows the
// block draws. The cut is per group: every group keeps its first row, so a kind, a control or a
// component is never left out of the block whole, and the rest of the block's rows go to the groups
// one row at a time, so the largest group gives up the most. --top 0 draws every row.
func shownCaveatGroups(d Data) []shownGroup {
	cs := caveats(d)
	slices.SortStableFunc(cs, compareGroups)
	if consoleFixFirstLimit(d.TopN) >= 0 {
		cs = foldUnreadByReason(d, cs)
	}
	var groups []shownGroup
	for i := 0; i < len(cs); {
		j := i
		for j < len(cs) && sameGroup(cs[j], cs[i]) {
			j++
		}
		groups = append(groups, shownGroup{rows: cs[i:j]})
		i = j
	}
	if n, _ := shownRows(d, len(cs)); n == len(cs) {
		return groups
	}
	take := make([]int, len(groups))
	budget := errorRowsShown - len(groups)
	for i := range take {
		take[i] = 1
	}
	for gave := true; budget > 0 && gave; {
		gave = false
		for i, g := range groups {
			if budget > 0 && take[i] < len(g.rows) {
				take[i]++
				budget--
				gave = true
			}
		}
	}
	for i := range groups {
		groups[i].left = len(groups[i].rows) - take[i]
		groups[i].rows = groups[i].rows[:take[i]]
	}
	return groups
}

// shownCaveats is the rows the console's caveats block draws, in its order, and how many it leaves
// out across its groups.
func shownCaveats(d Data) (shown []caveat, left int) {
	for _, g := range shownCaveatGroups(d) {
		shown = append(shown, g.rows...)
		left += g.left
	}
	return shown, left
}

// foldUnreadByReason folds a group's unread files that share a reason into fewer rows, for a console
// that lists the first rows of each block. A reader acts on the reason and how many files it covers,
// and a column of paths that differ only below a testdata directory pushes the findings off the
// screen. --top 0 and every report still name each file.
//
// A caveat the gate fails on keeps a row per file, because each of those files has to be read or
// set aside before the run passes, and the row is where its path is.
func foldUnreadByReason(d Data, cs []caveat) []caveat {
	out := make([]caveat, 0, len(cs))
	for i := 0; i < len(cs); {
		j := i
		for j < len(cs) && sameGroup(cs[j], cs[i]) {
			j++
		}
		group := cs[i:j]
		i = j
		if group[0].key != saga.CaveatUnreadFiles || group[0].fails(d) {
			out = append(out, group...)
			continue
		}
		var order []string
		byReason := map[string][]caveat{}
		for _, c := range group {
			r := c.reason()
			if c.folded {
				r = "\x00" + c.what
			}
			if _, seen := byReason[r]; !seen {
				order = append(order, r)
			}
			byReason[r] = append(byReason[r], c)
		}
		for _, r := range order {
			same := byReason[r]
			if len(same) < 2 {
				out = append(out, same...)
				continue
			}
			out = append(out, reasonRows(same)...)
		}
	}
	return out
}

// reasonRows is the row standing for several files of one group that share a reason.
func reasonRows(same []caveat) []caveat {
	c := same[0]
	c.what = english.Count(len(same), "file")
	c.byReason = true
	c.locations = nil
	for _, s := range same {
		c.locations = append(c.locations, s.locations...)
	}
	return []caveat{c}
}

// foldedByReason reports whether the console drew a row standing for several files of one reason.
func foldedByReason(shown []caveat) bool {
	return slices.ContainsFunc(shown, func(c caveat) bool { return c.byReason })
}

// fails reports whether the gate lists this caveat's kind in failOnCaveats.
func (c caveat) fails(d Data) bool { return slices.Contains(d.FailOnCaveats, c.key) }

// caveatGroup is one component's caveats, in the order caveats lists them.
type caveatGroup struct {
	component string
	caveats   []caveat
}

// caveatsByComponent folds the run's caveats under their components, which is how the HTML and
// markdown reports list them. caveats sorts by component, so each group is a run of rows.
func caveatsByComponent(cs []caveat) []caveatGroup {
	var out []caveatGroup
	for _, c := range cs {
		if n := len(out); n > 0 && out[n-1].component == c.component {
			out[n-1].caveats = append(out[n-1].caveats, c)
			continue
		}
		out = append(out, caveatGroup{component: c.component, caveats: []caveat{c}})
	}
	return out
}

// caveatSetting names the setting that makes a caveat fail the run and the kinds it lists, in the
// words every format prints: `config.gate.failOnCaveats: unread-files`.
func caveatSetting(d Data) string {
	return fmt.Sprintf("%s: %s", cmp.Or(d.FailOnCaveatsFrom, "config.gate.failOnCaveats"),
		strings.Join(namesOfKinds(d.FailOnCaveats), ", "))
}

// splitCaveats divides the run's caveats into the ones the gate fails on and the rest.
func splitCaveats(d Data) (failing, rest []caveat) {
	for _, c := range caveats(d) {
		if c.fails(d) {
			failing = append(failing, c)
		} else {
			rest = append(rest, c)
		}
	}
	return failing, rest
}

// FailedCaveat is a caveat whose kind the gate lists in failOnCaveats. Declared in skald, which
// writes it into report.json.
type FailedCaveat = skald.FailedCaveat

// FailedCaveats returns the run's caveats of the kinds d.FailOnCaveats lists, by component.
func FailedCaveats(d Data) []FailedCaveat {
	failing, _ := splitCaveats(d)
	out := make([]FailedCaveat, 0, len(failing))
	for _, c := range failing {
		out = append(out, FailedCaveat{Component: c.component, What: c.what, Kind: c.key, Detail: c.detail})
	}
	return out
}

// caveatsOfKinds returns the run's not-checked and unbound-imports caveats, every one whatever the
// gate does with it, in the shape report.json lists them. The engine's result holds the other kinds,
// and the document reads those from it.
func caveatsOfKinds(d Data) (notChecked []skald.NotChecked, unbound []skald.UnboundImport) {
	for _, c := range caveats(d) {
		switch c.key {
		case saga.CaveatNotChecked:
			nc := skald.NotChecked{Component: c.component, What: c.what, Controls: c.controls, Reason: c.reason()}
			for _, l := range c.locations {
				nc.Paths = append(nc.Paths, l.URI)
			}
			notChecked = append(notChecked, nc)
		case saga.CaveatUnboundImports:
			unbound = append(unbound, skald.UnboundImport{Component: c.component, File: c.what,
				Controls: c.controls, Reason: c.reason()})
		}
	}
	return notChecked, unbound
}

// shownRows is how many of n rows a block draws, and whether some were left out.
func shownRows(d Data, n int) (int, bool) {
	if consoleFixFirstLimit(d.TopN) < 0 || n <= errorRowsShown {
		return n, false
	}
	return errorRowsShown, true
}

// writeErrors draws the targets no scanner could read. Images a registry refused are grouped under
// that registry, with its answer and the command that changes it said once; every other target is
// a row of its own, with its reason.
func writeErrors(w io.Writer, col tui.Painter, d Data) {
	missed := notReached(d)
	if len(missed) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "%s  %s\n", heading(col, "Errors"), col.Paint(cFail,
		fmt.Sprintf("%d of %s not reached", len(missed), english.Count(len(d.Run.Targets), "target"))))
	n, capped := shownRows(d, len(missed))
	cols := tui.Columns(w)
	groups, rest := byRegistry(missed[:n])

	for _, g := range groups {
		_, _ = fmt.Fprintf(w, "  %s  %s\n", col.Paint(tui.StyleStrong, g.host), col.Paint(cDim, g.said))
		rows := make([]unreachedRow, len(g.images))
		for i, m := range g.images {
			rows[i] = unreachedRow{name: inRegistry(m.Target, g.host), components: m.Components}
		}
		writeUnreached(w, col, cols, "    ", "Image", rows)
		if g.login {
			_, _ = fmt.Fprintf(w, "  %s  %s\n", col.Paint(cAccent, loginCommand(g.host)), col.Paint(cDim, "then scan again"))
		}
		if g.local {
			for i, line := range wrapMessage(localAdvice, messageWidth) {
				prefix := "  "
				if i > 0 {
					prefix = "    "
				}
				_, _ = fmt.Fprintf(w, "%s%s\n", prefix, col.Paint(cDim, line))
			}
		}
	}
	if len(rest) > 0 {
		rows := make([]unreachedRow, len(rest))
		for i, m := range rest {
			rows[i] = unreachedRow{name: m.Kind + " " + shownTarget(m.Kind, m.Target), components: m.Components,
				why: shortReason(m.Detail, whyWidth)}
		}
		writeUnreached(w, col, cols, "  ", "Target", rows)
	}
	if capped {
		_, _ = fmt.Fprintf(w, "  %s\n", col.Paint(cDim,
			fmt.Sprintf("… and %d more · --top 0 lists every one", len(missed)-n)))
	}
	_, _ = fmt.Fprintln(w)
}

// unreachedRow is one target the errors block names: what it is, the components it leaves
// unscanned, and why it was not read where its group does not already say.
type unreachedRow struct {
	name       string
	components []string
	why        string
}

// writeUnreached draws rows as a table when the table fits a terminal cols wide, and otherwise each
// target on a line of its own with its components and reason on the line under it. A table cut to
// fit would cut the reason, which is the one column a reader needs whole, and the target's name is
// an address, useless shortened. A cols of zero is a file or a pipe, with no width to respect.
func writeUnreached(w io.Writer, col tui.Painter, cols int, indent, first string, rows []unreachedRow) {
	headers := []string{first, "Components"}
	withWhy := slices.ContainsFunc(rows, func(r unreachedRow) bool { return r.why != "" })
	if withWhy {
		headers = append(headers, "Why")
	}
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = utf8.RuneCountInString(h)
	}
	for _, r := range rows {
		widths[0] = max(widths[0], utf8.RuneCountInString(r.name))
		widths[1] = max(widths[1], utf8.RuneCountInString(strings.Join(r.components, ", ")))
		if withWhy {
			widths[2] = max(widths[2], utf8.RuneCountInString(r.why))
		}
	}
	natural := len(indent) + 2*(len(widths)-1)
	for _, n := range widths {
		natural += n
	}

	if cols > 0 && natural > cols {
		for _, r := range rows {
			below := componentsLabel(r.components)
			if r.why != "" {
				below += " · " + r.why
			}
			_, _ = fmt.Fprintf(w, "%s%s\n", indent, col.Paint(tui.StyleStrong, r.name))
			_, _ = fmt.Fprintf(w, "%s  %s\n", indent, col.Paint(cDim, truncate(below, max(cols-len(indent)-2, minBelow))))
		}
		return
	}
	t := tui.NewTable(col, headers...).Indent(indent)
	for _, r := range rows {
		cells := []tui.Cell{tui.Styled(tui.StyleStrong, r.name), tui.Styled(cDim, strings.Join(r.components, ", "))}
		if withWhy {
			cells = append(cells, tui.Styled(cDim, r.why))
		}
		t.Row(cells...)
	}
	t.Render(w)
}

// minBelow is the narrowest the line under a target is cut to, on a terminal too narrow for its
// indent: below that, a cut says less than a wrap does.
const minBelow = 40

// componentsLabel names a target's components with the word for them, for a line that has no
// column heading to say what they are.
func componentsLabel(cs []string) string {
	return english.Choose(len(cs), "component", "components") + " " + strings.Join(cs, ", ")
}

// writeCaveats draws a row per shortfall in what the run covered, under a heading per kind,
// controls and component.
//
// One block for every caveat, the ones the gate fails on among them, each marked where it sits.
// Moving those into the errors would put two kinds of row under one heading, a target no scanner
// read beside a file no scanner read, and split a component's caveats across two blocks. The
// heading says how many fail the run and which setting made them, so a reader can find the line to
// change.
//
// The kind, the controls and the component are the same on every row of a group, so they are said
// once above it and each row says only what and why. Repeated on every row, they take a quarter of
// the line, and a block of file caveats runs past a terminal's width and wraps. A field every group
// shares, such as the one component of a run, is said once over the groups for the same reason.
func writeCaveats(w io.Writer, col tui.Painter, d Data) {
	groups := shownCaveatGroups(d)
	if len(groups) == 0 {
		return
	}
	failing, _ := splitCaveats(d)
	note := col.Paint(cDim, "do not fail the run · config.gate.failOnCaveats lists the kinds that do")
	if len(failing) > 0 {
		setting := caveatSetting(d)
		verb := "fail"
		if len(failing) == 1 {
			verb = "fails"
		}
		note = col.Paint(cFail, fmt.Sprintf("%d %s the run · %s", len(failing), verb, setting))
		// Accepted, they are reported as an error accepted, which is what the verdict's own note
		// says beside PASS.
		if d.AcceptedErrors {
			note = col.Paint(cAccent, fmt.Sprintf("%d accepted by --allow-scan-errors · %s", len(failing), setting))
		}
	}
	_, _ = fmt.Fprintf(w, "%s  %s\n", heading(col, "Caveats"), note)
	// The mark only where something is marked, so a run with nothing failing reads as it always did,
	// and the kinds stay aligned under one another when something is. The mark goes where the kind
	// is named: on the line over the groups where every group is of one kind. The rows sit two
	// columns in from the heading's text either way, so they read as under it without color.
	marking := len(failing) > 0
	markOf := func(c caveat) string {
		switch {
		case !marking:
			return ""
		case c.fails(d):
			return col.Paint(cFail, "✗ ")
		}
		return "  "
	}
	shared, nested := sharedSlots(groups)
	headingIndent := "  "
	if nested {
		mark := markOf(groups[0].rows[0])
		if !shared[0] && marking {
			mark = "  "
		}
		_, _ = fmt.Fprintf(w, "  %s%s\n", mark, col.Paint(cAccent, joinSlots(groups[0].rows[0].headingSlots(),
			func(i int) bool { return shared[i] })))
		headingIndent = "    "
	}
	rowIndent := headingIndent + "  "
	if marking {
		rowIndent += "  "
	}
	cols := tui.Columns(w)
	left := 0
	for _, g := range groups {
		first := g.rows[0]
		mark := markOf(first)
		title := first.heading()
		if nested {
			title = joinSlots(first.headingSlots(), func(i int) bool { return !shared[i] })
			if shared[0] && marking {
				mark = "  "
			}
		}
		_, _ = fmt.Fprintf(w, "%s%s%s\n", headingIndent, mark, col.Paint(cAccent, title))
		writeCaveatGroupRows(w, col, cols, rowIndent, g.rows)
		if g.left > 0 {
			_, _ = fmt.Fprintf(w, "%s%s\n", rowIndent, col.Paint(cDim, fmt.Sprintf("… and %d more", g.left)))
		}
		left += g.left
	}
	switch {
	case left > 0:
		_, _ = fmt.Fprintf(w, "  %s\n", col.Paint(cDim, "--top 0 lists every one"))
	case slices.ContainsFunc(groups, func(g shownGroup) bool { return foldedByReason(g.rows) }):
		_, _ = fmt.Fprintf(w, "  %s\n", col.Paint(cDim, "--top 0 lists each file"))
	}
	_, _ = fmt.Fprintln(w)
}

// writeCaveatGroupRows draws a group's rows as a table of what and why where the table fits a
// terminal cols wide. Where it does not, each reason is said once and the rows it covers are listed
// under it, so a long path and a long reason never share a line: a table cut to fit would cut the
// reason, which says what to do, and a path, which is useless shortened. A cols of zero is a file or
// a pipe, with no width to respect.
func writeCaveatGroupRows(w io.Writer, col tui.Painter, cols int, indent string, rows []caveat) {
	widest := 0
	for _, r := range rows {
		widest = max(widest, utf8.RuneCountInString(r.what)+2+utf8.RuneCountInString(truncate(r.reason(), whyWidth)))
	}
	if cols <= 0 || len(indent)+widest <= cols {
		t := tui.NewTable(col).Indent(indent)
		for _, r := range rows {
			t.Row(tui.Styled(tui.StyleStrong, r.what), tui.Styled(cDim, truncate(r.reason(), whyWidth)))
		}
		t.Render(w)
		return
	}
	var order []string
	byReason := map[string][]caveat{}
	for _, r := range rows {
		if _, seen := byReason[r.reason()]; !seen {
			order = append(order, r.reason())
		}
		byReason[r.reason()] = append(byReason[r.reason()], r)
	}
	for _, reason := range order {
		_, _ = fmt.Fprintf(w, "%s%s\n", indent, col.Paint(cDim, truncate(reason, max(cols-len(indent), minBelow))))
		for _, r := range byReason[reason] {
			_, _ = fmt.Fprintf(w, "%s  %s\n", indent, col.Paint(tui.StyleStrong, r.what))
		}
	}
}

// foldedCaveat is the first caveat row the console draws that stands for several files, which
// --evidence names one by one, and false where it draws none.
func foldedCaveat(d Data) (caveat, bool) {
	shown, _ := shownCaveats(d)
	for _, c := range shown {
		if c.folded {
			return c, true
		}
	}
	return caveat{}, false
}

// cutShort reports whether the console left rows out of a block it drew: the errors, the caveats,
// or a list of findings or actions, which listed says it cut.
func cutShort(d Data, listed int) bool {
	if listed > 0 {
		return true
	}
	if _, capped := shownRows(d, len(notReached(d))); capped {
		return true
	}
	_, left := shownCaveats(d)
	return left > 0
}

// joinNotes puts two notes on one row, either of which may be empty.
func joinNotes(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + " · " + b
}

// namesOfKinds spells kinds of caveat as the setting writes them.
func namesOfKinds(kinds []saga.CaveatKind) []string {
	out := make([]string, len(kinds))
	for i, k := range kinds {
		out[i] = string(k)
	}
	return out
}

// unboundImport is an imported SARIF file that stated no commit, and the controls that read it.
type unboundImport struct {
	component, file string
	controls        []string
}

// unboundImports reads them off the import scanner's provenance, which records the commit each
// file was checked against or that it named none.
func unboundImports(d Data) []unboundImport {
	var out []unboundImport
	type key struct{ component, file string }
	at := map[key]int{}
	for _, name := range sortedControlNames(d) {
		for _, p := range d.Run.Controls[name].Report.Provenance {
			if p.Tool != plugin.ImportScanner {
				continue
			}
			var k key
			bound := true
			for _, f := range p.Fields {
				switch f.Key {
				case "component":
					k.component = f.Value
				case "file":
					k.file = f.Value
				case "commit":
					bound = f.Value != "not stated"
				}
			}
			if bound {
				continue
			}
			i, seen := at[k]
			if !seen {
				i = len(out)
				at[k] = i
				out = append(out, unboundImport{component: k.component, file: k.file})
			}
			if !slices.Contains(out[i].controls, name) {
				out[i].controls = append(out[i].controls, name)
			}
		}
	}
	return out
}
