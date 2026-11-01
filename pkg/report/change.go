package report

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/draugr-dev/draugr/pkg/prioritization"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// ChangeView draws a run's comparison with its base in the shape `draugr diff` prints: the band
// strips by state, and what changed.
//
// An interface this package declares and pkg/diff implements, with the CLI joining the two, rather
// than a call from here into pkg/diff. pkg/diff renders that shape and imports this package for the
// fix list its actions are grouped by, so a call the other way would be an import cycle. Moving the
// shared pieces into a package both could import means moving the fix list, which is most of this
// package, for the sake of two methods. Declaring the interface here keeps one renderer for the
// change, the one `draugr diff` already prints, and leaves the dependency pointing the way it did.
type ChangeView interface {
	// WriteStrips draws a strip of band counts for each state a finding can be in against the base,
	// then one more labeled strip for the counts in whole.
	WriteStrips(w io.Writer, label string, whole [4]int)
	// WriteListing draws what changed in the view asked for, capped at top rows where top is
	// positive, and reports whether it wrote anything. It writes nothing where nothing changed.
	WriteListing(w io.Writer, view View, top int) bool
}

// judgedOnChange reports whether the console prints this run as its change: the gate on new
// findings decided the verdict, and the caller gave the comparison a view to draw it with.
func (d Data) judgedOnChange() bool { return d.Change != nil && d.Gate.judgesChange() }

// renderChange is the console for a run the gate on new findings judged.
//
// The change in the layout `draugr diff` prints, because that is the question the run answered: what
// this change introduced, measured against the base. The whole run is one strip under the change's,
// since its outcome decides nothing and a full report of it would put a second verdict's worth of
// rows under the first. What qualifies the change stays in every view, the organization's policy,
// what each control was measured against, the targets not reached and the caveats: a coverage row
// such as "1 of 2 images checked" says the change was judged on less than the run was asked to read,
// which a shorter listing does not make any less true.
func renderChange(w io.Writer, d Data) error {
	s := summarize(d)
	col := tui.For(w)
	writeVerdictLine(w, col, s, d, changeNote(d.Gate))
	d.Change.WriteStrips(w, "whole run", [4]int{s.p1, s.p2, s.p3, s.p4})
	if d.Gate.Disabled {
		writeGate(w, col, d, false, "")
	}
	writePolicy(w, col, d.Policy)
	if lines := provenanceLines(d); len(lines) > 0 {
		width := 0
		for _, l := range lines {
			width = max(width, len(l.Control))
		}
		writeMeasuredRows(w, col, lines, width)
		_, _ = fmt.Fprintln(w)
	}
	writeErrors(w, col, d)
	writeCaveats(w, col, d)
	if d.Change.WriteListing(w, d.View, max(d.TopN, 0)) {
		_, _ = fmt.Fprintln(w)
	}
	writeTail(w, col, s, d, 0)
	return nil
}

// changeNote is what a judged run's verdict was measured against, beside it: the base, how many
// findings are new against it, and the gate on them.
//
// The count is every new finding, the number `draugr diff` heads its own output with, and the
// threshold beside it says which of them the gate counts.
func changeNote(g GateSettings) string {
	news := "nothing new"
	if n := len(g.New.Introduced); n > 0 {
		news = fmt.Sprintf("%d new", n)
	}
	return "change since " + g.baseName() + " · " + news + " · fails on " + ThresholdWords(g.FailOnNew)
}

// ThresholdWords is a gate setting as the report states it: a band as it is written, and a
// severity followed by "severity", the way the gate's own line words one. Shared with the message
// a failed run exits with, so the two say it alike.
func ThresholdWords(setting string) string {
	if band := strings.ToUpper(setting); prioritization.Priority(band).Rank() > 0 {
		return band
	}
	return setting + " severity"
}

// BaseName is a base scan as a reader quotes it: the first seven characters of each revision it
// read, or path, the file it was read from, where it records none. Seven, because that is how git
// abbreviates a commit and how a reader will look it up.
func BaseName(base []sarif.RepositoryRef, path string) string {
	var revs []string
	for _, r := range base {
		rev := r.Revision
		if len(rev) > 7 {
			rev = rev[:7]
		}
		if rev != "" && !slices.Contains(revs, rev) {
			revs = append(revs, rev)
		}
	}
	if len(revs) == 0 {
		return path
	}
	return strings.Join(revs, ", ")
}

// UpgradeTarget is the release the fix list names for an upgrade clearing these findings, empty
// where it names none or would split them into more than one action.
//
// For `draugr diff`'s rendering of a scan's change, so an upgrade there names the version the scan's
// own fix list names, from the same computation, rather than one worked out a second way.
func UpgradeTarget(results []sarif.Result) string {
	fs := make([]finding, 0, len(results))
	for _, r := range results {
		fs = append(fs, findingOf(r.Control, sarif.Report{}, r))
	}
	sortFindings(fs)
	actions, _ := groupActions(fs, nil)
	if len(actions) != 1 {
		return ""
	}
	return actions[0].target()
}
