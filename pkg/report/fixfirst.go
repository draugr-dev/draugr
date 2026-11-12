package report

import (
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/draugr-dev/draugr/pkg/tui"
)

// A finding is drawn as a block of three lines rather than as a row of columns.
//
// A table sizes every column to its widest value, and the values here have no common size: a rule
// id is short, a component name is whatever somebody called it, and a location is anything from
// `go.mod:12` to an image reference carrying a 71-character digest. One image therefore set the
// width of a column that 984 other findings paid for, and the table came out at 217 columns on a
// 120-column terminal, where a terminal wraps every row and the listing stops being one.
//
// The bound cannot be recovered by trimming, either: `Table.Fit` shortens the last column, and the
// columns before it had already spent the budget. What a reader loses is whichever column happened
// to be last, which is the one saying what to do about the finding.
//
// So there are no columns beyond the two that are fixed width anyway. Nothing here can be widened
// by one long value, at any terminal size.
const (
	// blockGutter is where the first line's text starts, after the band and the severity.
	blockGutter = 16
	// blockIndent is where the two lines under it start. Short of the gutter, so the band and the
	// severity keep an edge of their own and a reader can see where one finding ends.
	blockIndent = 6
	// narrowestBlock is the width assumed where there is none to read: a file, or a pipe. The
	// sentences are bounded by messageWidth regardless, so this only decides how much of a long
	// location survives.
	narrowestBlock = messageWidth + blockGutter
)

// renderFixFirstBlocks prints each ranked finding as a block: what it is, what is known about it,
// and where it is.
func renderFixFirstBlocks(w io.Writer, col tui.Painter, fs []finding, blobs blobLinker) {
	width := tui.Columns(w)
	if width <= 0 {
		width = narrowestBlock
	}
	// The same question the columns asked, for the same reason: a value identical on every finding
	// distinguishes none of them, and the release header already said what was scanned.
	withComponent := manyComponents(fs)
	withRepository := manyRepositories(fs)

	for i, f := range fs {
		if i > 0 {
			_, _ = fmt.Fprintln(w)
		}
		writeBlockHead(w, col, f, width)
		writeBlockFacts(w, col, f, width, withComponent, withRepository)
		writeBlockWhere(w, col, f, width, blobs)
	}
}

// writeBlockHead is the first lines: the band, the severity and the rule, then what the finding says.
//
// The rule id is printed whole, because it is what a reader pastes into `config.exclude`, which
// matches it exactly, and an id cut at either end matches nothing. It links to what the rule means,
// which costs no width. The finding's message takes the line beneath, so the id never has to give up
// room to it. Where the id is wider than the room beside the band, it takes a line of its own.
func writeBlockHead(w io.Writer, col tui.Painter, f finding, width int) {
	priority := dash(f.priority)
	severity := string(rankedSeverity(f))
	line := "  " +
		padPainted(col.Paint(priorityColor(f.priority), priority), priority, 4) +
		padPainted(col.Paint(severityColor(rankedSeverity(f)), severity), severity, 10)

	rule := col.Link(f.helpURI, f.ruleID)
	if who, expected, ok := unexpectedSigner(f); ok {
		// The signer the descriptor expected is short and goes whole on the title line; the identity
		// that signed the image is long and takes the line beneath, where the reader compares it with
		// the signer they declared.
		_, _ = fmt.Fprintln(w, line+rule+col.Paint(cDim, " · ")+"not "+expected)
		_, _ = fmt.Fprintln(w, "      "+signingIdentity(col, who, width-blockIndent))
		return
	}
	if blockGutter+utf8.RuneCountInString(f.ruleID) <= width {
		_, _ = fmt.Fprintln(w, line+rule)
	} else {
		_, _ = fmt.Fprintln(w, strings.TrimRight(line, " "))
		_, _ = fmt.Fprintln(w, "      "+rule)
	}
	room := max(width-blockIndent, minTitleWidth)
	// A sentence about the resource that is also the message, Prowler's, is printed whole up to the
	// width, rather than condensed the way a rule's description is.
	switch {
	case f.detail != "" && f.detail == f.message:
		_, _ = fmt.Fprintln(w, "      "+elide(f.detail, room))
	case findingTitle(f) != "":
		_, _ = fmt.Fprintln(w, "      "+elide(findingTitle(f), min(room, messageWidth)))
	}
	if d := f.addedDetail(); d != "" {
		_, _ = fmt.Fprintln(w, "      "+elideFront(d, room))
	}
	if i := findingInstruction(f); i != "" {
		_, _ = fmt.Fprintln(w, "      "+i)
	}
}

// writeBlockFacts is the second line: what moved the band, and what is known about the finding.
//
// The mark leads it. It qualifies everything after it, and a reader who has just read what the
// finding says meets the argument against its band before the facts that follow from it.
func writeBlockFacts(w io.Writer, col tui.Painter, f finding, width int, withComponent, withRepository bool) {
	var parts []string
	if m := movedBy(f); m != nil {
		parts = append(parts, col.Paint(m.style, strings.TrimSpace(m.glyph+" "+m.label)))
	}
	label := func(name, value string) string {
		return col.Paint(cDim, name) + " " + value
	}
	if withComponent && f.component != "" {
		parts = append(parts, label("component", f.component))
	}
	if withRepository && f.repository != "" {
		parts = append(parts, label("repository", shortRepository(f.repository)))
	}
	if f.tool != "" {
		// Lowercased, because half these names are what the tool calls itself and half are what
		// Draugr runs it as, and one scanner under two spellings reads as two scanners.
		parts = append(parts, label("scanner", strings.ToLower(f.tool)))
	}
	// The package, on every finding about one. One CVE in two packages is two findings with the same
	// rule, severity and location, and without the name a reader sees a duplicate.
	//
	// With a release to move to, the arrow is the fix and says it in fewer words than a phrase.
	// Without one, the phrase still says why there is nothing to upgrade to. A version is the answer
	// for a vulnerable dependency and there is none to give for a misconfiguration, a hardcoded
	// secret, or a flaw in the code itself, which keep the phrase alone. A package with no release
	// to move to keeps its name and takes the phrase that says why.
	//
	// A development dependency is labeled the way the scanner is, the kind dimmed before the value:
	// `dev dependency nanoid 3.3.7`. In full here, where the line has room; the compact cell
	// shortens it to `dev`. A dependency the runtime provides is labeled the same way.
	name, fixed := packageFix(f, true)
	if _, full := packageKind(f); name != "" && full != "" {
		name = col.Paint(cDim, full) + " " + name
	}
	if fixed != "" {
		parts = append(parts, name+" "+col.Paint(tui.StyleFixed, "→ "+fixed))
	} else {
		if name != "" {
			parts = append(parts, name)
		}
		parts = append(parts, col.Paint(cDim, "fix")+" "+col.Paint(tui.StyleFixed, fixPhrase(f)))
	}

	_, _ = fmt.Fprintln(w, blockLine(col, parts, width))
}

// writeBlockWhere is the third line: where the finding is, and anything standing behind it.
func writeBlockWhere(w io.Writer, col tui.Painter, f finding, width int, blobs blobLinker) {
	where := whereShown(displayLocation(f))
	linked := col.Paint(cDim, col.Link(blobs.forFinding(f), where))
	// The kind of directory the file sits under, beside the path it describes, the way the kind of a
	// dependency stands beside its name: `tests/fixture.yaml · test`. Kept with the location when the
	// working moves to a line of its own.
	if f.nonShipping != "" {
		linked += col.Paint(cDim, " · ") + f.nonShipping
		where += " · " + f.nonShipping
	}

	// The working behind the mark on the line above: which analyzer, which floor, what else found
	// it, and for a secret already published, that deleting it is not remediation.
	said := reasoning(col, f)
	if len(said) == 0 {
		_, _ = fmt.Fprintln(w, blockLine(col, []string{linked}, width))
		return
	}
	plain, painted := make([]string, 0, len(said)), make([]string, 0, len(said))
	for _, p := range said {
		plain = append(plain, p.plain)
		painted = append(painted, p.painted)
	}
	joined := strings.Join(plain, " · ")

	// Beside the location where it fits, and on a line of its own where it does not. Never
	// dropped: these are the sentences saying the band was argued with and what to do instead, so
	// a finding that loses them reads as one nobody questioned.
	if blockIndent+utf8.RuneCountInString(where)+len(" · ")+utf8.RuneCountInString(joined) <= width {
		_, _ = fmt.Fprintln(w, blockLine(col, append([]string{linked}, painted...), width))
		return
	}
	_, _ = fmt.Fprintln(w, blockLine(col, []string{linked}, width))
	_, _ = fmt.Fprintln(w, blockLine(col, []string{elideParts(col, said, min(width-blockIndent, messageWidth))}, width))
}

// elideParts renders the working to a width, cutting the last part rather than dropping any.
func elideParts(col tui.Painter, parts []notePart, width int) string {
	painted := make([]string, 0, len(parts))
	room := width
	for i, p := range parts {
		if i > 0 {
			room -= len(" · ")
		}
		if room <= 0 {
			break
		}
		painted = append(painted, col.Paint(cDim, elide(p.plain, room)))
		room -= utf8.RuneCountInString(p.plain)
	}
	return strings.Join(painted, col.Paint(cDim, " · "))
}

// blockLine joins one of the lines under the head, indented and separated the way every other
// list of facts Draugr prints is.
func blockLine(col tui.Painter, parts []string, _ int) string {
	return strings.Repeat(" ", blockIndent) + strings.Join(parts, col.Paint(cDim, " · "))
}

// padPainted pads painted text by what a reader sees rather than by the bytes the escapes add.
func padPainted(painted, plain string, width int) string {
	if n := width - utf8.RuneCountInString(plain); n > 0 {
		return painted + strings.Repeat(" ", n)
	}
	return painted + " "
}

// unexpectedSigner reads a provenance-unexpected-identity finding's message, `Signed by <identity>,
// not <signer>.` as the cosign scanner writes it, back into the identity and the signer. False for
// any other finding, and for a message in another form, which keeps its row as it was. The message
// itself is unchanged, because it is part of the finding's identity across runs.
func unexpectedSigner(f finding) (who, expected string, ok bool) {
	if f.ruleID != "provenance-unexpected-identity" {
		return "", "", false
	}
	rest, found := strings.CutPrefix(f.message, "Signed by ")
	if !found {
		return "", "", false
	}
	i := strings.LastIndex(rest, ", not ")
	if i < 0 {
		return "", "", false
	}
	return rest[:i], strings.TrimSuffix(rest[i+len(", not "):], "."), true
}

// signingIdentity is a signing identity in width columns, under the keys a descriptor's GitHub signer
// takes: `repository … · workflow … · ref …`, in the descriptor's own values where they fit, so each
// can be pasted into the signer, and with the workflow's file name and the ref's short name where they
// do not. An identity that is not a GitHub workflow's is printed as it is, cut at the end.
func signingIdentity(col tui.Painter, who string, width int) string {
	repo, rest, ok := strings.Cut(who, "/.github/workflows/")
	file, ref, hasRef := strings.Cut(rest, "@")
	if !ok || !hasRef || repo == "" || file == "" {
		return col.Paint(cDim, "signed by") + " " + elide(who, width-len("signed by "))
	}
	sep := col.Paint(cDim, " · ")
	key := func(k string) string { return col.Paint(cDim, k) + " " }
	workflow, short := ".github/workflows/"+file, ref
	if utf8.RuneCountInString("repository "+repo+" · workflow "+workflow+" · ref "+ref) > width {
		workflow = file
		short = strings.TrimPrefix(strings.TrimPrefix(ref, "refs/heads/"), "refs/tags/")
	}
	return key("repository") + repo + sep + key("workflow") + workflow + sep + key("ref") + short
}
