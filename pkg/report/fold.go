package report

import (
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/draugr-dev/draugr/internal/english"
)

// foldLines is a list with the actions for single lines that say the same thing on one row.
//
// One rule across seventeen lines is seventeen edits, and report.json keeps them as seventeen actions,
// but a reader decides about the rule once, and seventeen rows of one sentence bury everything else
// in the list. The row takes the place of the first of them, so the list keeps the order its ranking
// gave it.
//
// One row per band, component and repository. A row spanning two bands would rank as the worse, two
// components are two owners, and paths are repository-relative, so two repositories' main.go:12 are
// two files. A line asking for a second change keeps a row of its own, because the row says so.
func foldLines(as []action) []action {
	out := make([]action, 0, len(as))
	at := map[string]int{}
	for _, a := range as {
		if !a.atOneLine() {
			out = append(out, a)
			continue
		}
		k := lineFoldKey(a)
		i, ok := at[k]
		if !ok {
			a.lines = 1
			at[k] = len(out)
			out = append(out, a)
			continue
		}
		out[i].lines++
		out[i].findings = append(out[i].findings[:len(out[i].findings):len(out[i].findings)], a.findings...)
		out[i].copies = append(out[i].copies[:len(out[i].copies):len(out[i].copies)], a.copies...)
	}
	return out
}

// lineFoldKey is what two actions for single lines share when foldLines puts them on one row.
func lineFoldKey(a action) string {
	return strings.Join([]string{a.priority, a.component, a.findings[0].repository, a.title, a.summary}, "\x00")
}

// lineRows says, for each action, which action's row foldLines puts it on: the index of the first
// action of its row, or -1 for an action on a row of its own, which is every action not about one
// line and every line no other line shares a row with.
//
// What report.json records as each action's row, so a consumer of the document lists the actions
// as --view actions does without repeating the rule foldLines applies.
func lineRows(as []action) []int {
	rows := make([]int, len(as))
	first := map[string]int{}
	size := map[int]int{}
	for i, a := range as {
		rows[i] = -1
		if !a.atOneLine() {
			continue
		}
		k := lineFoldKey(a)
		f, ok := first[k]
		if !ok {
			f = i
			first[k] = i
		}
		rows[i] = f
		size[f]++
	}
	for i, f := range rows {
		if f >= 0 && size[f] < 2 {
			rows[i] = -1
		}
	}
	return rows
}

// foldFindings puts the findings that share a findingFoldKey on one row, at the place of the first of
// them in the order the ranking gave, and returns the rows. A row's repeats is how many more findings
// it stands for, and repeatFiles how many files they are in, its own included.
//
// One rule firing across a codebase is one decision for a reader, and a row per firing fills the
// list with copies of one sentence and pushes every other rule below the cut. The row keeps the
// place of the first, so the list keeps its order.
//
// The row shows the first finding, unless a later one ranking alike leads where it does not
// (foldLead): its location is the reader's first clue where to look.
func foldFindings(fs []finding) []finding {
	out := make([]finding, 0, len(fs))
	at := map[string]int{}
	files := map[string]map[string]bool{}
	for _, f := range fs {
		k := findingFoldKey(f)
		if files[k] == nil {
			files[k] = map[string]bool{}
		}
		files[k][lineSuffix.ReplaceAllString(f.location, "")] = true
		if i, ok := at[k]; ok {
			if foldLead(f) && !foldLead(out[i]) && rankOrder(out[i], f) == 0 {
				f.repeats = out[i].repeats
				out[i] = f
			}
			out[i].repeats++
			continue
		}
		at[k] = len(out)
		out = append(out, f)
	}
	for k, i := range at {
		out[i].repeatFiles = len(files[k])
	}
	return out
}

// foldLead reports whether a finding is the one a folded row should show over the others ranking
// alike: a mutable tag on an action somebody outside GitHub publishes.
//
// GitHub publishes its own actions under the actions and github organizations, and a tag there moves
// only when GitHub moves it. A tag on any other action moves when its owner, or whoever holds the
// owner's account, moves it, and the job then runs what it points at with the job's token: that
// reference is what makes the row worth fixing. A row showing `actions/checkout` beside it sends the
// reader to the line that is not the risk.
func foldLead(f finding) bool {
	if f.uses == "" {
		return false
	}
	owner, _, _ := strings.Cut(f.uses, "/")
	return !strings.EqualFold(owner, "actions") && !strings.EqualFold(owner, "github")
}

// findingFoldKey is what two findings share when foldFindings puts them on one row: the rule, the
// band, the component and the repository, for the reasons lineFoldKey gives, and the group the
// ranking lists before the band, so a row never joins shipped code to a test fixture whose findings
// the order puts after it. The package and its fix as well, because one advisory in two packages is
// two upgrades, and a row names one.
func findingFoldKey(f finding) string {
	pkg, fixed := packageFix(f, false)
	return strings.Join([]string{f.priority, f.ruleID, f.component, f.repository,
		f.nonShipping, f.aside, pkg, fixed}, "\x00")
}

// foldedPlaces names a folded row's lines, each file once with its line numbers together, within
// room columns. Lines that do not fit are counted, and the first always appears, with its directories
// cut if it must be, because a row that names no file sends the reader nowhere.
func foldedPlaces(a action, room int) string {
	byFile := map[string][]int{}
	var files []string
	total := 0
	seen := map[string]bool{}
	for _, f := range a.findings {
		if seen[f.location] {
			continue
		}
		seen[f.location] = true
		total++
		m := lineSuffix.FindString(f.location)
		path := strings.TrimSuffix(f.location, m)
		if a.nameRepository {
			path = inRepository(f.repository, path)
		}
		n, _ := strconv.Atoi(strings.TrimPrefix(m, ":"))
		if _, ok := byFile[path]; !ok {
			files = append(files, path)
		}
		byFile[path] = append(byFile[path], n)
	}
	width := utf8.RuneCountInString
	var whole []string
	for _, path := range files {
		sort.Ints(byFile[path])
		nums := make([]string, len(byFile[path]))
		for i, n := range byFile[path] {
			nums[i] = strconv.Itoa(n)
		}
		whole = append(whole, path+":"+strings.Join(nums, ","))
	}
	if all := strings.Join(whole, " · "); width(all) <= room {
		return all
	}
	more := func(left int) string { return " · and " + strconv.Itoa(left) + " more" }
	var b strings.Builder
	shown := 0
	for _, path := range files {
		for i, n := range byFile[path] {
			part := "," + strconv.Itoa(n)
			if i == 0 {
				part = " · " + path + ":" + strconv.Itoa(n)
				if shown == 0 {
					part = path + ":" + strconv.Itoa(n)
				}
			}
			left := total - shown - 1
			if width(b.String())+width(part)+width(more(left)) <= room {
				b.WriteString(part)
				shown++
				continue
			}
			if shown > 0 {
				return b.String() + more(left+1)
			}
			// The first line, in less room than it needs: its directories go, and then the count,
			// because the row already says how many lines it stands for.
			if clipped, ok := clipDirs(part, room-width(more(left))); ok {
				b.WriteString(clipped)
				shown++
				continue
			}
			if clipped, ok := clipDirs(part, room); ok {
				return clipped
			}
			return part
		}
	}
	return b.String()
}

// listCount is a list's rows, and the lines they stand for where every row is about lines and there
// are more lines than rows.
func listCount(as []action) string {
	rows := foldLines(as)
	for _, a := range as {
		if !a.atOneLine() {
			return english.Count(len(rows), "action")
		}
	}
	// The lines only where they say something the findings beside them do not: a line count equal to
	// the finding count is the same number said twice.
	if len(as) > len(rows) && len(as) != cleared(as) {
		return english.Count(len(rows), "action") + " on " + english.Count(len(as), "line")
	}
	return english.Count(len(rows), "action")
}

// foldsAny reports whether a list has rows standing for more than one line.
func foldsAny(as []action) bool {
	return len(foldLines(as)) < len(as)
}

// oneControl reports whether every action came from one control, which the rows then need not repeat.
func oneControl(as []action) bool {
	for _, a := range as {
		if a.control != as[0].control {
			return false
		}
	}
	return true
}
