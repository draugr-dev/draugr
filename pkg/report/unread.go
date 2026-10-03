package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/draugr-dev/draugr/pkg/engine"
)

// unreadShown caps the files a component's line names in markdown. The rest are counted, and
// report.json carries them all.
const unreadShown = 3

// unreadNote says what the markdown section lists and what it cost.
const unreadNote = "dependency files and Terraform modules no scanner read · what they declare was not checked"

// unreadGroup is one component's unread files, each named once however many controls missed it.
type unreadGroup struct {
	component string
	files     []unreadFile
}

type unreadFile struct {
	label, reason string
	controls      []string
}

// unreadByComponent folds per-control coverage into one entry per component.
//
// Per component because the fix is per file: a pyproject.toml with no lockfile is one lockfile to
// commit, whether one control or two passed it by, and a block per control would print it twice. A
// path is named with its repository only where the component's files come from more than one,
// because two repositories can each hold a package.json.
func unreadByComponent(inputs []engine.InputCoverage) []unreadGroup {
	var out []unreadGroup
	index := map[string]int{}
	type fileKey struct{ repository, path string }
	files := map[string]map[fileKey]int{}
	repos := map[string]map[string]bool{}
	for _, c := range inputs {
		for _, u := range c.Unread {
			i, ok := index[c.Component]
			if !ok {
				i = len(out)
				index[c.Component] = i
				out = append(out, unreadGroup{component: c.Component})
				files[c.Component] = map[fileKey]int{}
				repos[c.Component] = map[string]bool{}
			}
			repos[c.Component][u.Repository] = true
			k := fileKey{u.Repository, u.Path}
			j, seen := files[c.Component][k]
			if !seen {
				j = len(out[i].files)
				files[c.Component][k] = j
				out[i].files = append(out[i].files, unreadFile{label: u.Repository + "\x00" + u.Path, reason: u.Reason})
			}
			out[i].files[j].controls = append(out[i].files[j].controls, c.Control)
		}
	}
	for i := range out {
		several := len(repos[out[i].component]) > 1
		for j := range out[i].files {
			repo, path, _ := strings.Cut(out[i].files[j].label, "\x00")
			out[i].files[j].label = path
			if several {
				out[i].files[j].label = shortRepository(repo) + ":" + path
			}
		}
	}
	return out
}

// text is the group's line: each file with its reason and the controls it went unread for, the
// first limit of them and a count of the rest. A negative limit names every file.
func (g unreadGroup) text(limit int, code func(string) string) string {
	parts := make([]string, 0, len(g.files))
	for i, f := range g.files {
		if i == limit {
			parts = append(parts, fmt.Sprintf("+%d", len(g.files)-limit))
			break
		}
		parts = append(parts, fmt.Sprintf("%s %s (%s)", code(f.label), f.reason, strings.Join(f.controls, ", ")))
	}
	return strings.Join(parts, " · ")
}

// writeUnreadRows lists the unread files for the format pasted into a pull request, where a passing check
// is read as covering the whole repository.
func writeUnreadRows(w io.Writer, d Data) {
	groups := unreadByComponent(d.Run.Inputs)
	if len(groups) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "**Unread** · %s\n\n", unreadNote)
	for _, g := range groups {
		_, _ = fmt.Fprintf(w, "- `%s` · %s\n", g.component, g.text(unreadShown, func(s string) string { return "`" + s + "`" }))
	}
	_, _ = fmt.Fprintln(w)
}
