package report

import (
	"strings"

	"github.com/draugr-dev/draugr/pkg/engine"
)

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
// path is named with its repository where the component scans more than one, because two
// repositories can each hold a package.json. That is decided by the repositories the run planned
// for the component, not only by the ones holding an unread file: with one of two repositories'
// files unread, a bare path does not say which repository to open.
func unreadByComponent(inputs []engine.InputCoverage, targets []engine.TargetOutcome) []unreadGroup {
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
	planned := repositoriesByComponent(targets)
	for i := range out {
		several := len(repos[out[i].component]) > 1 || planned[out[i].component] > 1
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

// repositoriesByComponent counts the distinct repositories the run planned for each component. One
// repository at two revisions is one repository.
func repositoriesByComponent(targets []engine.TargetOutcome) map[string]int {
	seen := map[string]map[string]bool{}
	for _, t := range targets {
		if t.Kind != "repository" {
			continue
		}
		source, _, _ := strings.Cut(t.Target, "@")
		for _, c := range t.Components {
			if seen[c] == nil {
				seen[c] = map[string]bool{}
			}
			seen[c][source] = true
		}
	}
	out := make(map[string]int, len(seen))
	for c, s := range seen {
		out[c] = len(s)
	}
	return out
}
