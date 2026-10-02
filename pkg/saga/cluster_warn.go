package saga

import (
	"fmt"
	"maps"
	"slices"
)

// ClusterWarnings names declared clusters that no component's `kubernetes:` entry uses.
//
// A warning rather than an error. A declared cluster nobody runs on changes no result, and it may be
// written ahead of the component that will use it. Saying nothing is still wrong: the likelier story
// is a component that misspelled the name, which validation refuses, or one that was removed and
// left its cluster behind, which only this notices.
func (m *Model) ClusterWarnings() []string {
	used := map[string]bool{}
	for _, c := range m.Components {
		for _, ref := range c.Kubernetes {
			used[ref.Cluster] = true
		}
	}
	var out []string
	for _, name := range slices.Sorted(maps.Keys(m.Clusters)) {
		if !used[name] {
			out = append(out, fmt.Sprintf("clusters.%s is declared and no component's kubernetes: "+
				"entry names it, so nothing scans it", name))
		}
	}
	return out
}
