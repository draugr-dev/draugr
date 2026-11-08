package engine

import (
	"cmp"
	"slices"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// UnreadChecks are the checks of one service a component's scan could not evaluate, or evaluate in
// full, and why.
//
// Grouped by service because that is what a reader acts on: a denied read is fixed by granting the
// permission it needs, once, and it clears every check that reads the service.
type UnreadChecks struct {
	Component string
	Control   string
	// Group is what the checks read, the cloud service, such as "compute".
	Group string
	// Checks are the identifiers of the checks with no result, sorted.
	Checks []string
	// PartlyRead are the identifiers of the checks that returned results from the reads they were
	// allowed, sorted. Their findings are in the report, and they are not decided.
	PartlyRead []string
	// Reason is why, the first stated for the group: "denied compute.instances.list".
	Reason string
}

// unreadChecks folds each control's unchecked checks into one entry per component, control and
// group, sorted in that order.
func unreadChecks(byCtl map[string][]sarif.Report) []UnreadChecks {
	type key struct{ component, control, group string }
	at := map[key]*UnreadChecks{}
	for control, reports := range byCtl {
		for _, rep := range reports {
			for _, u := range rep.Unchecked {
				k := key{u.Component, control, u.Group}
				g := at[k]
				if g == nil {
					g = &UnreadChecks{Component: u.Component, Control: control, Group: u.Group, Reason: u.Reason}
					at[k] = g
				}
				list := &g.Checks
				if u.PartlyRead {
					list = &g.PartlyRead
				}
				if !slices.Contains(*list, u.Check) {
					*list = append(*list, u.Check)
				}
				// Stable across runs whichever report arrived first.
				if u.Reason < g.Reason {
					g.Reason = u.Reason
				}
			}
		}
	}
	out := make([]UnreadChecks, 0, len(at))
	for _, g := range at {
		slices.Sort(g.Checks)
		slices.Sort(g.PartlyRead)
		out = append(out, *g)
	}
	slices.SortFunc(out, func(a, b UnreadChecks) int {
		return cmp.Or(cmp.Compare(a.Component, b.Component), cmp.Compare(a.Control, b.Control),
			cmp.Compare(a.Group, b.Group))
	})
	return out
}
