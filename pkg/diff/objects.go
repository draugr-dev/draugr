package diff

import (
	"sort"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// ObjectChange is a check that lists the objects failing it, failing in both scans, whose list
// changed: the head's copy, and the objects that joined it and left it.
//
// A check is one finding per place, so the comparison pairs it on its objects and calls it new when
// one joined and unchanged otherwise. Neither says which object, and the message, which lists every
// object failing the check, cannot be read for it either: most of what it lists was there before.
type ObjectChange struct {
	sarif.Result
	// Joined are the objects the head lists and the base did not, and Left the reverse, each sorted.
	Joined, Left []string
}

// objectDelta is what joined and left a check between base and head, both listing objects.
func objectDelta(head, base sarif.Result) (joined, left []string) {
	if len(head.Objects) == 0 || len(base.Objects) == 0 {
		return nil, nil
	}
	in := func(list []string) map[string]bool {
		m := make(map[string]bool, len(list))
		for _, o := range list {
			m[o] = true
		}
		return m
	}
	before, after := in(base.Objects), in(head.Objects)
	for o := range after {
		if !before[o] {
			joined = append(joined, o)
		}
	}
	for o := range before {
		if !after[o] {
			left = append(left, o)
		}
	}
	sort.Strings(joined)
	sort.Strings(left)
	return joined, left
}

// sortObjectChanges orders them as the findings they belong to are ordered.
func sortObjectChanges(cs []ObjectChange) {
	sort.SliceStable(cs, func(i, j int) bool {
		a, b := cs[i].Result, cs[j].Result
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.Location.URI != b.Location.URI {
			return a.Location.URI < b.Location.URI
		}
		return a.Component < b.Component
	})
}
