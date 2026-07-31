package report

import "testing"

// "Fix first" describes a shortlist. Over the whole set it stops being a recommendation and
// becomes a label, and the reader loses what the default view was telling them.
func TestFixFirstHeading(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name         string
		s            summary
		shown, total int
		want         string
	}{
		{"a shortlist says so", summary{}, 10, 437, "Fix first (top 10 of 437, by priority):"},
		{"the whole set is not a shortlist", summary{}, 437, 437, "All 437 findings, by priority:"},
		{"one finding is not a list", summary{}, 1, 1, "The finding (by priority):"},
		{"filtered and capped", summary{minPriority: "p2"}, 10, 50,
			"Fix first (top 10 of 50, by priority, P2 and above):"},
		{"filtered, hiding some", summary{minPriority: "p1", hidden: 12}, 3, 3,
			"All 3 findings, by priority, P1 and above; 12 lower-priority finding(s) hidden:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := fixFirstHeading(tc.s, tc.shown, tc.total); got != tc.want {
				t.Errorf("heading = %q,\n    want %q", got, tc.want)
			}
		})
	}
}

// One component repeats the same value on every row and answers a question nobody has. The
// column earns its width only when it tells findings apart.
func TestComponentColumnOnlyWhenItDistinguishes(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		fs   []finding
		want bool
	}{
		{"no components", []finding{{}, {}}, false},
		{"one component", []finding{{component: "web"}, {component: "web"}}, false},
		{"two components", []finding{{component: "web"}, {component: "api"}}, true},
		{"one named, one not", []finding{{component: "web"}, {}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := manyComponents(tc.fs); got != tc.want {
				t.Errorf("manyComponents = %v, want %v", got, tc.want)
			}
		})
	}
}
