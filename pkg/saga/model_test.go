package saga

import (
	"strings"
	"testing"
)

// project and release.name name the same thing, so which one wins — and what a reader is told
// about the one that is going away — is the whole of the migration.
func TestProjectNameAndDeprecations(t *testing.T) {
	cases := []struct {
		name    string
		model   Model
		want    string
		deprecs int
	}{
		{"project only", Model{Project: "payments-api"}, "payments-api", 0},
		{"release.name only", Model{Release: Release{Name: "Payments API"}}, "Payments API", 1},
		{"neither", Model{}, "", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.model.ProjectName(); got != c.want {
				t.Errorf("ProjectName() = %q, want %q", got, c.want)
			}
			if got := len(c.model.Deprecations()); got != c.deprecs {
				t.Errorf("Deprecations() = %d entries, want %d", got, c.deprecs)
			}
		})
	}
}

// The notice has one job beyond announcing the removal: hand over the line to paste. A suggestion
// that is not a legal project name sends somebody to the reference to find out why their
// copy-paste was rejected.
func TestDeprecationSuggestsAUsableName(t *testing.T) {
	for _, in := range []string{"Payments API", "  Payments/API  ", "payments_api", "Payments -- API"} {
		m := Model{Release: Release{Name: in}}
		got := m.Deprecations()
		if len(got) != 1 {
			t.Fatalf("%q: got %d notices, want 1", in, len(got))
		}
		if !strings.Contains(got[0], "`project: payments-api`") {
			t.Errorf("%q: notice does not suggest `project: payments-api`: %s", in, got[0])
		}
		if !projectName.MatchString(slugify(in)) {
			t.Errorf("%q: suggested %q, which validation rejects", in, slugify(in))
		}
	}
}

// A name with nothing to slugify has no suggestion to make, and must not offer an empty one.
func TestSlugifyDegenerate(t *testing.T) {
	for _, in := range []string{"", "---", "///"} {
		if got := slugify(in); got != "" {
			t.Errorf("slugify(%q) = %q, want empty", in, got)
		}
	}
	got := (&Model{Release: Release{Name: "///"}}).Deprecations()
	if len(got) != 1 {
		t.Fatalf("got %d notices, want 1", len(got))
	}
	if strings.Contains(got[0], "project: `") || strings.Contains(got[0], "project: —") {
		t.Errorf("notice offers an empty project name: %s", got[0])
	}
}
