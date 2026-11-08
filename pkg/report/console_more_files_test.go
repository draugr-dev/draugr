package report

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A row's location names one file of the flaw's copies, and says how many others hold it. The line
// on the row's own location is not another file.
func TestARowSaysHowManyOtherFilesHoldTheFlaw(t *testing.T) {
	others := []sarif.Observation{
		{Tool: "grype", Location: "admin/package-lock.json"},
		{Tool: "grype", Location: "web/package-lock.json"},
		{Tool: "trivy", Location: "web/package-lock.json"},
	}
	for _, c := range []struct {
		name string
		f    finding
		want string
	}{
		{"another file", finding{location: "admin/package-lock.json:14", alsoFoundBy: others}, "and 1 more"},
		{"one file", finding{location: "web/package-lock.json:3", alsoFoundBy: others[1:]}, ""},
		{"no copies", finding{location: "web/package-lock.json:3"}, ""},
	} {
		if got := moreFilesNote(c.f); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}
