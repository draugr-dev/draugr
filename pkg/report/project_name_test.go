package report

import (
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
)

// A descriptor written the way the reference tells people to write it names its project at the top
// level and leaves release.name empty. Everything that renders the name of the thing being scanned
// has to read the accessor, or it renders nothing.
//
// The two that mattered most were silent. A VEX document published with no author is one a
// consumer with a question cannot ask anybody about, and a product identifier of
// "pkg:generic/@2.4.0" is not a package URL at all — it is read, understood, and applied to
// nothing, which is the failure mode the schema reference warns about for this exact field.
func TestEveryReportNamesTheProjectWhenReleaseNameIsGone(t *testing.T) {
	d := Data{Project: "acme-api", Release: saga.Release{Version: "2.4.0"}}

	if got := d.ProjectName(); got != "acme-api" {
		t.Fatalf("ProjectName() = %q", got)
	}
	if got := vexAuthor(d); got != "acme-api" {
		t.Errorf("vexAuthor = %q, want the project — a document with no author is one nobody can "+
			"be asked about", got)
	}
	if got := vexProductID(d); got != "pkg:generic/acme-api@2.4.0" {
		t.Errorf("vexProductID = %q, want a package URL with a name in it", got)
	}
	if got := releaseLabel(d); got != "acme-api 2.4.0" {
		t.Errorf("releaseLabel = %q", got)
	}
}

// And a descriptor that has not moved yet still renders, because release.name is accepted until it
// is removed and a report that goes blank is worse than one naming a deprecated field's value.
func TestAReportStillNamesADescriptorThatHasNotMovedYet(t *testing.T) {
	d := Data{Release: saga.Release{Name: "legacy-api", Version: "1.0"}}
	if got := vexProductID(d); !strings.Contains(got, "legacy-api") {
		t.Errorf("vexProductID = %q, want it to fall back to release.name", got)
	}
	if got := releaseLabel(d); got != "legacy-api 1.0" {
		t.Errorf("releaseLabel = %q", got)
	}
}
