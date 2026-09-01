package report

import (
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
)

// A descriptor names its project at the top level. Everything that renders the name of the thing
// being scanned reads the accessor, or it renders nothing.
//
// The two that mattered most were silent. A VEX document published with no author is one a
// consumer with a question cannot ask anybody about, and a product identifier of
// "pkg:generic/@2.4.0" is not a package URL at all — it is read, understood, and applied to
// nothing, which is the failure mode the schema reference warns about for this exact field.
func TestEveryReportNamesTheProject(t *testing.T) {
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

// A descriptor naming no project says so rather than rendering something that looks like an
// identifier and matches nothing. "pkg:generic/@1.0" is not a package URL; it is read, understood
// and applied to nothing, which is the failure the schema reference warns about for this field.
func TestANamelessDescriptorDoesNotInventAnIdentifier(t *testing.T) {
	d := Data{Release: saga.Release{Version: "1.0"}}
	if got := vexProductID(d); strings.Contains(got, "pkg:generic/@") {
		t.Errorf("vexProductID = %q, which is a purl with no name in it", got)
	}
	if got := releaseLabel(d); got != "unnamed release 1.0" && got != "unnamed release" {
		t.Errorf("releaseLabel = %q, want it to say the release is unnamed", got)
	}
}
