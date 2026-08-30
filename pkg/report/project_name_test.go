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

// The identifier a consumer looks this up by, when the descriptor declared one.
//
// The synthesized `pkg:generic/…` is honest about being made up from the descriptor, and the
// schema reference is explicit that nothing will match it unless a consumer happens to call the
// product exactly that. A declaration replaces it, and a declaration without a version gets the
// release's — so the identifier moves when the release does rather than quietly claiming an old
// one.
func TestAVEXProductUsesWhatTheProjectSaysItPublishes(t *testing.T) {
	base := Data{Project: "acme-api", Release: saga.Release{Version: "2.4.0"}}

	if got := vexProductID(base); got != "pkg:generic/acme-api@2.4.0" {
		t.Errorf("undeclared = %q, want the synthesized purl", got)
	}

	declared := base
	declared.Publishes = "pkg:oci/acme/api"
	if got := vexProductID(declared); got != "pkg:oci/acme/api@2.4.0" {
		t.Errorf("declared = %q, want the release's version appended", got)
	}

	// A version somebody wrote is left exactly as given: pinning to a digest is better practice
	// than pinning to a tag, and overriding it would be Draugr deciding it knows the artifact
	// better than the person who named it.
	pinned := base
	pinned.Publishes = "pkg:oci/acme/api@sha256:abc"
	if got := vexProductID(pinned); got != "pkg:oci/acme/api@sha256:abc" {
		t.Errorf("pinned = %q, want it left alone", got)
	}
}
