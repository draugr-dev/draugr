package scanners

import (
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// Trivy names an operating system it has no advisory data for in the image's metadata and returns
// no result set for its packages; a supported one always has that set, vulnerabilities or not. The
// first is an unread input naming the image and the distribution, and the second is not. The two
// documents are the shape Trivy 0.76.1 wrote for a CentOS Stream 9 and an Alpine 3.22 image.
func TestAnImageWhoseOperatingSystemTrivyDoesNotSupportIsSaidToBeUnread(t *testing.T) {
	img := plugin.ImageTarget{Ref: "registry.example/app:1", Digest: "sha256:" + strings.Repeat("a", 64)}
	unsupported := []byte(`{"Metadata":{"OS":{"Family":"centos-stream","Name":"9"}},"Results":[]}`)
	supported := []byte(`{"Metadata":{"OS":{"Family":"alpine","Name":"3.22.8"}},"Results":[` +
		`{"Target":"registry.example/app:1 (alpine 3.22.8)","Class":"os-pkgs","Type":"alpine"}]}`)
	noOS := []byte(`{"Metadata":{},"Results":[]}`)

	rep, err := parseTrivyImage(unsupported, img, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Inputs) != 1 {
		t.Fatalf("inputs = %+v, want the operating system unread", rep.Inputs)
	}
	in := rep.Inputs[0]
	if in.Kind != sarif.InputOperatingSystem || in.Path != img.PinnedRef() ||
		in.Unread != "centos-stream 9 not supported by trivy, OS packages not checked" {
		t.Errorf("input = %+v", in)
	}
	for name, out := range map[string][]byte{"a supported OS": supported, "no OS identified": noOS} {
		if rep, _ := parseTrivyImage(out, img, nil); len(rep.Inputs) != 0 {
			t.Errorf("%s: inputs = %+v, want none", name, rep.Inputs)
		}
	}
	// A scan narrowed to libraries asked for no OS packages, so their absence is not a skip.
	if rep, _ := parseTrivyImage(unsupported, img, plugin.Config{"pkgTypes": []any{"library"}}); len(rep.Inputs) != 0 {
		t.Errorf("a library-only scan: inputs = %+v, want none", rep.Inputs)
	}
	if _, err := parseTrivyImage([]byte("not json"), img, nil); err == nil {
		t.Error("a document that does not parse is not an error")
	}
}
