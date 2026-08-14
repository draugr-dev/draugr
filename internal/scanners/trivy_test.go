package scanners

import (
	"slices"
	"testing"

	"github.com/draugr-dev/draugr/internal/netpolicy"

	"github.com/draugr-dev/draugr/pkg/plugin"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

func TestTrivyInfo(t *testing.T) {
	info := NewTrivy().Info()
	if info.Name != "trivy" {
		t.Errorf("name = %q", info.Name)
	}
	if len(info.Controls) != 1 || info.Controls[0] != "images" {
		t.Errorf("controls = %v", info.Controls)
	}
}

func TestTrivyArgv(t *testing.T) {
	argv, err := trivyArgv(plugin.ImageTarget{Ref: "repo/app:1.0"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"trivy", "image", "--quiet", "--format", "sarif", "repo/app:1.0"}
	if len(argv) != len(want) {
		t.Fatalf("argv = %v", argv)
	}
	for i := range want {
		if argv[i] != want[i] {
			t.Fatalf("argv[%d] = %q, want %q", i, argv[i], want[i])
		}
	}
}

func TestTrivyArgvPrefersRefThenDigest(t *testing.T) {
	argv, _ := trivyArgv(plugin.ImageTarget{Digest: "sha256:abc"}, nil)
	if argv[len(argv)-1] != "sha256:abc" {
		t.Errorf("should fall back to digest, got %v", argv)
	}
}

func TestTrivyArgvPinsDigest(t *testing.T) {
	// With both a ref and a digest, Trivy should pull the digest-pinned reference so the
	// scanned bytes match the digest the result is cached under.
	argv, _ := trivyArgv(plugin.ImageTarget{Ref: "repo/app:1.0", Digest: "sha256:abc"}, nil)
	if got := argv[len(argv)-1]; got != "repo/app:1.0@sha256:abc" {
		t.Errorf("should scan the pinned ref, got %q", got)
	}
}

func TestTrivyArgvErrors(t *testing.T) {
	if _, err := trivyArgv(plugin.RepositoryTarget{URL: "u"}, nil); err == nil {
		t.Error("non-image target should error")
	}
	if _, err := trivyArgv(plugin.ImageTarget{}, nil); err == nil {
		t.Error("image target with no ref/digest should error")
	}
}

func TestTrivyFSInfo(t *testing.T) {
	info := NewTrivyFS().Info()
	if info.Name != "trivy-fs" {
		t.Errorf("name = %q", info.Name)
	}
	if len(info.Controls) != 1 || info.Controls[0] != "sca" {
		t.Errorf("controls = %v", info.Controls)
	}
}

func TestTrivyFSArgs(t *testing.T) {
	argv := trivyFSArgs("/work/repo", nil)
	// json, not sarif: Trivy's SARIF states the package only in prose. See trivy_vuln_json.go.
	want := []string{"trivy", "fs", "--quiet", "--scanners", "vuln", "--format", "json", "/work/repo"}
	if len(argv) != len(want) {
		t.Fatalf("argv = %v", argv)
	}
	for i := range want {
		if argv[i] != want[i] {
			t.Fatalf("argv[%d] = %q, want %q", i, argv[i], want[i])
		}
	}
}

// Trivy names an image finding after the registry path with the tag dropped, at line 1. That
// isn't where the finding is, and it makes two images in one component indistinguishable.
func TestTrivyImageLocationsUseTheScannedReference(t *testing.T) {
	in := sarif.Report{Results: []sarif.Result{
		{RuleID: "CVE-1", Location: sarif.Location{URI: "library/python", StartLine: 1}},
		{RuleID: "CVE-2", Location: sarif.Location{URI: "library/python", StartLine: 1}},
	}}
	got := trivyImageLocations(plugin.ImageTarget{Ref: "python:3.8-slim"}, in)
	for _, res := range got.Results {
		if res.Location.URI != "python:3.8-slim" {
			t.Errorf("uri = %q, want the image we scanned", res.Location.URI)
		}
		// A line number is meaningless for an image, and renders as "python:3.8-slim:1".
		if res.Location.StartLine != 0 {
			t.Errorf("startLine = %d, want none", res.Location.StartLine)
		}
	}

	// A digest-pinned target reports the pinned reference, so the finding names exactly what
	// was pulled.
	pinned := trivyImageLocations(
		plugin.ImageTarget{Ref: "python:3.8-slim", Digest: "sha256:abc"},
		sarif.Report{Results: []sarif.Result{{Location: sarif.Location{URI: "library/python"}}}})
	if got := pinned.Results[0].Location.URI; got != "python:3.8-slim@sha256:abc" {
		t.Errorf("uri = %q, want the pinned reference", got)
	}

	// Anything that isn't an image target, or has no reference to report, is left alone.
	untouched := sarif.Report{Results: []sarif.Result{{Location: sarif.Location{URI: "a/b.go", StartLine: 7}}}}
	for _, target := range []plugin.Target{plugin.RepositoryTarget{URL: "."}, plugin.ImageTarget{}} {
		if got := trivyImageLocations(target, untouched); got.Results[0].Location.URI != "a/b.go" {
			t.Errorf("%T: location was rewritten to %q", target, got.Results[0].Location.URI)
		}
	}
}

func TestOfflineTrivyArgs(t *testing.T) {
	// Online: untouched. Adding flags nobody asked for would change what runs and what the
	// cache key covers.
	if got := trivyFSArgs("/src", nil); slices.Contains(got, "--skip-db-update") {
		t.Errorf("online argv carries the offline flag: %v", got)
	}

	netpolicy.SetOffline(true)
	t.Cleanup(func() { netpolicy.SetOffline(false) })

	// Skipping the prewarm is not enough: Trivy refreshes at scan time too, so an offline run
	// would still reach out once per job without this.
	for name, argv := range map[string][]string{
		"fs":     trivyFSArgs("/src", nil),
		"config": trivyConfigArgs("/src", nil),
	} {
		if !slices.Contains(argv, "--skip-db-update") {
			t.Errorf("%s: %v", name, argv)
		}
		// The target stays last: Trivy takes its flags before the positional argument.
		if argv[len(argv)-1] != "/src" {
			t.Errorf("%s: target is no longer last: %v", name, argv)
		}
	}

	img, err := trivyArgv(plugin.ImageTarget{Ref: "acme/api:1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(img, "--skip-db-update") || img[len(img)-1] != "acme/api:1" {
		t.Errorf("image argv: %v", img)
	}
}
