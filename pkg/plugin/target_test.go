package plugin

import (
	"slices"
	"testing"
)

func TestTargetKinds(t *testing.T) {
	cases := []struct {
		target Target
		kind   TargetKind
	}{
		{RepositoryTarget{URL: "u", Revision: "r"}, TargetRepository},
		{ImageTarget{Ref: "img:1"}, TargetImage},
		{HostTarget{URL: "https://x"}, TargetHost},
		{InfraTarget{Platform: "kubernetes", Ref: "prod"}, TargetInfra},
	}
	for _, c := range cases {
		if got := c.target.Kind(); got != c.kind {
			t.Errorf("%T.Kind() = %q, want %q", c.target, got, c.kind)
		}
	}
}

func TestTargetIdentity(t *testing.T) {
	if got := (RepositoryTarget{URL: "https://git/x", Revision: "1.0"}).Identity(); got != "https://git/x@1.0" {
		t.Errorf("repo identity = %q", got)
	}
	if got := (HostTarget{URL: "https://api"}).Identity(); got != "https://api" {
		t.Errorf("host identity = %q", got)
	}
	if got := (InfraTarget{Platform: "kubernetes", Ref: "prod"}).Identity(); got != "kubernetes/prod" {
		t.Errorf("infra identity = %q", got)
	}
}

func TestImageIdentityPrefersDigest(t *testing.T) {
	withDigest := ImageTarget{Ref: "img:1.0", Digest: "sha256:abc"}
	if got := withDigest.Identity(); got != "sha256:abc" {
		t.Errorf("identity should prefer digest, got %q", got)
	}
	withoutDigest := ImageTarget{Ref: "img:1.0"}
	if got := withoutDigest.Identity(); got != "img:1.0" {
		t.Errorf("identity should fall back to ref, got %q", got)
	}
}

func TestImagePinnedRef(t *testing.T) {
	cases := []struct {
		name   string
		target ImageTarget
		want   string
	}{
		{"ref and digest pin together", ImageTarget{Ref: "repo/x:1.0", Digest: "sha256:abc"}, "repo/x:1.0@sha256:abc"},
		{"ref only", ImageTarget{Ref: "repo/x:1.0"}, "repo/x:1.0"},
		{"digest only", ImageTarget{Digest: "sha256:abc"}, "sha256:abc"},
		{"already digest-pinned ref", ImageTarget{Ref: "repo/x@sha256:abc", Digest: "sha256:abc"}, "repo/x@sha256:abc"},
		{"empty", ImageTarget{}, ""},
	}
	for _, c := range cases {
		if got := c.target.PinnedRef(); got != c.want {
			t.Errorf("%s: PinnedRef() = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestRepositoryIdentitySeparatesAWorkingTreeFromItsCommit(t *testing.T) {
	// A working tree's content changes between two runs at the same revision, so sharing an
	// identity with the committed scan would let a content-addressed cache serve the previous
	// edit's findings — the exact opposite of what somebody iterating on a fix needs.
	committed := RepositoryTarget{URL: ".", Revision: "abc"}
	working := RepositoryTarget{URL: ".", Revision: "abc", WorkingTree: true}
	if committed.Identity() == working.Identity() {
		t.Errorf("both identify as %q", committed.Identity())
	}
}

func TestImageTargetContentAddressed(t *testing.T) {
	// The cache's correctness rests on this answer, and only a digest can give it. A tag is a
	// name someone can repoint at different bytes.
	for _, c := range []struct {
		name   string
		target ImageTarget
		want   bool
	}{
		{"a declared digest", ImageTarget{Ref: "alpine:3.19", Digest: "sha256:abc"}, true},
		{"a digest already in the ref", ImageTarget{Ref: "alpine@sha256:abc"}, true},
		{"a digest with no ref", ImageTarget{Digest: "sha256:abc"}, true},
		{"a tag alone", ImageTarget{Ref: "alpine:3.19"}, false},
		{"no tag at all, which means latest", ImageTarget{Ref: "alpine"}, false},
		{"nothing", ImageTarget{}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := c.target.ContentAddressed(); got != c.want {
				t.Errorf("ContentAddressed() = %v, want %v", got, c.want)
			}
		})
	}
}

// TestContentAddressedDefaultsToTrue pins the default for targets that do not answer. A
// repository at a revision and a host at a URL are content-addressed, and a helper that assumed
// the opposite would put a caveat on every run.
func TestContentAddressedDefaultsToTrue(t *testing.T) {
	for _, target := range []Target{
		RepositoryTarget{URL: "u", Revision: "r"},
		HostTarget{URL: "https://example.com"},
		ImageTarget{Digest: "sha256:abc"},
	} {
		if !ContentAddressed(target) {
			t.Errorf("%T should be treated as content-addressed", target)
		}
	}
	if ContentAddressed(ImageTarget{Ref: "alpine:3.19"}) {
		t.Error("a tag-only image says it is not content-addressed, and the helper must pass that on")
	}
}

func TestNormaliseMethods(t *testing.T) {
	for _, c := range []struct {
		name string
		in   []string
		want []string
	}{
		{"absent means read-only", nil, []string{"get", "head"}},
		{"blank means read-only", []string{"", "  "}, []string{"get", "head"}},
		{"lower-cased and sorted", []string{"POST", "get"}, []string{"get", "post"}},
		{"deduplicated", []string{"get", "GET"}, []string{"get"}},
		// A method the scan will never send is dropped rather than carried into the cache key,
		// where it would make two identical scans look different.
		{"unknown dropped", []string{"get", "connect"}, []string{"get"}},
		{"only unknown falls back", []string{"connect"}, []string{"get", "head"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := NormaliseMethods(c.in); !slices.Equal(got, c.want) {
				t.Errorf("NormaliseMethods(%v) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

// TestHostIdentitySeparatesScansThatAreNotComparable keeps the cache honest. The same URL scanned
// anonymously, scanned as a user, and driven from a specification are three different scans, and
// a shared key would let one answer for another.
func TestHostIdentitySeparatesScansThatAreNotComparable(t *testing.T) {
	base := HostTarget{URL: "https://api.example.com"}
	authed := base
	authed.Auth = &HostAuth{Kind: "bearer", TokenEnv: "TOK"}
	spec := base
	spec.Spec = &HostSpec{Path: "openapi.yaml"}
	writes := base
	writes.Spec = &HostSpec{Path: "openapi.yaml", Methods: []string{"get", "delete"}}

	ids := map[string]string{
		"anonymous":     base.Identity(),
		"authenticated": authed.Identity(),
		"spec":          spec.Identity(),
		"spec+writes":   writes.Identity(),
	}
	seen := map[string]string{}
	for name, id := range ids {
		if other, clash := seen[id]; clash {
			t.Errorf("%s and %s share a cache key (%q)", name, other, id)
		}
		seen[id] = name
	}
	// Case and order are presentation, not a different scan.
	same := base
	same.Spec = &HostSpec{Path: "openapi.yaml", Methods: []string{"DELETE", "get"}}
	if same.Identity() != writes.Identity() {
		t.Errorf("case and order changed the key:\n %q\n %q", same.Identity(), writes.Identity())
	}
}
