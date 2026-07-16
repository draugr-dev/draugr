package plugin

import "testing"

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
