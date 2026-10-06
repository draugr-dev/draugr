package plugin

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
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
		{KubernetesTarget{Cluster: "prod"}, TargetKubernetes},
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
	if got := (KubernetesTarget{Cluster: "prod"}).Identity(); got != "kubernetes/prod" {
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
	// A working tree's content changes between two runs at the same revision, so sharing an identity
	// with the committed scan would let a content-addressed cache serve the previous edit's
	// findings, the exact opposite of what somebody iterating on a fix needs.
	committed := RepositoryTarget{URL: ".", Revision: "abc"}
	working := RepositoryTarget{URL: ".", Revision: "abc", WorkingTree: true}
	if committed.Identity() == working.Identity() {
		t.Errorf("both identify as %q", committed.Identity())
	}
}

// A repository's scope decides what a scanner reads, so every part of it is part of the identity.
// Two components on one repository that differ only in their paths, or only in what they ignore,
// are two scans, and a shared identity lets one answer for the other from the cache and dedupes
// them into a single run whose findings both receive.
func TestRepositoryIdentityCarriesEachPartOfTheScope(t *testing.T) {
	base := RepositoryTarget{URL: "https://git/mono", Revision: "v2"}
	scoped := func(paths, ignore []string) RepositoryTarget {
		r := base
		r.Paths, r.Ignore = paths, ignore
		return r
	}
	for name, pair := range map[string][2]RepositoryTarget{
		"only the paths differ":        {scoped([]string{"services/web"}, nil), scoped([]string{"services/api"}, nil)},
		"only the ignore lists differ": {scoped(nil, []string{"vendor/"}), scoped(nil, []string{"testdata/"})},
		"paths against none":           {base, scoped([]string{"services/web"}, nil)},
		"an ignore list against none":  {base, scoped(nil, []string{"vendor/"})},
		"one entry, path or ignored":   {scoped([]string{"vendor"}, nil), scoped(nil, []string{"vendor"})},
		"same paths, another ignore": {
			scoped([]string{"services"}, []string{"services/web/"}),
			scoped([]string{"services"}, []string{"services/api/"}),
		},
	} {
		if a, b := pair[0].Identity(), pair[1].Identity(); a == b {
			t.Errorf("%s: both identify as %q", name, a)
		}
	}
}

// An account's regions narrow what a scan reports, so two components claiming different regions
// of one account are two scans, and a shared identity would hand one the other's findings. The
// same regions in another order are the same question, so they share one identity.
func TestAccountIdentityCarriesTheRegions(t *testing.T) {
	whole := AccountTarget{Account: "prod", Provider: "gcp", ID: "shop-prod-4821"}
	us := AccountTarget{Account: "prod", Provider: "gcp", ID: "shop-prod-4821", Regions: []string{"us-east1", "us-central1"}}
	reordered := AccountTarget{Account: "prod", Provider: "gcp", ID: "shop-prod-4821", Regions: []string{"us-central1", "us-east1"}}
	eu := AccountTarget{Account: "prod", Provider: "gcp", ID: "shop-prod-4821", Regions: []string{"europe-west1"}}

	if got := us.Identity(); got != "gcp/shop-prod-4821[us-central1,us-east1]" {
		t.Errorf("identity = %q, want the regions sorted after the ID", got)
	}
	if us.Identity() != reordered.Identity() {
		t.Errorf("the same regions in another order gave another identity: %q, %q", us.Identity(), reordered.Identity())
	}
	for _, other := range []AccountTarget{whole, eu} {
		if us.Identity() == other.Identity() {
			t.Errorf("%v and %v share an identity", us.Regions, other.Regions)
		}
	}
	if !slices.Equal(us.Regions, []string{"us-east1", "us-central1"}) {
		t.Error("Identity reordered the target's own regions")
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

func TestNormalizeMethods(t *testing.T) {
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
			if got := NormalizeMethods(c.in); !slices.Equal(got, c.want) {
				t.Errorf("NormalizeMethods(%v) = %v, want %v", c.in, got, c.want)
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

// identities differ; the same namespaces in another order ask the same one, so theirs do not.
func TestKubernetesIdentityCarriesTheNamespaces(t *testing.T) {
	whole := KubernetesTarget{Cluster: "prod"}
	teamA := KubernetesTarget{Cluster: "prod", Namespaces: []string{"payments", "api"}}
	reordered := KubernetesTarget{Cluster: "prod", Namespaces: []string{"api", "payments"}}
	teamB := KubernetesTarget{Cluster: "prod", Namespaces: []string{"search"}}

	if got := teamA.Identity(); got != "kubernetes/prod[api,payments]" {
		t.Errorf("identity = %q, want the namespaces sorted after the ref", got)
	}
	if teamA.Identity() != reordered.Identity() {
		t.Error("the same namespaces in another order gave another identity")
	}
	for _, other := range []KubernetesTarget{whole, teamB} {
		if teamA.Identity() == other.Identity() {
			t.Errorf("%v and %v share an identity", teamA, other)
		}
	}
	if !slices.Equal(teamA.Namespaces, []string{"payments", "api"}) {
		t.Error("Identity reordered the target's own namespaces")
	}
}

// name whatever they point at today.
func TestRepositoryPinnedOnlyByAFullCommit(t *testing.T) {
	for rev, want := range map[string]bool{
		"0123456789abcdef0123456789abcdef01234567": true,
		"0123456789ABCDEF0123456789ABCDEF01234567": false,
		"0123456": false,
		"main":    false,
		"v1.4.2":  false,
		"":        false,
		"0123456789abcdef0123456789abcdef012345678": false,
	} {
		if got := (RepositoryTarget{URL: "https://example.com/r", Revision: rev}).Pinned(); got != want {
			t.Errorf("Pinned(%q) = %v, want %v", rev, got, want)
		}
	}
}

// answer; a cluster answers with operatedBy instead and does not implement it.
func TestRepositoriesAndImagesSayWhoPublishesThem(t *testing.T) {
	for _, tc := range []struct {
		target Target
		want   bool
	}{
		{RepositoryTarget{URL: "u", Upstream: true}, true},
		{RepositoryTarget{URL: "u"}, false},
		{ImageTarget{Ref: "app:1", Upstream: true}, true},
		{ImageTarget{Ref: "app:1"}, false},
	} {
		up, ok := tc.target.(UpstreamPublished)
		if !ok {
			t.Fatalf("%T does not implement UpstreamPublished", tc.target)
		}
		if got := up.BuiltUpstream(); got != tc.want {
			t.Errorf("%T.BuiltUpstream() = %v, want %v", tc.target, got, tc.want)
		}
	}
	if _, ok := Target(KubernetesTarget{}).(UpstreamPublished); ok {
		t.Error("a cluster answers who runs it with operatedBy, not with BuiltUpstream")
	}
}

// A cluster's context and benchmark decide what a scan of it returns without being part of its
// identity, which a report shows and which stays the same on every machine. They reach the cache
// key, so a run through another context or against another benchmark is never answered with an
// earlier one, and two components on the same cluster still share one scan.
func TestAClustersFactsSeparateCacheEntriesButNotIdentities(t *testing.T) {
	base := KubernetesTarget{Cluster: "prod", Context: "prod-admin", Benchmark: "eks-1.5.0"}
	if base.Identity() != "kubernetes/prod" {
		t.Errorf("identity = %q, want the cluster's name alone", base.Identity())
	}
	key := func(t Target) CacheKey { return ComputeCacheKey("draugr-k8s-policies", "1", t, nil) }
	if key(base) != key(KubernetesTarget{Cluster: "prod", Context: "prod-admin", Benchmark: "eks-1.5.0"}) {
		t.Error("the same cluster gave two cache keys, so two components on it would scan twice")
	}
	for name, other := range map[string]KubernetesTarget{
		"another context":   {Cluster: "prod", Context: "staging-admin", Benchmark: "eks-1.5.0"},
		"another benchmark": {Cluster: "prod", Context: "prod-admin", Benchmark: "cis-1.10"},
		"another version":   {Cluster: "prod", Context: "prod-admin", Benchmark: "eks-1.5.0", Version: "1.30"},
	} {
		if key(base) == key(other) {
			t.Errorf("%s shares the cache key", name)
		}
		if base.Identity() != other.Identity() {
			t.Errorf("%s changed the identity", name)
		}
	}
}

// Components carved out of one module share a checkout and are analyzed from their own code. The
// checkout is named by the identity, so Entry stays out of it, and the analysis by the cache key,
// so Entry is in it. A target with no Entry keys exactly as it did before there was one.
func TestRepositoryEntryKeysTheAnalysisNotTheCheckout(t *testing.T) {
	widened := RepositoryTarget{URL: "https://git/mono", Revision: "v2", Paths: []string{"."}}
	api, admin := widened, widened
	api.Entry = []string{"go.mod", "cmd/api"}
	admin.Entry = []string{"cmd/admin", "go.mod"}

	if api.Identity() != widened.Identity() || admin.Identity() != widened.Identity() {
		t.Errorf("identities %q and %q, want both %q: one checkout serves both", api.Identity(), admin.Identity(), widened.Identity())
	}
	key := func(t Target) CacheKey { return ComputeCacheKey("govulncheck", "1", t, nil) }
	if key(api) == key(admin) {
		t.Error("api and admin share a cache key, so one component's call graph would answer for the other")
	}
	reordered := api
	reordered.Entry = []string{"cmd/api", "go.mod"}
	if key(api) != key(reordered) {
		t.Error("the same entry paths in another order key differently")
	}
	if widened.CacheDetail() != "" {
		t.Errorf("CacheDetail() = %q with no Entry, want empty", widened.CacheDetail())
	}
	// The key a target with no Entry had before Entry existed: the parts ComputeCacheKey joins,
	// with no detail among them.
	sum := sha256.Sum256([]byte(strings.Join([]string{"govulncheck", "1", string(TargetRepository), widened.Identity()}, "\x00")))
	if got, want := key(widened), CacheKey(hex.EncodeToString(sum[:])); got != want {
		t.Errorf("key = %s, want %s: an empty detail must not move every repository's cache entry", got, want)
	}
}
