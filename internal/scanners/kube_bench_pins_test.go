package scanners

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/tools"
)

// kubeBenchWorkflowVersion is the release integration.yml fetches the CIS definitions at.
var kubeBenchWorkflowVersion = regexp.MustCompile(`(?m)^\s*KUBE_BENCH_VERSION:\s*"([^"]*)"`)

// kubeBenchPinDisagreements names every place whose kube-bench release differs from the binary
// `draugr tools install` pins. Empty when the binary, the Job's image and the catalog check all
// name one release.
func kubeBenchPinDisagreements(binary, image, workflow string) []string {
	want := "v" + binary
	var out []string
	tag := ""
	if at := strings.Index(image, "@"); at > 0 {
		if colon := strings.LastIndex(image[:at], ":"); colon > 0 {
			tag = image[colon+1 : at]
		}
	}
	if tag != want {
		out = append(out, "defaultKubeBenchImage in internal/scanners/kube_bench_job.go is "+
			image+", tagged "+quoteOrNone(tag)+", not "+want)
	}
	m := kubeBenchWorkflowVersion.FindStringSubmatch(workflow)
	got := ""
	if m != nil {
		got = m[1]
	}
	if got != want {
		out = append(out, "KUBE_BENCH_VERSION in .github/workflows/integration.yml is "+
			quoteOrNone(got)+", not "+want)
	}
	return out
}

func quoteOrNone(s string) string {
	if s == "" {
		return "nothing"
	}
	return `"` + s + `"`
}

// TestKubeBenchJobImageIsTheInstalledRelease holds the kube-bench release in three places to one
// value: the binary the kube-bench scanner runs, the image the kube-bench-job scanner runs, and the
// definitions the integration suite checks the CIS catalog against.
//
// The weekly tool bump moves the binary alone, because the binary is what `tools outdated` reads.
// Left to drift, the two scanners audit one cluster against different benchmark definitions, and
// the catalog is checked against a release neither of them runs. This test turns that bump red
// until the other two move with it.
func TestKubeBenchJobImageIsTheInstalledRelease(t *testing.T) {
	t.Parallel()
	binary := tools.PinnedVersion("kube-bench")
	if binary == "" {
		t.Fatal("draugr tools install pins no kube-bench, so there is no release to hold the image to")
	}
	workflow, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "integration.yml"))
	if err != nil {
		t.Fatalf("read the integration workflow: %v", err)
	}
	problems := kubeBenchPinDisagreements(binary, defaultKubeBenchImage, string(workflow))
	if len(problems) == 0 {
		return
	}
	t.Errorf("draugr tools install pins kube-bench %s, and:\n  %s\n\n"+
		"Move each to v%[1]s, reading the values rather than typing them:\n"+
		"  defaultKubeBenchImage (internal/scanners/kube_bench_job.go, and the example in kube-bench-job.md):\n"+
		"      docker buildx imagetools inspect docker.io/aquasec/kube-bench:v%[1]s\n"+
		"      (the index's Digest line, the one above Manifests)\n"+
		"  KUBE_BENCH_VERSION and KUBE_BENCH_COMMIT (.github/workflows/integration.yml):\n"+
		"      gh api repos/aquasecurity/kube-bench/git/ref/tags/v%[1]s --jq .object.sha\n"+
		"      (if .object.type is \"tag\", the tag is annotated: gh api repos/aquasecurity/kube-bench/git/tags/<sha> --jq .object.sha)\n"+
		"Then check the CIS catalog against that release's definitions, from a checkout of kube-bench at v%[1]s:\n"+
		"  KUBE_BENCH_CFG=<checkout>/cfg go test -tags integration ./internal/scanners -run 'TestCISCatalogMatchesKubeBench|TestManagedServicesCountsMatchKubeBench'",
		binary, strings.Join(problems, "\n  "))
}

// TestKubeBenchPinDisagreementsNamesEachPlace proves the guard above fails for each place it
// reads, so a regular expression that stopped matching cannot pass it by finding nothing.
func TestKubeBenchPinDisagreementsNamesEachPlace(t *testing.T) {
	t.Parallel()
	const (
		image    = "docker.io/aquasec/kube-bench:v1.2.3@sha256:abc"
		workflow = "env:\n  KUBE_BENCH_VERSION: \"v1.2.3\"\n"
	)
	if got := kubeBenchPinDisagreements("1.2.3", image, workflow); len(got) != 0 {
		t.Errorf("one release in all three places reported %q", got)
	}

	cases := []struct {
		name, image, workflow, want string
	}{
		{"older image", "docker.io/aquasec/kube-bench:v1.2.2@sha256:abc", workflow, `tagged "v1.2.2", not v1.2.3`},
		{"image by digest alone", "docker.io/aquasec/kube-bench@sha256:abc", workflow, "tagged nothing"},
		{"image by tag alone", "docker.io/aquasec/kube-bench:v1.2.3", workflow, "tagged nothing"},
		{"older workflow", image, "env:\n  KUBE_BENCH_VERSION: \"v1.2.2\"\n", `KUBE_BENCH_VERSION in .github/workflows/integration.yml is "v1.2.2"`},
		{"workflow without the variable", image, "env:\n  GO_VERSION: \"1.26.10\"\n", "KUBE_BENCH_VERSION in .github/workflows/integration.yml is nothing"},
	}
	for _, c := range cases {
		got := kubeBenchPinDisagreements("1.2.3", c.image, c.workflow)
		if len(got) != 1 || !strings.Contains(got[0], c.want) {
			t.Errorf("%s: got %q, want one disagreement containing %q", c.name, got, c.want)
		}
	}
}

// platformBenchmark is kube-bench's table copied, so it is read again whenever the release Draugr
// installs moves. A table older than the binary names an older benchmark than kube-bench would.
func TestThePlatformBenchmarksFollowThePinnedKubeBench(t *testing.T) {
	t.Parallel()
	if pinned := tools.PinnedVersion("kube-bench"); pinned != platformBenchmarksFor {
		t.Errorf("draugr tools install pins kube-bench %s, and platformBenchmark (internal/scanners/kube_bench_platform.go) "+
			"was read from %s. Read getPlatformBenchmarkVersion in cmd/util.go at v%[1]s, copy any change, and set "+
			"platformBenchmarksFor to %[1]s:\n"+
			"    gh api repos/aquasecurity/kube-bench/contents/cmd/util.go?ref=v%[1]s --jq .content | base64 -d",
			pinned, platformBenchmarksFor)
	}
	// Every platform the parser recognizes has a benchmark, and each is one the parser's prefix
	// allows, so verifyBenchmark accepts what this names.
	for platform, prefix := range platformBenchmarkPrefix {
		if b := platformBenchmark(platform, "1.35"); !strings.HasPrefix(b, prefix) {
			t.Errorf("platformBenchmark(%q) = %q, want a name starting %q", platform, b, prefix)
		}
	}
	if b := platformBenchmark("ocp", "4.14"); b != "" {
		t.Errorf("platformBenchmark names %q for a platform Draugr does not detect", b)
	}
}
