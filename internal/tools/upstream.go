package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Upstream says where a tool's releases are published and how to read the newest one.
//
// In Draugr rather than in a workflow, so one implementation answers both a person asking what is
// out of date and a pipeline proposing a bump. The alternative is release-API handling written
// twice, in Go and in YAML, where only the half somebody runs by hand stays true.
type Upstream struct {
	// Kind is how the newest version is read. Each is a different answer to the same question and
	// the difference is not cosmetic: see KindGitHubTag.
	Kind Kind
	// Ref names the thing to ask about: "owner/repo" on GitHub, a package name on PyPI or npm.
	Ref string
}

// Kind is a way of finding the newest published version.
type Kind string

const (
	// KindGitHubRelease reads the repository's latest *release*, which is what most projects
	// publish and what their users are told to install.
	KindGitHubRelease Kind = "github-release"
	// KindGitHubTag reads the newest semver *tag* instead.
	//
	// For a repository holding several modules the release marked latest is whichever was
	// published most recently, which is not the newest version of the command Draugr installs:
	// golang/vuln answers v1.1.4 there while its newest tag is v1.8.0. A resolver that trusted
	// the release would hold govulncheck seven minor versions back and report itself current.
	KindGitHubTag Kind = "github-tag"
	// KindPyPI reads the version PyPI serves as current.
	KindPyPI Kind = "pypi"
	// KindNPM reads the version tagged `latest` in the npm registry.
	KindNPM Kind = "npm"
)

// upstreams names where each pinned tool is published.
//
// Every tool Draugr provisions is here. A tool that is installable and absent from this map is one
// nothing can notice has gone stale, which is the drift this exists to end, so a test holds the two
// lists to each other rather than trusting this to be kept up.
var upstreams = map[string]Upstream{
	"trivy":       {KindGitHubRelease, "aquasecurity/trivy"},
	"cosign":      {KindGitHubRelease, "sigstore/cosign"},
	"notation":    {KindGitHubRelease, "notaryproject/notation"},
	"kube-bench":  {KindGitHubRelease, "aquasecurity/kube-bench"},
	"gosec":       {KindGitHubRelease, "securego/gosec"},
	"gitleaks":    {KindGitHubRelease, "gitleaks/gitleaks"},
	"syft":        {KindGitHubRelease, "anchore/syft"},
	"grype":       {KindGitHubRelease, "anchore/grype"},
	"nuclei":      {KindGitHubRelease, "projectdiscovery/nuclei"},
	"govulncheck": {KindGitHubTag, "golang/vuln"},
	"semgrep":     {KindPyPI, "semgrep"},
	"retire":      {KindNPM, "retire"},
}

// UpstreamFor reports where a tool is published.
func UpstreamFor(name string) (Upstream, bool) {
	u, ok := upstreams[name]
	return u, ok
}

// Drift is one tool, what Draugr pins, and what its upstream publishes.
type Drift struct {
	// Tool is the tool's name as Draugr and its own command line spell it.
	Tool string
	// Pinned is the version this build installs.
	Pinned string
	// Latest is what the upstream publishes now, empty where the question could not be answered.
	Latest string
	// Err is why Latest is empty. A network that refused is a different answer from "current",
	// and reporting the second for the first is how a checker comes to report everything current
	// while reaching nothing.
	Err error
}

// Behind reports whether the upstream has moved past the pin.
//
// Only a difference, never an ordering. Version schemes here are not comparable to each other and
// a pin ahead of its upstream is a real state, a release withdrawn after Draugr pinned it, which
// somebody needs to see rather than have reported as current.
func (d Drift) Behind() bool { return d.Err == nil && d.Latest != "" && d.Latest != d.Pinned }

// PinnedVersion is the version Draugr installs for a tool, whichever way it is packaged.
func PinnedVersion(name string) string {
	if spec, ok := Spec(name); ok {
		return spec.Version
	}
	if v := PythonVersion(name); v != "" {
		return v
	}
	if v := NodeVersion(name); v != "" {
		return v
	}
	return GoVersion(name)
}

// Outdated compares every pinned tool against its upstream, in name order.
//
// One entry per tool whatever happened, including the ones that could not be reached. A list that
// silently omits a tool nobody could ask about is a list that says everything is fine.
func Outdated(ctx context.Context, client *http.Client) []Drift {
	names := make([]string, 0, len(upstreams))
	for name := range upstreams {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]Drift, 0, len(names))
	for _, name := range names {
		d := Drift{Tool: name, Pinned: PinnedVersion(name)}
		d.Latest, d.Err = Latest(ctx, client, name)
		out = append(out, d)
	}
	return out
}

// Latest is the newest version an upstream publishes for a tool.
func Latest(ctx context.Context, client *http.Client, name string) (string, error) {
	up, ok := upstreams[name]
	if !ok {
		return "", fmt.Errorf("%s: no upstream is recorded for it", name)
	}
	if client == nil {
		client = http.DefaultClient
	}
	switch up.Kind {
	case KindGitHubRelease:
		return githubRelease(ctx, client, up.Ref)
	case KindGitHubTag:
		return githubTag(ctx, client, up.Ref)
	case KindPyPI:
		return pypiVersion(ctx, client, up.Ref)
	case KindNPM:
		return npmVersion(ctx, client, up.Ref)
	}
	return "", fmt.Errorf("%s: %q is not a way of finding a version", name, up.Kind)
}

// getJSON reads a JSON document, refusing a body large enough to be an attack on the reader.
func getJSON(ctx context.Context, client *http.Client, url string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "draugr")
	// GitHub rate-limits by source address for an unauthenticated caller, and a CI runner shares
	// its address with everybody else on the pool. A token here reads public release listings and
	// nothing else; the variable is the one every CI already sets, and its absence is ordinary.
	if token := os.Getenv("GITHUB_TOKEN"); token != "" && strings.HasPrefix(url, githubAPI) {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		// A rate limit answers 403 like a refusal does, and the two need different things from
		// the reader: one is waiting or a token, the other is a URL that is wrong. GitHub tells
		// them apart in a header, so this does too rather than leaving "403 Forbidden" to mean
		// both.
		if resp.Header.Get("X-RateLimit-Remaining") == "0" {
			return fmt.Errorf("%s rate-limited this machine; it resets shortly, or set "+
				"GITHUB_TOKEN to raise the limit", hostOf(url))
		}
		return fmt.Errorf("%s answered %s", url, resp.Status)
	}
	// A truncated body decodes as a JSON error, which reads as an upstream that answered badly
	// rather than as a limit of ours, so the limit is checked for what it is.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataForTest+1))
	if err != nil {
		return err
	}
	if int64(len(body)) > maxMetadataForTest {
		return fmt.Errorf("%s answered with more than %d bytes, which is more than any release "+
			"listing should be", url, maxMetadataForTest)
	}
	return json.Unmarshal(body, into)
}

// githubAPI is where a token is worth sending, and nowhere else is.
const githubAPI = "https://api.github.com/"

// hostOf names the service in a message, because the full URL is Draugr's business and the reader
// needs to know which upstream went quiet.
func hostOf(url string) string {
	rest := strings.TrimPrefix(strings.TrimPrefix(url, "https://"), "http://")
	host, _, _ := strings.Cut(rest, "/")
	return host
}

// maxMetadataBytes caps a release listing.
//
// Generous, because these documents carry every release a package ever made rather than the one
// being asked about: PyPI answers 1.5 MB for Semgrep and npm 300 KB for retire.js, and both grow
// with every version published. A megabyte was under the first of them, which truncated the JSON
// and reported the tool as unreachable. 64 MiB is far above anything published and far below
// anything that would hurt.
const maxMetadataBytes = 64 << 20

// maxMetadataForTest is the limit actually applied, so a test can shrink it rather than serve
// sixty-four megabytes to prove the guard works.
var maxMetadataForTest int64 = maxMetadataBytes

func githubRelease(ctx context.Context, client *http.Client, repo string) (string, error) {
	var payload struct {
		Tag string `json:"tag_name"`
	}
	url := "https://api.github.com/repos/" + repo + "/releases/latest"
	if err := getJSON(ctx, client, url, &payload); err != nil {
		return "", err
	}
	if payload.Tag == "" {
		return "", fmt.Errorf("%s names no latest release", repo)
	}
	return strings.TrimPrefix(payload.Tag, "v"), nil
}

// githubTag is the newest semver tag, compared as numbers.
//
// Ordered here rather than taken from the top of the list, because the API returns tags in the
// repository's own order and a repository holding several modules interleaves theirs. Anything
// that is not a plain `vX.Y.Z` is skipped: a prerelease and a module-scoped tag are both real and
// neither is what Draugr would install.
func githubTag(ctx context.Context, client *http.Client, repo string) (string, error) {
	return githubTagAt(ctx, client, "https://api.github.com/repos/"+repo+"/tags?per_page=100")
}

// githubTagAt is githubTag against a given listing, so a test can serve one.
func githubTagAt(ctx context.Context, client *http.Client, url string) (string, error) {
	var tags []struct {
		Name string `json:"name"`
	}
	if err := getJSON(ctx, client, url, &tags); err != nil {
		return "", err
	}
	best := ""
	var bestParts []int
	for _, t := range tags {
		parts, ok := semver(t.Name)
		if !ok {
			continue
		}
		if best == "" || newer(parts, bestParts) {
			best, bestParts = strings.TrimPrefix(t.Name, "v"), parts
		}
	}
	if best == "" {
		return "", fmt.Errorf("%s publishes no vX.Y.Z tag", url)
	}
	return best, nil
}

// semver reads a plain `vX.Y.Z` tag, and reports whether it was one.
func semver(tag string) ([]int, bool) {
	fields := strings.Split(strings.TrimPrefix(tag, "v"), ".")
	if len(fields) != 3 {
		return nil, false
	}
	out := make([]int, 3)
	for i, f := range fields {
		n, err := strconv.Atoi(f)
		if err != nil {
			return nil, false
		}
		out[i] = n
	}
	return out, true
}

// newer reports whether a is a higher version than b.
func newer(a, b []int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return false
}

func pypiVersion(ctx context.Context, client *http.Client, pkg string) (string, error) {
	var payload struct {
		Info struct {
			Version string `json:"version"`
		} `json:"info"`
	}
	if err := getJSON(ctx, client, "https://pypi.org/pypi/"+pkg+"/json", &payload); err != nil {
		return "", err
	}
	if payload.Info.Version == "" {
		return "", errors.New("pypi names no current version for " + pkg)
	}
	return payload.Info.Version, nil
}

func npmVersion(ctx context.Context, client *http.Client, pkg string) (string, error) {
	var payload struct {
		DistTags map[string]string `json:"dist-tags"`
	}
	if err := getJSON(ctx, client, "https://registry.npmjs.org/"+pkg, &payload); err != nil {
		return "", err
	}
	if payload.DistTags["latest"] == "" {
		return "", errors.New("npm names no latest version for " + pkg)
	}
	return payload.DistTags["latest"], nil
}
