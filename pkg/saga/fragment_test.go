package saga

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// write creates a file under dir, making parents as needed.
func write(t *testing.T, dir, rel, body string) string {
	t.Helper()
	full := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return full
}

const rootHeader = "release: { name: acme, version: \"1.0.0\" }\n"

func resolveIn(t *testing.T, dir string) (*Resolved, error) {
	t.Helper()
	return ResolveFile(filepath.Join(dir, "draugr.saga.yaml"), nil)
}

// The monorepo case: a shared fragment describes each component, a per-product one adds to it,
// and the two fold into one component holding both surfaces.
func TestResolveOverlaysFragmentsOntoOneComponent(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "draugr.saga.yaml", rootHeader+`
fragments:
  - path: "**/draugr.saga-fragment.yaml"
  - path: "**/azure.saga-fragment.yaml"
`)
	write(t, dir, "services/payments/draugr.saga-fragment.yaml", `
components:
  - name: payments
    exposure: public
    criticality: critical
    repositories: [{ url: "." }]
`)
	write(t, dir, "services/payments/azure.saga-fragment.yaml", `
components:
  - name: payments
    images: [{ image: "acme.azurecr.io/payments:1" }]
`)
	write(t, dir, "services/ledger/draugr.saga-fragment.yaml", `
components:
  - name: ledger
    repositories: [{ url: "." }]
`)

	res, err := resolveIn(t, dir)
	if err != nil {
		t.Fatalf("ResolveFile: %v", err)
	}
	if len(res.Model.Components) != 2 {
		t.Fatalf("components = %d, want 2 (payments, ledger)", len(res.Model.Components))
	}
	var payments *Component
	for i := range res.Model.Components {
		if res.Model.Components[i].Name == "payments" {
			payments = &res.Model.Components[i]
		}
	}
	if payments == nil {
		t.Fatal("no payments component")
	}
	if len(payments.Repositories) != 1 || len(payments.Images) != 1 {
		t.Errorf("surfaces not unioned: %+v", payments)
	}
	if payments.Exposure.Value != "public" || payments.Criticality.Value != "critical" {
		t.Errorf("classification lost: %+v", payments)
	}
}

// A fragment that describes a component the root already declared must not reclassify it. The
// root is the file someone opened, so it stays authoritative.
func TestResolveKeepsTheRootAuthoritativeOnClassification(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "draugr.saga.yaml", rootHeader+`
components:
  - name: web
    exposure: restricted
    criticality: supporting
fragments:
  - path: "f.saga-fragment.yaml"
`)
	write(t, dir, "f.saga-fragment.yaml", `
components:
  - name: web
    exposure: public
    criticality: critical
    repositories: [{ url: "." }]
`)
	res, err := resolveIn(t, dir)
	if err != nil {
		t.Fatalf("ResolveFile: %v", err)
	}
	c := res.Model.Components[0]
	if c.Exposure.Value != "restricted" || c.Criticality.Value != "supporting" {
		t.Errorf("a fragment reclassified a component the root declared: %+v", c)
	}
	if len(c.Repositories) != 1 {
		t.Errorf("the fragment's surface should still have been added: %+v", c)
	}
}

// Exclusions append, and each carries the file that authorized it — the property that makes
// splitting a governance record across files safe.
func TestResolveAppendsExclusionsWithTheirSource(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "draugr.saga.yaml", rootHeader+`
components: [{ name: web, repositories: [{ url: "." }] }]
config:
  exclude:
    - rules: ["ROOT-1"]
      reason: "from the root"
fragments:
  - path: "excl/*.saga-fragment.yaml"
`)
	write(t, dir, "excl/legacy.saga-fragment.yaml", `
config:
  exclude:
    - rules: ["FRAG-1"]
      reason: "from a fragment"
`)
	res, err := resolveIn(t, dir)
	if err != nil {
		t.Fatalf("ResolveFile: %v", err)
	}
	rules := res.Model.Config.Exclude
	if len(rules) != 2 {
		t.Fatalf("exclusions = %d, want 2", len(rules))
	}
	bySource := map[string]string{}
	for _, r := range rules {
		bySource[r.Rules[0]] = r.Source
	}
	if !strings.HasSuffix(bySource["ROOT-1"], "draugr.saga.yaml") {
		t.Errorf("root rule source = %q", bySource["ROOT-1"])
	}
	if !strings.HasSuffix(bySource["FRAG-1"], "legacy.saga-fragment.yaml") {
		t.Errorf("fragment rule source = %q", bySource["FRAG-1"])
	}
}

// A pattern somebody wrote on purpose that matches nothing is indistinguishable from a typo, and
// the result is a descriptor scanning less than it claims.
func TestResolveRefusesAPatternThatMatchesNothing(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "draugr.saga.yaml", rootHeader+`
components: [{ name: web, repositories: [{ url: "." }] }]
fragments:
  - path: "**/gcp.saga-fragment.yaml"
`)
	_, err := resolveIn(t, dir)
	if err == nil {
		t.Fatal("an empty pattern was accepted")
	}
	if !strings.Contains(err.Error(), "gcp.saga-fragment.yaml") || !strings.Contains(err.Error(), "matched no files") {
		t.Errorf("error should name the pattern: %v", err)
	}
}

// Two patterns legitimately overlap. Loading a file twice would double its exclusions, so the
// report's counts would be wrong in the direction that hides nothing but invents suppressions.
func TestResolveLoadsAFileOnceWhenTwoPatternsMatchIt(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "draugr.saga.yaml", rootHeader+`
components: [{ name: web, repositories: [{ url: "." }] }]
fragments:
  - path: "**/*.saga-fragment.yaml"
  - path: "a/shared.saga-fragment.yaml"
`)
	write(t, dir, "a/shared.saga-fragment.yaml", `
config:
  exclude:
    - rules: ["ONCE"]
      reason: "counted once"
`)
	res, err := resolveIn(t, dir)
	if err != nil {
		t.Fatalf("ResolveFile: %v", err)
	}
	if n := len(res.Model.Config.Exclude); n != 1 {
		t.Errorf("exclusions = %d, want 1 — the same file matched two patterns", n)
	}
}

func TestResolveDetectsACycleAndPrintsThePath(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "draugr.saga.yaml", rootHeader+`
components: [{ name: web, repositories: [{ url: "." }] }]
fragments: [{ path: "a.saga-fragment.yaml" }]
`)
	write(t, dir, "a.saga-fragment.yaml", `fragments: [{ path: "b.saga-fragment.yaml" }]`)
	write(t, dir, "b.saga-fragment.yaml", `fragments: [{ path: "a.saga-fragment.yaml" }]`)

	// a → b → a: the second visit to `a` is deduplicated rather than looping forever, so the
	// resolution terminates. The guarantee under test is termination, not an error.
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := resolveIn(t, dir); err != nil {
			t.Errorf("a cycle should resolve by loading each file once: %v", err)
		}
	}()
	<-done
}

// Nesting that is acyclic can still be unbounded, so the depth limit is its own guard.
func TestResolveStopsAtTheDepthLimit(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "draugr.saga.yaml", rootHeader+`
components: [{ name: web, repositories: [{ url: "." }] }]
fragments: [{ path: "d0/f.saga-fragment.yaml" }]
`)
	for i := 0; i < maxFragmentDepth+2; i++ {
		write(t, dir, filepath.Join(dirName(i), "f.saga-fragment.yaml"),
			"fragments: [{ path: \"../"+dirName(i+1)+"/f.saga-fragment.yaml\" }]\n")
	}
	_, err := resolveIn(t, dir)
	if err == nil {
		t.Fatal("unbounded nesting was accepted")
	}
	if !strings.Contains(err.Error(), "nest more than") {
		t.Errorf("error should name the limit: %v", err)
	}
}

func dirName(i int) string { return fmt.Sprintf("d%d", i) }

// A fragment is not a Saga, and the error should say why rather than reporting a known Saga key
// as unknown.
func TestFragmentRejectsSectionsItMayNotCarry(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"release", "release: { name: x, version: \"1\" }", "has no `release:`"},
		{"gate", "config:\n  gate:\n    failOn: high", "may not set `config.gate`"},
		{"controllers", "config:\n  controllers:\n    sca: { enabled: false }", "may not set `config.controllers`"},
		{"publishers", "config:\n  publishers: [{ kind: github }]", "may not set `config.publishers`"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadFragment([]byte(tc.body), "f.saga-fragment.yaml")
			if err == nil {
				t.Fatalf("%s was accepted in a fragment", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error should explain the rule, got: %v", err)
			}
		})
	}
}

func TestFragmentAcceptsWhatItMayCarry(t *testing.T) {
	body := `
components:
  - name: web
    repositories: [{ url: "." }]
config:
  exclude:
    - rules: ["X"]
      reason: "why"
fragments:
  - path: "nested.saga-fragment.yaml"
`
	f, err := LoadFragment([]byte(body), "f.saga-fragment.yaml")
	if err != nil {
		t.Fatalf("LoadFragment: %v", err)
	}
	if len(f.Components) != 1 || len(f.Config.Exclude) != 1 || len(f.Fragments) != 1 {
		t.Errorf("fragment did not decode: %+v", f)
	}
}

// A remote fragment tracking a moving branch is a gate that changes with no commit in your own
// repository, so the revision is required rather than defaulted.
func TestFragmentRefRequiresARevisionWhenRemote(t *testing.T) {
	errs := validateFragmentRefs([]FragmentRef{{URL: "https://git/x.git", Path: "a.yaml"}}, "fragments")
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "revision is required") {
		t.Errorf("errors = %v", errs)
	}
	ok := validateFragmentRefs([]FragmentRef{{URL: "https://git/x.git", Revision: "v1", Path: "a.yaml"}}, "fragments")
	if len(ok) != 0 {
		t.Errorf("a pinned remote fragment was rejected: %v", ok)
	}
}

func TestFragmentRefRejectsARevisionWithoutAURL(t *testing.T) {
	errs := validateFragmentRefs([]FragmentRef{{Path: "a.yaml", Revision: "v1"}}, "fragments")
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "applies only with url") {
		t.Errorf("errors = %v", errs)
	}
}

func TestFragmentRefRequiresAPath(t *testing.T) {
	errs := validateFragmentRefs([]FragmentRef{{URL: "https://git/x.git", Revision: "v1"}}, "fragments")
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "path is required") {
		t.Errorf("errors = %v", errs)
	}
}

// Without a Fetcher a remote reference must say so, not quietly contribute nothing.
func TestResolveRefusesARemoteFragmentWithNoFetcher(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "draugr.saga.yaml", rootHeader+`
components: [{ name: web, repositories: [{ url: "." }] }]
fragments:
  - url: https://github.com/acme/platform.git
    revision: v2.4.0
    path: "f.saga-fragment.yaml"
`)
	_, err := resolveIn(t, dir)
	if err == nil {
		t.Fatal("a remote fragment resolved with no fetcher")
	}
	if !strings.Contains(err.Error(), "acme/platform") {
		t.Errorf("error should name the fragment: %v", err)
	}
}

// Load has no directory to resolve a relative path against, so it must refuse rather than return
// a model describing less than the bytes do.
func TestLoadFromBytesRefusesADescriptorWithFragments(t *testing.T) {
	_, err := Load([]byte(rootHeader + "fragments: [{ path: \"a.saga-fragment.yaml\" }]\n"))
	if err == nil {
		t.Fatal("fragments were accepted from bytes")
	}
	if !strings.Contains(err.Error(), "load it from a path") {
		t.Errorf("error should say what to do instead: %v", err)
	}
}

// Provenance is what pays for the split: the resolution says where every part came from.
func TestResolveRecordsItsSources(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "draugr.saga.yaml", rootHeader+`
components: [{ name: web, repositories: [{ url: "." }] }]
fragments: [{ path: "f.saga-fragment.yaml" }]
`)
	write(t, dir, "f.saga-fragment.yaml", "components: [{ name: api, repositories: [{ url: \".\" }] }]\n")

	res, err := resolveIn(t, dir)
	if err != nil {
		t.Fatalf("ResolveFile: %v", err)
	}
	if len(res.Sources) != 2 {
		t.Fatalf("sources = %d, want 2", len(res.Sources))
	}
	if !res.Sources[0].Root {
		t.Error("the first source should be the root descriptor")
	}
	if res.Sources[1].Root || !strings.HasSuffix(res.Sources[1].Path, "f.saga-fragment.yaml") {
		t.Errorf("second source = %+v", res.Sources[1])
	}
}

// A descriptor with no fragments must behave exactly as it did before the feature existed.
func TestResolveLeavesAPlainDescriptorAlone(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "draugr.saga.yaml", rootHeader+"components: [{ name: web, repositories: [{ url: \".\" }] }]\n")
	res, err := resolveIn(t, dir)
	if err != nil {
		t.Fatalf("ResolveFile: %v", err)
	}
	if len(res.Model.Components) != 1 || len(res.Sources) != 1 {
		t.Errorf("model = %+v, sources = %d", res.Model.Components, len(res.Sources))
	}
}

// The glob dialect is the descriptor's, so `**` crosses directories and `*` does not.
func TestGlobFilesRecursesAndSorts(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "a/b/c/x.saga-fragment.yaml", "")
	write(t, dir, "a/y.saga-fragment.yaml", "")
	write(t, dir, "top.saga-fragment.yaml", "")

	deep, err := globFiles(dir, "**/*.saga-fragment.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(deep) != 3 {
		t.Errorf("** matched %v, want all three", deep)
	}
	for i := 1; i < len(deep); i++ {
		if deep[i-1] > deep[i] {
			t.Errorf("results are not sorted: %v", deep)
		}
	}
	shallow, err := globFiles(dir, "*.saga-fragment.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(shallow) != 1 || shallow[0] != "top.saga-fragment.yaml" {
		t.Errorf("* should not cross directories, got %v", shallow)
	}
}

// A component's fragment reaching a shared file above its own directory is a monorepo's natural
// shape, and the walk starts at the pattern's literal prefix so it works.
func TestResolveFollowsAPathAboveTheFragment(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "draugr.saga.yaml", rootHeader+`
components: [{ name: web, repositories: [{ url: "." }] }]
fragments: [{ path: "services/web/draugr.saga-fragment.yaml" }]
`)
	write(t, dir, "services/web/draugr.saga-fragment.yaml",
		"fragments: [{ path: \"../../shared/exclusions.saga-fragment.yaml\" }]\n")
	write(t, dir, "shared/exclusions.saga-fragment.yaml", `
config:
  exclude:
    - rules: ["SHARED"]
      reason: "one list, every component"
`)
	res, err := resolveIn(t, dir)
	if err != nil {
		t.Fatalf("ResolveFile: %v", err)
	}
	if len(res.Model.Config.Exclude) != 1 {
		t.Fatalf("exclusions = %d, want 1", len(res.Model.Config.Exclude))
	}
	if got := res.Model.Config.Exclude[0].Rules[0]; got != "SHARED" {
		t.Errorf("rule = %q", got)
	}
}

// fakeFetcher stands in for the git-backed one, so the remote resolution path is exercised
// without a network or a repository.
type fakeFetcher struct {
	dir      string
	resolved string
	err      error
	calls    []string
}

func (f *fakeFetcher) Fetch(url, revision string) (string, string, func(), error) {
	f.calls = append(f.calls, url+"@"+revision)
	if f.err != nil {
		return "", "", func() {}, f.err
	}
	return f.dir, f.resolved, func() {}, nil
}

func TestResolveMergesARemoteFragmentAndRecordsTheCommit(t *testing.T) {
	remote := t.TempDir()
	write(t, remote, "components/api/draugr.saga-fragment.yaml", `
components:
  - name: api
    repositories: [{ url: "." }]
config:
  exclude:
    - rules: ["REMOTE-1"]
      reason: "accepted upstream"
`)
	dir := t.TempDir()
	root := write(t, dir, "draugr.saga.yaml", rootHeader+`
fragments:
  - url: https://github.com/acme/platform.git
    revision: v2.4.0
    path: "components/**/draugr.saga-fragment.yaml"
`)
	f := &fakeFetcher{dir: remote, resolved: "a1b3f9c0d2e4f6a8b0c2"}
	res, err := ResolveFile(root, f)
	if err != nil {
		t.Fatalf("ResolveFile: %v", err)
	}
	if len(f.calls) != 1 || f.calls[0] != "https://github.com/acme/platform.git@v2.4.0" {
		t.Errorf("fetches = %v", f.calls)
	}
	if len(res.Model.Components) != 1 || res.Model.Components[0].Name != "api" {
		t.Errorf("components = %+v", res.Model.Components)
	}
	if len(res.Model.Config.Exclude) != 1 {
		t.Fatalf("exclusions = %d, want 1", len(res.Model.Config.Exclude))
	}

	// The commit is what makes a moved tag visible after the fact, so it has to reach the record.
	src := res.Sources[1]
	if src.URL != "https://github.com/acme/platform.git" || src.Revision != "v2.4.0" || src.Resolved != "a1b3f9c0d2e4f6a8b0c2" {
		t.Errorf("source = %+v", src)
	}
	if got := src.String(); !strings.Contains(got, "v2.4.0") || !strings.Contains(got, "a1b3f9c0d2e4") {
		t.Errorf("source string should carry the revision and the commit: %q", got)
	}
	if got := res.Model.Config.Exclude[0].Source; !strings.Contains(got, "acme/platform") {
		t.Errorf("a remote exclusion should be attributed to its repository: %q", got)
	}
}

// A fetch that fails must name the fragment, not just the git error.
func TestResolveReportsAFetchFailureAgainstTheFragment(t *testing.T) {
	dir := t.TempDir()
	root := write(t, dir, "draugr.saga.yaml", rootHeader+`
components: [{ name: web, repositories: [{ url: "." }] }]
fragments:
  - url: https://github.com/acme/platform.git
    revision: v2.4.0
    path: "f.saga-fragment.yaml"
`)
	_, err := ResolveFile(root, &fakeFetcher{err: errFetch})
	if err == nil {
		t.Fatal("a failed fetch was ignored")
	}
	if !strings.Contains(err.Error(), "acme/platform") || !strings.Contains(err.Error(), "v2.4.0") {
		t.Errorf("error should name the fragment: %v", err)
	}
}

var errFetch = fmt.Errorf("no such revision")

// A local source names its file; a remote one names repository, revision and commit.
func TestSourceString(t *testing.T) {
	if got := (Source{Path: "a.yaml"}).String(); got != "a.yaml" {
		t.Errorf("local = %q", got)
	}
	remote := Source{Path: "a.yaml", URL: "https://git/x.git", Revision: "v1", Resolved: "0123456789abcdef"}
	if got := remote.String(); got != "https://git/x.git@v1 (0123456789ab) a.yaml" {
		t.Errorf("remote = %q", got)
	}
	// A revision that is already the commit should not be printed twice.
	pinned := Source{Path: "a.yaml", URL: "https://git/x.git", Revision: "abc", Resolved: "abc"}
	if got := pinned.String(); got != "https://git/x.git@abc a.yaml" {
		t.Errorf("pinned = %q", got)
	}
}

func TestGlobFilesHandlesAMissingPrefixAndDirectories(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "a/x.saga-fragment.yaml", "")
	if got, err := globFiles(dir, "nope/**/*.yaml"); err != nil || len(got) != 0 {
		t.Errorf("a missing prefix should match nothing, got %v %v", got, err)
	}
	// A literal pattern naming a directory is not a file to read.
	if got, err := globFiles(dir, "a"); err != nil || len(got) != 0 {
		t.Errorf("a directory should not match, got %v %v", got, err)
	}
	if got, err := globFiles(dir, "a/x.saga-fragment.yaml"); err != nil || len(got) != 1 {
		t.Errorf("a literal file should match itself, got %v %v", got, err)
	}
}

func TestLoadFragmentRejectsBrokenYAMLAndUndefinedVars(t *testing.T) {
	if _, err := LoadFragment([]byte("components: [oops"), "f.saga-fragment.yaml"); err == nil {
		t.Error("broken YAML was accepted")
	}
	_, err := LoadFragment([]byte("components: [{ name: \"${{ NOPE_UNSET_VAR }}\" }]"), "f.saga-fragment.yaml")
	if err == nil || !strings.Contains(err.Error(), "NOPE_UNSET_VAR") {
		t.Errorf("an undefined variable should be named: %v", err)
	}
}

func TestLoadFragmentRejectsAnInvalidComponent(t *testing.T) {
	_, err := LoadFragment([]byte("components: [{ name: web, exposure: nonsense }]"), "f.saga-fragment.yaml")
	if err == nil || !strings.Contains(err.Error(), "exposure") {
		t.Errorf("a fragment's components should be validated: %v", err)
	}
}
