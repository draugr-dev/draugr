package scanners

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/draugr-dev/draugr/internal/mendapi"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func TestMendSCAInfo(t *testing.T) {
	info := NewMendSCA().Info()
	if info.Name != mendSCAScannerName || info.Binary != "mend" {
		t.Errorf("info = %+v", info)
	}
	if len(info.Controls) != 1 || info.Controls[0] != "sca" {
		t.Errorf("controls = %v", info.Controls)
	}
	// Both effects are load-bearing: one says data leaves, the other says something is created in
	// somebody's account and needs consent.
	var kinds []string
	for _, e := range info.Effects {
		kinds = append(kinds, string(e.Kind))
		if e.Detail == "" {
			t.Errorf("effect %s has no detail; a reader deciding needs to know what is sent", e.Kind)
		}
	}
	if !contains(kinds, string(plugin.EffectDisclosure)) || !contains(kinds, string(plugin.EffectMutate)) {
		t.Errorf("effects = %v, want disclosure and mutate", kinds)
	}
}

func contains(h []string, n string) bool {
	for _, s := range h {
		if s == n {
			return true
		}
	}
	return false
}

// Every repository gets its own Mend project. Sharing one would mean concurrent uploads replacing
// each other's inventory, and findings describing whichever landed last.
func TestMendProjectNameIsPerRepository(t *testing.T) {
	api := plugin.RepositoryTarget{URL: "https://github.com/acme/api.git", Revision: "v1"}
	a := mendProjectName("acme", api)
	b := mendProjectName("acme", plugin.RepositoryTarget{URL: "https://github.com/acme/worker.git"})
	if a == b {
		t.Fatalf("two repositories share a project name: %q", a)
	}
	// An unscoped repository keeps the name it had before scopes were part of it, so an existing
	// project does not move.
	if a != "acme-github.com-acme-api" {
		t.Errorf("unscoped name = %q, want acme-github.com-acme-api", a)
	}
	if got := mendProjectName("", api); got != "github.com-acme-api" {
		t.Errorf("unprefixed name = %q, want github.com-acme-api", got)
	}
	// Stable across commits: a revision in the name would make a Mend project per commit.
	api.Revision = "v2"
	if a != mendProjectName("acme", api) {
		t.Error("project name is not stable")
	}
}

// Two components scoped to different subtrees of one repository upload different inventories,
// so each needs a project of its own or the second upload replaces the first's.
func TestMendProjectNameIsPerScope(t *testing.T) {
	repo := func(paths, ignore []string) plugin.RepositoryTarget {
		return plugin.RepositoryTarget{URL: "https://github.com/acme/mono.git", Paths: paths, Ignore: ignore}
	}
	unscoped := mendProjectName("acme", repo(nil, nil))
	web := mendProjectName("acme", repo([]string{"services/web"}, nil))
	worker := mendProjectName("acme", repo([]string{"services/worker"}, nil))
	webNoTests := mendProjectName("acme", repo([]string{"services/web"}, []string{"**/testdata/"}))
	ignoreOnly := mendProjectName("acme", repo(nil, []string{"vendor/"}))

	seen := map[string]string{}
	for label, name := range map[string]string{
		"unscoped": unscoped, "web": web, "worker": worker,
		"web without tests": webNoTests, "ignore only": ignoreOnly,
	} {
		if other, dup := seen[name]; dup {
			t.Errorf("%s and %s share the project %q", label, other, name)
		}
		seen[name] = label
		if !strings.HasPrefix(name, unscoped) {
			t.Errorf("%s: %q should extend the repository's name %q", label, name, unscoped)
		}
	}
	if !strings.HasPrefix(web, unscoped+"-services-web-") {
		t.Errorf("the paths should be readable in the name: %q", web)
	}
	if web != mendProjectName("acme", repo([]string{"services/web"}, nil)) {
		t.Error("a scoped project name is not stable")
	}
}

// A component listing many paths still gets a readable name, and two that share a long common
// prefix still get two projects.
func TestMendScopeFragmentBoundsItsLength(t *testing.T) {
	long := []string{strings.Repeat("a", 30) + "/" + strings.Repeat("b", 30) + "/one"}
	other := []string{strings.Repeat("a", 30) + "/" + strings.Repeat("b", 30) + "/two"}
	a, b := mendScopeFragment(long, nil), mendScopeFragment(other, nil)
	if a == b {
		t.Fatalf("two scopes truncated to one fragment: %q", a)
	}
	if len(a) > maxScopeSlug+1+8 {
		t.Errorf("fragment %q is longer than the bound allows", a)
	}
	if mendScopeFragment(nil, nil) != "" {
		t.Error("an unscoped repository should add nothing to the name")
	}
	if got := mendScopeFragment([]string{"/"}, nil); len(got) != 8 {
		t.Errorf("paths with nothing nameable should leave the hash alone, got %q", got)
	}
}

// A source with nothing nameable in it must still be distinguishable, or two such repositories
// silently become one project.
func TestMendProjectNameDistinguishesUnnameableSources(t *testing.T) {
	a := mendProjectName("", plugin.RepositoryTarget{URL: "."})
	b := mendProjectName("", plugin.RepositoryTarget{URL: "/"})
	if a == b {
		t.Errorf("two unnameable sources collapsed to %q", a)
	}
	if !strings.HasPrefix(a, "repo-") {
		t.Errorf("expected a distinguishing fallback, got %q", a)
	}
}

// The agent exits zero having resolved nothing and replaces the inventory with nothing, after
// which the API honestly reports no vulnerabilities. Every signal says pass.
func TestUASummaryRefusesZeroResolvedAgainstAManifest(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("requests==2.19.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := uaSummary{resolved: 0, sawSummary: true}.check(dir)
	if err == nil {
		t.Fatal("a scan that resolved nothing from a tree with a manifest was accepted")
	}
	if !strings.Contains(err.Error(), "requirements.txt") || !strings.Contains(err.Error(), "PATH") {
		t.Errorf("the error should name what was found and the likely cause: %v", err)
	}
}

// Where nothing declares dependencies, resolving nothing is the right answer.
func TestUASummaryAcceptsZeroWhenNothingDeclaresDependencies(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (uaSummary{resolved: 0, sawSummary: true}).check(dir); err != nil {
		t.Errorf("a tree with no manifests should pass: %v", err)
	}
}

// Not finding the summary at all is a different failure from finding a zero in it, and neither
// may read as a clean scan.
func TestUASummaryRefusesWhenItCannotSeeTheSummary(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\n\nrequire golang.org/x/net v0.1.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := uaSummary{sawSummary: false}.check(dir)
	if err == nil || !strings.Contains(err.Error(), "no scan summary") {
		t.Errorf("err = %v", err)
	}
}

func TestParseUASummary(t *testing.T) {
	out := `
Pre-Step And Resolve Dependencies                    COMPLETED     00:00:09.436     3 total dependencies (3 unique)
   PIP                                               COMPLETED     00:00:09.429     3 total dependencies (3 unique)
Request Token: 4f2c8a91-0b3d-4e6f-9a1c-2d3e4f5a6b7c
`
	s := parseUASummary(out)
	if !s.sawSummary || s.resolved != 3 {
		t.Errorf("summary = %+v", s)
	}
	if s.requestToken == "" {
		t.Error("the request token is what tells a landed upload from an early poll")
	}
}

// Only security vulnerabilities become findings. The other alert types are a different kind of
// statement, and one of them is policy from somebody else's console.
func TestMendReportKeepsOnlyVulnerabilities(t *testing.T) {
	rep := mendReport([]mendapi.Alert{
		{Type: "SECURITY_VULNERABILITY", Library: mendapi.Library{Name: "requests", Version: "2.19.1"},
			Vulnerability: mendapi.Vulnerability{Name: "CVE-2018-18074", Severity: "high", Score: 7.5,
				Description: "Redirect leaks the Authorization header",
				TopFix:      &mendapi.Fix{FixResolution: "2.20.0"}}},
		{Type: "NEW_MAJOR_VERSION", Library: mendapi.Library{Name: "flask"}},
		{Type: "REJECTED_BY_POLICY_RESOURCE", Library: mendapi.Library{Name: "left-pad"}},
	})
	if len(rep.Results) != 1 {
		t.Fatalf("results = %d, want only the vulnerability", len(rep.Results))
	}
	r := rep.Results[0]
	if r.RuleID != "CVE-2018-18074" || r.Level != sarif.LevelError || !r.HasScore || r.Score != 7.5 {
		t.Errorf("result = %+v", r)
	}
	for _, want := range []string{"requests 2.19.1", "fixed in 2.20.0"} {
		if !strings.Contains(r.Message, want) {
			t.Errorf("message %q should contain %q", r.Message, want)
		}
	}
}

func TestMendLevels(t *testing.T) {
	for sev, want := range map[string]sarif.Level{
		"critical": sarif.LevelError, "high": sarif.LevelError,
		"medium": sarif.LevelWarning, "low": sarif.LevelNote,
		"": sarif.LevelWarning, // unknown is reported, not dropped
	} {
		if got := mendLevel(sev); got != want {
			t.Errorf("mendLevel(%q) = %v, want %v", sev, got, want)
		}
	}
}

func TestMendMessageMarksTransitives(t *testing.T) {
	msg := mendMessage(mendapi.Alert{
		Library:       mendapi.Library{Name: "urllib3", Version: "1.24.1"},
		Vulnerability: mendapi.Vulnerability{Description: "CRLF injection"},
	})
	if !strings.Contains(msg, "(transitive)") {
		t.Errorf("a transitive dependency should say so: %q", msg)
	}
}

// Credentials come from the environment; a descriptor that is missing them is told which.
func TestMendSettingsRequiresCredentialsAndProduct(t *testing.T) {
	none := func(string) string { return "" }
	_, err := mendSettings(plugin.Config{}, none)
	if err == nil || !strings.Contains(err.Error(), envMendUserKey) {
		t.Errorf("err = %v", err)
	}

	full := func(k string) string {
		switch k {
		case envMendURL:
			return "https://saas.mend.io"
		case envMendUserKey, envMendEmail:
			return "x"
		}
		return ""
	}
	if _, err := mendSettings(plugin.Config{}, full); err == nil ||
		!strings.Contains(err.Error(), "productToken") {
		t.Errorf("a missing product token should be named: %v", err)
	}

	set, err := mendSettings(plugin.Config{
		"productToken":  "tok",
		"resultTimeout": "15m",
		"settings":      map[string]any{"python.installVirtualenv": true},
	}, full)
	if err != nil {
		t.Fatalf("mendSettings: %v", err)
	}
	if set.resultTimeout.Minutes() != 15 {
		t.Errorf("resultTimeout = %v", set.resultTimeout)
	}
	if cfg := set.agentConfig(); !strings.Contains(cfg, "python.installVirtualenv=true") {
		t.Errorf("agent settings are passed through verbatim; got:\n%s", cfg)
	}
}

func TestMendSettingsRejectsABadTimeout(t *testing.T) {
	full := func(k string) string {
		if k == envMendURL {
			return "https://saas.mend.io"
		}
		return "x"
	}
	_, err := mendSettings(plugin.Config{"productToken": "t", "resultTimeout": "soon"}, full)
	if err == nil || !strings.Contains(err.Error(), "not a duration") {
		t.Errorf("err = %v", err)
	}
}

func TestMendSCARejectsANonRepositoryTarget(t *testing.T) {
	_, err := NewMendSCA().Scan(context.Background(), plugin.ImageTarget{Ref: "alpine:3"}, plugin.Config{})
	if err == nil || !strings.Contains(err.Error(), "repositories") {
		t.Errorf("err = %v", err)
	}
}

// The full path through Scan, with the agent and the API both stubbed: the point is that an
// upload's request token reaches the poll, so results cannot be read before the scan lands.
func TestMendSCAScanEndToEnd(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("requests==2.19.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	repoAt(t, dir)

	var gotArgv []string
	var gotOpts mendapi.AwaitOpts
	s := mendSCAScanner{
		info: NewMendSCA().Info(),
		run: func(_ context.Context, _ string, argv, env []string) ([]byte, error) {
			gotArgv = argv
			// The agent's logs hold the user key in plaintext, so its base directory must be one
			// Draugr owns and removes rather than the operator's home.
			var based bool
			for _, e := range env {
				if strings.HasPrefix(e, "MEND_BASEDIR=") && !strings.Contains(e, os.Getenv("HOME")+"/.mend") {
					based = true
				}
			}
			if !based {
				t.Error("MEND_BASEDIR was not redirected away from the default location")
			}
			return []byte("Resolve Dependencies  COMPLETED  00:00:01  2 total dependencies (2 unique)\n" +
				"Request Token: abc12345-0000\n"), nil
		},
		api: func(string, string) mendResults {
			return stubResults{alerts: []mendapi.Alert{{
				Type: "SECURITY_VULNERABILITY", Library: mendapi.Library{Name: "requests", Version: "2.19.1"},
				Vulnerability: mendapi.Vulnerability{Name: "CVE-2018-18074", Severity: "high"},
			}}, opts: &gotOpts}
		},
		env: func(k string) string {
			switch k {
			case envMendURL:
				return "https://saas.mend.io"
			case envMendUserKey, envMendEmail:
				return "x"
			}
			return ""
		},
	}

	rep, err := s.Scan(context.Background(), plugin.RepositoryTarget{URL: dir}, plugin.Config{"productToken": "tok"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(rep.Results) != 1 || rep.Results[0].RuleID != "CVE-2018-18074" {
		t.Errorf("results = %+v", rep.Results)
	}
	if gotOpts.RequestToken != "abc12345-0000" {
		t.Errorf("the agent's request token did not reach the poll: %q", gotOpts.RequestToken)
	}
	if gotOpts.ProductToken != "tok" || gotOpts.ProjectName == "" {
		t.Errorf("await opts = %+v", gotOpts)
	}
	if !contains(gotArgv, "ua") || !contains(gotArgv, "-productToken") {
		t.Errorf("argv = %v", gotArgv)
	}
}

// A scan whose agent resolved nothing must not reach the API at all. Asking would get an honest
// "no vulnerabilities" for a project whose inventory was just emptied.
func TestMendSCAScanStopsBeforeQueryingWhenNothingResolved(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("requests==2.19.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	repoAt(t, dir)

	queried := false
	s := mendSCAScanner{
		info: NewMendSCA().Info(),
		run: func(context.Context, string, []string, []string) ([]byte, error) {
			return []byte("Resolve Dependencies  COMPLETED  00:00:01  0 dependencies\n"), nil
		},
		api: func(string, string) mendResults { queried = true; return stubResults{} },
		env: func(k string) string {
			if k == envMendURL {
				return "https://saas.mend.io"
			}
			return "x"
		},
	}
	if _, err := s.Scan(context.Background(), plugin.RepositoryTarget{URL: dir}, plugin.Config{"productToken": "t"}); err == nil {
		t.Fatal("a scan that resolved nothing returned success")
	}
	if queried {
		t.Error("the API was queried after a resolution that found nothing")
	}
}

type stubResults struct {
	alerts []mendapi.Alert
	opts   *mendapi.AwaitOpts
}

func (s stubResults) Await(_ context.Context, o mendapi.AwaitOpts) ([]mendapi.Alert, error) {
	if s.opts != nil {
		*s.opts = o
	}
	return s.alerts, nil
}

// repoAt makes dir a git repository so the checkout in Scan has something to clone.
func repoAt(t *testing.T, dir string) {
	t.Helper()
	for _, args := range [][]string{{"init", "-q", "."}, {"add", "-A"},
		{"-c", "user.email=e@e", "-c", "user.name=e", "commit", "-q", "-m", "i"}} {
		cmd := exec.Command("git", args...) //nolint:gosec // fixed argv in a temp dir
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("git unavailable: %v %s", err, out)
		}
	}
}

func TestMendLocationAndFirstLine(t *testing.T) {
	if got := mendLocation(mendapi.Library{GroupID: "org.acme", ArtifactID: "api"}); got != "org.acme:api" {
		t.Errorf("maven coordinates = %q", got)
	}
	if got := mendLocation(mendapi.Library{Filename: "x.whl"}); got != "x.whl" {
		t.Errorf("fallback = %q", got)
	}
	if got := firstLine("one\ntwo"); got != "one" {
		t.Errorf("firstLine = %q", got)
	}
}

func TestMapOfAcceptsBothDecoderShapes(t *testing.T) {
	if m := mapOf(map[any]any{"a": 1}); m["a"] != 1 {
		t.Errorf("map[any]any not handled: %v", m)
	}
	if mapOf("nope") != nil {
		t.Error("a non-map should yield nil")
	}
}

// fakeMend is a Mend tenant reduced to the one behavior these tests depend on: an upload replaces
// the named project's inventory, and the alerts read back describe whatever that project holds.
type fakeMend struct {
	mu       sync.Mutex
	projects map[string][]string
	uploads  int
}

// run stands in for the Unified Agent: the inventory it uploads is the manifests in the tree.
func (f *fakeMend) run(_ context.Context, dir string, argv, _ []string) ([]byte, error) {
	project := argAfter(argv, "-project")
	inventory := manifestsIn(dir)
	sort.Strings(inventory)
	f.mu.Lock()
	f.projects[project] = inventory
	f.uploads++
	f.mu.Unlock()
	return fmt.Appendf(nil, "Resolve Dependencies  COMPLETED  00:00:01  %d total dependencies\n", len(inventory)), nil
}

// Await reports one alert per manifest in the project, named after the manifest.
func (f *fakeMend) Await(_ context.Context, o mendapi.AwaitOpts) ([]mendapi.Alert, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var alerts []mendapi.Alert
	for _, m := range f.projects[o.ProjectName] {
		alerts = append(alerts, mendapi.Alert{Type: mendapi.AlertTypeVulnerability,
			Library: mendapi.Library{Name: m}, Vulnerability: mendapi.Vulnerability{Name: m}})
	}
	return alerts, nil
}

// ProjectByName answers with the name as the token, so Inventory can find the project again.
func (f *fakeMend) ProjectByName(_ context.Context, _, name string) (mendapi.Project, error) {
	return mendapi.Project{Name: name, Token: name}, nil
}

// Inventory reports each manifest in the project as an MIT-licensed library of the same name.
func (f *fakeMend) Inventory(_ context.Context, token string) ([]mendapi.InventoryLibrary, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var libs []mendapi.InventoryLibrary
	for _, m := range f.projects[token] {
		libs = append(libs, mendapi.InventoryLibrary{Name: m,
			Licenses: []mendapi.InventoryLicense{{Name: "MIT", SPDXName: "MIT"}}})
	}
	return libs, nil
}

func argAfter(argv []string, flag string) string {
	for i := 0; i+1 < len(argv); i++ {
		if argv[i] == flag {
			return argv[i+1]
		}
	}
	return ""
}

// Two components scoped to different paths of one repository, scanned concurrently as Draugr
// plans them. Each must land in its own project and read back its own inventory; sharing a
// project would leave both reporting whichever upload finished last.
func TestMendSCATwoScopesOfOneRepositoryKeepTwoInventories(t *testing.T) {
	sharedMendUploads.reset()
	t.Cleanup(sharedMendUploads.reset)

	dir := monorepo(t)
	tenant := &fakeMend{projects: map[string][]string{}}
	s := mendSCAScanner{
		info: NewMendSCA().Info(),
		run:  tenant.run,
		api:  func(string, string) mendResults { return tenant },
		env:  fakeMendEnv,
	}

	components := map[string]plugin.RepositoryTarget{
		"web":    {URL: dir, Paths: []string{"services/web"}},
		"worker": {URL: dir, Paths: []string{"services/worker"}},
	}
	results := map[string][]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for name, target := range components {
		wg.Go(func() {
			rep, err := s.Scan(context.Background(), target, plugin.Config{"productToken": "tok"})
			if err != nil {
				t.Errorf("%s: %v", name, err)
				return
			}
			var rules []string
			for _, r := range rep.Results {
				rules = append(rules, r.RuleID)
			}
			mu.Lock()
			results[name] = rules
			mu.Unlock()
		})
	}
	wg.Wait()

	if len(tenant.projects) != 2 {
		t.Fatalf("projects = %v, want one per component", tenant.projects)
	}
	want := map[string][]string{
		"web":    {"services/web/requirements.txt"},
		"worker": {"services/worker/requirements-dev.txt", "services/worker/requirements.txt"},
	}
	for name, rules := range want {
		if !slices.Equal(results[name], rules) {
			t.Errorf("%s reported %v, want its own inventory %v", name, results[name], rules)
		}
		project := mendProjectName("", components[name])
		if !slices.Equal(tenant.projects[project], rules) {
			t.Errorf("project %q holds %v, want %v", project, tenant.projects[project], rules)
		}
	}
}

// Both Mend controls on one scoped component must name the same project, or the licenses control
// would upload a second time into a project of its own and read an inventory the vulnerability
// findings were not drawn from.
func TestMendLicensesSharesTheScopedProjectWithSCA(t *testing.T) {
	sharedMendUploads.reset()
	t.Cleanup(sharedMendUploads.reset)

	tenant := &fakeMend{projects: map[string][]string{}}
	web := plugin.RepositoryTarget{URL: monorepo(t), Paths: []string{"services/web"}}
	cfg := plugin.Config{"productToken": "tok", "deny": []any{"MIT"}}

	sca := mendSCAScanner{info: NewMendSCA().Info(), run: tenant.run, env: fakeMendEnv,
		api: func(string, string) mendResults { return tenant }}
	lic := mendLicensesScanner{info: NewMendLicenses().Info(), run: tenant.run, env: fakeMendEnv,
		api: func(string, string) mendInventory { return tenant }}

	if _, err := sca.Scan(context.Background(), web, cfg); err != nil {
		t.Fatalf("sca: %v", err)
	}
	rep, err := lic.Scan(context.Background(), web, cfg)
	if err != nil {
		t.Fatalf("licenses: %v", err)
	}
	if tenant.uploads != 1 {
		t.Errorf("uploads = %d, want the one both controls share", tenant.uploads)
	}
	var located []string
	for _, r := range rep.Results {
		located = append(located, r.Location.URI)
	}
	if want := []string{"services/web/requirements.txt"}; !slices.Equal(located, want) {
		t.Errorf("licenses read %v, want the web component's inventory %v", located, want)
	}
}

// fakeMendEnv supplies every credential a Mend scan asks the environment for.
func fakeMendEnv(k string) string {
	if k == envMendURL {
		return "https://saas.mend.io"
	}
	return "x"
}

// monorepo is one repository holding two services, each with its own manifests, and nothing at
// the root that declares dependencies.
func monorepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for path, body := range map[string]string{
		"README.md":                            "mono\n",
		"services/web/requirements.txt":        "requests==2.19.1\n",
		"services/worker/requirements.txt":     "urllib3==1.24.1\n",
		"services/worker/requirements-dev.txt": "pytest==7.0.0\n",
	} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, path)), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, path), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	repoAt(t, dir)
	return dir
}
