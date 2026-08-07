package scanners

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	a := mendProjectName("acme", "https://github.com/acme/api.git")
	b := mendProjectName("acme", "https://github.com/acme/worker.git")
	if a == b {
		t.Fatalf("two repositories share a project name: %q", a)
	}
	if !strings.HasPrefix(a, "acme-") {
		t.Errorf("the configured name should prefix rather than replace: %q", a)
	}
	// Stable across commits: a revision in the name would make a Mend project per commit.
	if a != mendProjectName("acme", "https://github.com/acme/api.git") {
		t.Error("project name is not stable")
	}
}

// A source with nothing nameable in it must still be distinguishable, or two such repositories
// silently become one project.
func TestMendProjectNameDistinguishesUnnameableSources(t *testing.T) {
	a := mendProjectName("", ".")
	b := mendProjectName("", "/")
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
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\n"), 0o600); err != nil {
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

// Only security vulnerabilities become findings — the other alert types are a different kind of
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

// A scan whose agent resolved nothing must not reach the API at all — asking would get an honest
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
