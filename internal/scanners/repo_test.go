package scanners

import (
	"context"
	"errors"
	"os"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

const repoSARIF = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":""}},` +
	`"results":[{"ruleId":"CVE-1","level":"error","message":{"text":"vuln"}}]}]}`

func fakeCheckout(_ context.Context, _, _ string, _ git.Scope) (git.Tree, func(), error) {
	return git.Tree{Dir: "/tmp/fake-checkout", Revision: "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"}, func() {}, nil
}

func newFakeRepoScanner(run func(context.Context, string, []string) ([]byte, error)) repoScanner {
	return repoScanner{
		info:     plugin.ScannerInfo{Name: "trivy-fs", Controls: []string{"sca"}},
		args:     func(dir string, _ plugin.Config) []string { return []string{"trivy", "fs", dir} },
		checkout: fakeCheckout,
		run:      run,
	}
}

func TestRepoScannerScan(t *testing.T) {
	s := newFakeRepoScanner(func(context.Context, string, []string) ([]byte, error) {
		return []byte(repoSARIF), nil
	})
	rep, err := s.Scan(context.Background(), plugin.RepositoryTarget{URL: "u", Revision: "r"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 || rep.Results[0].Tool != "trivy-fs" {
		t.Fatalf("unexpected report: %+v", rep)
	}
}

func TestRepoScannerRewritesAbsolutePathsToRepoRelative(t *testing.T) {
	// A tool that reports absolute paths under the checkout dir (like Semgrep) must have its
	// finding paths rewritten to repo-relative so code scanning can anchor them.
	sarif := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep"}},"results":[
		{"ruleId":"R1","level":"error","message":{"text":"x"},
		 "locations":[{"physicalLocation":{"artifactLocation":{"uri":"/tmp/fake-checkout/pkg/report/template.go"},"region":{"startLine":7}}}]},
		{"ruleId":"R2","level":"warning","message":{"text":"y"},
		 "locations":[{"physicalLocation":{"artifactLocation":{"uri":"internal/cli/survey.go"},"region":{"startLine":60}}}]},
		{"ruleId":"R3","level":"note","message":{"text":"z"},
		 "locations":[{"physicalLocation":{"artifactLocation":{"uri":"/etc/passwd"},"region":{"startLine":1}}}]}
	]}]}`
	s := newFakeRepoScanner(func(context.Context, string, []string) ([]byte, error) {
		return []byte(sarif), nil
	})
	rep, err := s.Scan(context.Background(), plugin.RepositoryTarget{URL: "u"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range rep.Results {
		got[r.RuleID] = r.Location.URI
	}
	if got["R1"] != "pkg/report/template.go" {
		t.Errorf("absolute in-checkout path not made relative: %q", got["R1"])
	}
	if got["R2"] != "internal/cli/survey.go" {
		t.Errorf("already-relative path should be unchanged: %q", got["R2"])
	}
	if got["R3"] != "/etc/passwd" {
		t.Errorf("absolute path outside the checkout should be unchanged: %q", got["R3"])
	}
}

func TestRepoScannerStripsCheckoutDirFromMessage(t *testing.T) {
	// Gitleaks-style: the message embeds the absolute checkout path. It must be stripped so the
	// message is repo-relative and stable across scans (otherwise diff churns as new+fixed).
	sarif := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks"}},"results":[
		{"ruleId":"private-key","level":"error",
		 "message":{"text":"private-key has detected secret for file /tmp/fake-checkout/app/config.pem."},
		 "locations":[{"physicalLocation":{"artifactLocation":{"uri":"/tmp/fake-checkout/app/config.pem"},"region":{"startLine":1}}}]}
	]}]}`
	s := newFakeRepoScanner(func(context.Context, string, []string) ([]byte, error) {
		return []byte(sarif), nil
	})
	rep, err := s.Scan(context.Background(), plugin.RepositoryTarget{URL: "u"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := rep.Results[0]
	if got.Location.URI != "app/config.pem" {
		t.Errorf("uri = %q, want app/config.pem", got.Location.URI)
	}
	if got.Message != "private-key has detected secret for file app/config.pem." {
		t.Errorf("message still contains the checkout path: %q", got.Message)
	}
}

func TestStripCheckoutDir(t *testing.T) {
	cases := []struct{ dir, in, want string }{
		{"/tmp/co", "secret in /tmp/co/a/b.pem found", "secret in a/b.pem found"},
		{"/tmp/co", "no path here", "no path here"},
		{"/tmp/co", "", ""},
		{"", "/tmp/co/x", "/tmp/co/x"}, // empty dir → unchanged
	}
	for _, c := range cases {
		if got := stripCheckoutDir(c.dir, c.in); got != c.want {
			t.Errorf("stripCheckoutDir(%q, %q) = %q, want %q", c.dir, c.in, got, c.want)
		}
	}
}

func TestRepoRelPath(t *testing.T) {
	cases := []struct{ dir, in, want string }{
		{"/tmp/co", "/tmp/co/a/b.go", "a/b.go"},
		{"/tmp/co", "file:///tmp/co/a/b.go", "a/b.go"},
		{"/tmp/co", "a/b.go", "a/b.go"},           // already relative
		{"/tmp/co", "/other/x.go", "/other/x.go"}, // outside
		{"/tmp/co", "", ""},
	}
	for _, c := range cases {
		if got := repoRelPath(c.dir, c.in); got != c.want {
			t.Errorf("repoRelPath(%q, %q) = %q, want %q", c.dir, c.in, got, c.want)
		}
	}
}

func TestRepoScannerNonRepoTarget(t *testing.T) {
	s := newFakeRepoScanner(func(context.Context, string, []string) ([]byte, error) { return nil, nil })
	if _, err := s.Scan(context.Background(), plugin.ImageTarget{Ref: "x"}, nil); err == nil {
		t.Fatal("expected error for non-repository target")
	}
}

func TestRepoScannerNoURL(t *testing.T) {
	s := newFakeRepoScanner(func(context.Context, string, []string) ([]byte, error) { return nil, nil })
	if _, err := s.Scan(context.Background(), plugin.RepositoryTarget{}, nil); err == nil {
		t.Fatal("expected error for missing url")
	}
}

func TestRepoScannerCheckoutError(t *testing.T) {
	s := newFakeRepoScanner(func(context.Context, string, []string) ([]byte, error) { return nil, nil })
	s.checkout = func(context.Context, string, string, git.Scope) (git.Tree, func(), error) {
		return git.Tree{}, nil, errors.New("clone failed")
	}
	if _, err := s.Scan(context.Background(), plugin.RepositoryTarget{URL: "u"}, nil); err == nil {
		t.Fatal("expected checkout error")
	}
}

func TestRepoScannerRunError(t *testing.T) {
	s := newFakeRepoScanner(func(context.Context, string, []string) ([]byte, error) {
		return nil, errors.New("exec failed")
	})
	if _, err := s.Scan(context.Background(), plugin.RepositoryTarget{URL: "u"}, nil); err == nil {
		t.Fatal("expected run error")
	}
}

func TestRepoScannerBadSARIF(t *testing.T) {
	s := newFakeRepoScanner(func(context.Context, string, []string) ([]byte, error) {
		return []byte("{not sarif"), nil
	})
	if _, err := s.Scan(context.Background(), plugin.RepositoryTarget{URL: "u"}, nil); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestExecArgv(t *testing.T) {
	out, err := execArgv(context.Background(), []string{"echo", "hi"})
	if err != nil {
		t.Fatalf("execArgv: %v", err)
	}
	if string(out) != "hi\n" {
		t.Fatalf("output = %q", out)
	}
	if _, err := execArgv(context.Background(), nil); err == nil {
		t.Fatal("empty argv should error")
	}
}

func TestRepoScanStampsWhatItRead(t *testing.T) {
	// A report that cannot name the commit it describes cannot be reproduced or compared, which
	// is the whole reason a scan reads a committed revision rather than the files on disk.
	s := newFakeRepoScanner(func(context.Context, string, []string) ([]byte, error) {
		return []byte(`{"runs":[{"tool":{"driver":{"name":"Trivy"}},"results":[]}]}`), nil
	})
	report, err := s.Scan(context.Background(), plugin.RepositoryTarget{URL: "."}, plugin.Config{})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, p := range report.Provenance {
		r, ok := p.Repository()
		if !ok {
			continue
		}
		found = true
		if r.URL != "." {
			t.Errorf("repository = %q", r.URL)
		}
		if r.Short() != "a1b2c3d4" {
			t.Errorf("revision = %q, want the checkout's resolved SHA", r.Short())
		}
	}
	if !found {
		t.Error("a repository scan recorded no repository provenance")
	}
}

func TestRepoScanSharesAPooledCheckout(t *testing.T) {
	// Five controls over one repository should check it out once. The scanner cannot know how
	// many others there are, so it asks the run's pool by the target's identity and the pool
	// decides — which also means every control provably reads the same commit.
	var clones atomic.Int32
	s := newFakeRepoScanner(func(context.Context, string, []string) ([]byte, error) {
		return []byte(`{"runs":[{"tool":{"driver":{"name":"Trivy"}},"results":[]}]}`), nil
	})
	dir := t.TempDir()
	s.checkout = func(context.Context, string, string, git.Scope) (git.Tree, func(), error) {
		clones.Add(1)
		return git.Tree{Dir: dir, Revision: "abc"}, func() {}, nil
	}

	pool := git.NewPool()
	defer pool.Close()
	ctx := git.WithPool(context.Background(), pool)
	target := plugin.RepositoryTarget{URL: "."}
	for range 5 {
		if _, err := s.Scan(ctx, target, plugin.Config{}); err != nil {
			t.Fatal(err)
		}
	}
	if n := clones.Load(); n != 1 {
		t.Errorf("checked out %d times, want 1", n)
	}
}

func TestRepoScanWithoutAPoolChecksOutForItself(t *testing.T) {
	// A scanner used on its own, or in a test, must not depend on a run having set one up.
	var clones atomic.Int32
	s := newFakeRepoScanner(func(context.Context, string, []string) ([]byte, error) {
		return []byte(`{"runs":[{"tool":{"driver":{"name":"Trivy"}},"results":[]}]}`), nil
	})
	dir := t.TempDir()
	s.checkout = func(context.Context, string, string, git.Scope) (git.Tree, func(), error) {
		clones.Add(1)
		return git.Tree{Dir: dir}, func() {}, nil
	}
	for range 3 {
		if _, err := s.Scan(context.Background(), plugin.RepositoryTarget{URL: "."}, plugin.Config{}); err != nil {
			t.Fatal(err)
		}
	}
	if n := clones.Load(); n != 3 {
		t.Errorf("checked out %d times without a pool, want 3", n)
	}
}

func TestRepoScanDoesNotShareAcrossDifferentTargets(t *testing.T) {
	// The key is the target's identity, which already accounts for revision and scope — two
	// components pointing at different subtrees are two scans, not one.
	var clones atomic.Int32
	s := newFakeRepoScanner(func(context.Context, string, []string) ([]byte, error) {
		return []byte(`{"runs":[{"tool":{"driver":{"name":"Trivy"}},"results":[]}]}`), nil
	})
	dir := t.TempDir()
	s.checkout = func(context.Context, string, string, git.Scope) (git.Tree, func(), error) {
		clones.Add(1)
		return git.Tree{Dir: dir}, func() {}, nil
	}
	pool := git.NewPool()
	defer pool.Close()
	ctx := git.WithPool(context.Background(), pool)

	// WorkingTree is deliberately absent: it routes to CheckoutWorkingTree rather than the
	// injected checkout, so this counter cannot see it. That it keys separately is covered by
	// RepositoryTarget.Identity's own test.
	for _, target := range []plugin.RepositoryTarget{
		{URL: "."},
		{URL: ".", Revision: "v1"},
		{URL: ".", Paths: []string{"api"}},
	} {
		if _, err := s.Scan(ctx, target, plugin.Config{}); err != nil {
			t.Fatal(err)
		}
	}
	if n := clones.Load(); n != 3 {
		t.Errorf("checked out %d times for 3 distinct targets, want 3", n)
	}
}

// The second pass exists because one pass over history reports every finding at the path it had
// when it was introduced. A file since renamed then appears under a directory that does not
// exist, and the most severe finding in a report reads as something already cleaned up.
func TestRepoScannerMergesAHistoryPassAndMarksIt(t *testing.T) {
	report := func(uri string) string {
		return `{"runs":[{"tool":{"driver":{"name":"gitleaks"}},"results":[{"ruleId":"github-pat",` +
			`"level":"error","message":{"text":"secret"},"locations":[{"physicalLocation":{` +
			`"artifactLocation":{"uri":"` + uri + `"},"region":{"startLine":1}}}]}]}]}`
	}
	var ran [][]string
	s := repoScanner{
		info: plugin.ScannerInfo{Name: "gitleaks", Controls: []string{"secrets"}},
		args: func(string, plugin.Config) []string { return []string{"tree"} },
		checkout: func(_ context.Context, _, _ string, _ git.Scope) (git.Tree, func(), error) {
			return git.Tree{Dir: t.TempDir()}, func() {}, nil
		},
		historyArgs: func(string, plugin.Config) []string { return []string{"history"} },
		run: func(_ context.Context, _ string, argv []string) ([]byte, error) {
			ran = append(ran, argv)
			if argv[0] == "history" {
				return []byte(report("old/path.ps1")), nil
			}
			return []byte(report("new/path.ps1")), nil
		},
	}

	got, err := s.Scan(context.Background(), plugin.RepositoryTarget{URL: "u"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(ran) != 2 {
		t.Fatalf("ran %d commands, want the tree and the history: %v", len(ran), ran)
	}
	if len(got.Results) != 2 {
		t.Fatalf("got %d findings, want both passes': %+v", len(got.Results), got.Results)
	}
	byPath := map[string]sarif.Result{}
	for _, r := range got.Results {
		byPath[r.Location.URI] = r
	}
	if byPath["new/path.ps1"].Historical {
		t.Error("the tree pass produced a finding marked as history")
	}
	if !byPath["old/path.ps1"].Historical {
		t.Error("the history pass produced a finding not marked as history, which is the whole defect")
	}
}

// No second pass configured, or none wanted, must leave the scan exactly as it was.
func TestRepoScannerRunsOnePassWhenNoHistoryIsWanted(t *testing.T) {
	var ran int
	s := repoScanner{
		info: plugin.ScannerInfo{Name: "gitleaks", Controls: []string{"secrets"}},
		args: func(string, plugin.Config) []string { return []string{"tree"} },
		checkout: func(_ context.Context, _, _ string, _ git.Scope) (git.Tree, func(), error) {
			return git.Tree{Dir: t.TempDir()}, func() {}, nil
		},
		historyArgs: func(string, plugin.Config) []string { return nil },
		run: func(context.Context, string, []string) ([]byte, error) {
			ran++
			return []byte(`{"runs":[{"tool":{"driver":{"name":"gitleaks"}},"results":[]}]}`), nil
		},
	}
	if _, err := s.Scan(context.Background(), plugin.RepositoryTarget{URL: "u"}, nil); err != nil {
		t.Fatal(err)
	}
	if ran != 1 {
		t.Errorf("ran %d commands, want 1", ran)
	}
}

// A tool that writes its report to a file gets a real one.
//
// Pointing such a tool at /dev/stdout looks equivalent and is not: that path is a symlink to the
// process's own fd 1, and opening it is not writing to the descriptor it inherited. Where stdout
// is a pipe — every containerised runner — the open lands somewhere the parent never reads, the
// tool exits 0 having written nothing, and the parse blames the JSON.
func TestRunReportingGivesTheToolARealFile(t *testing.T) {
	const report = `{"version":"2.1.0","runs":[]}`

	var gotArgv []string
	s := repoScanner{
		run: func(_ context.Context, _ string, argv []string) ([]byte, error) {
			gotArgv = argv
			// Stand in for the tool: write the report to the path it was handed, and put nothing
			// on stdout — which is exactly what the real failure looked like.
			for i, a := range argv {
				if a == "--report-path" && i+1 < len(argv) {
					if err := os.WriteFile(argv[i+1], []byte(report), 0o600); err != nil {
						return nil, err
					}
				}
			}
			return nil, nil
		},
	}

	out, err := s.runReporting(context.Background(), "/tmp", []string{
		"tool", "--report-path", ReportPathToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != report {
		t.Errorf("read %q from the report file, want the tool's output", out)
	}
	if slices.Contains(gotArgv, ReportPathToken) {
		t.Errorf("the placeholder reached the tool: %v", gotArgv)
	}
	if path := gotArgv[2]; path == "" || path == "/dev/stdout" {
		t.Errorf("the tool was handed %q rather than a real file", path)
	}
	if _, err := os.Stat(gotArgv[2]); !os.IsNotExist(err) {
		t.Errorf("the temporary report was left behind at %s", gotArgv[2])
	}
}

// A tool with no report path keeps writing to stdout, which is how every other scanner works.
func TestRunReportingLeavesStdoutToolsAlone(t *testing.T) {
	s := repoScanner{
		run: func(_ context.Context, _ string, _ []string) ([]byte, error) {
			return []byte(`{"version":"2.1.0"}`), nil
		},
	}
	out, err := s.runReporting(context.Background(), "/tmp", []string{"tool", "--format", "sarif"})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"version":"2.1.0"}` {
		t.Errorf("stdout was not returned: %q", out)
	}
}
