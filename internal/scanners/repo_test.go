package scanners

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/internal/observability"
	"github.com/draugr-dev/draugr/pkg/plugin"
)

const repoSARIF = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":""}},` +
	`"results":[{"ruleId":"CVE-1","level":"error","message":{"text":"vuln"}}]}]}`

func fakeCheckout(_ context.Context, _, _ string) (string, func(), error) {
	return "/tmp/fake-checkout", func() {}, nil
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
	s.checkout = func(context.Context, string, string) (string, func(), error) {
		return "", nil, errors.New("clone failed")
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

// A scan used to be a black box: you could see that a tool failed but not what was run, where,
// for how long, or what the tool itself said. These assert the record that answers that.
func TestLogToolRunRecordsTheCommand(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(prev)

	logToolRun(context.Background(), []string{"trivy", "fs", "--quiet", "/src"}, "/work",
		time.Now().Add(-50*time.Millisecond), []byte("output"), nil)

	out := buf.String()
	for _, want := range []string{`tool=trivy`, `argv="trivy fs --quiet /src"`, `dir=/work`, "stdout_bytes=6", "duration="} {
		if !strings.Contains(out, want) {
			t.Errorf("debug record missing %s\n%s", want, out)
		}
	}
}

// The tool's own stderr is usually where the answer is, so trace must relay it — and debug must
// not, since it's verbose.
func TestLogToolRunRelaysStderrAtTraceOnly(t *testing.T) {
	run := func(level slog.Level) string {
		var buf bytes.Buffer
		prev := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: level})))
		defer slog.SetDefault(prev)
		err := &exec.ExitError{ProcessState: &os.ProcessState{}, Stderr: []byte("boom: bad flag")}
		logToolRun(context.Background(), []string{"gitleaks", "dir", "."}, "", time.Now(), nil, err)
		return buf.String()
	}
	if got := run(observability.LevelTrace); !strings.Contains(got, "boom: bad flag") {
		t.Errorf("trace should relay the tool's stderr:\n%s", got)
	}
	if got := run(slog.LevelDebug); strings.Contains(got, "boom: bad flag") {
		t.Errorf("debug should not include the tool's full stderr:\n%s", got)
	}
}
