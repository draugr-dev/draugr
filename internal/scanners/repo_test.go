package scanners

import (
	"context"
	"errors"
	"testing"

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
