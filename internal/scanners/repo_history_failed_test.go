package scanners

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/internal/toolexec"
	"github.com/draugr-dev/draugr/pkg/plugin"
)

// historyScanner is a scanner whose tree pass finds one secret and whose history pass fails with
// historyErr.
func historyScanner(t *testing.T, historyErr error) repoScanner {
	t.Helper()
	const tree = `{"runs":[{"tool":{"driver":{"name":"gitleaks"}},"results":[{"ruleId":"github-pat",` +
		`"level":"error","message":{"text":"secret"},"locations":[{"physicalLocation":{` +
		`"artifactLocation":{"uri":"app/config.yaml"},"region":{"startLine":1}}}]}]}]}`
	return repoScanner{
		info: plugin.ScannerInfo{Name: "gitleaks", Controls: []string{"secrets"}},
		args: func(string, plugin.Config) []string { return []string{"tree"} },
		checkout: func(_ context.Context, _, _ string, _ git.Scope) (git.Tree, func(), error) {
			return git.Tree{Dir: t.TempDir()}, func() {}, nil
		},
		historyArgs: func(string, plugin.Config) []string { return []string{"history"} },
		run: func(_ context.Context, _ string, argv []string) ([]byte, error) {
			if argv[0] == "history" {
				return nil, historyErr
			}
			return []byte(tree), nil
		},
	}
}

// A history pass the kernel killed leaves the tree pass's findings standing. The scan is partial,
// and its error names the repository, the pass, and what lowers the memory it needs.
func TestAKilledHistoryPassKeepsTheTreeFindings(t *testing.T) {
	t.Parallel()
	killed := fmt.Errorf("run with --ignore-gitleaks-allow: %w (signal: killed)", toolexec.ErrKilled)
	repo := plugin.RepositoryTarget{URL: "https://github.com/acme/api"}

	_, err := historyScanner(t, killed).Scan(context.Background(), repo, nil)
	partial, ok := errors.AsType[*plugin.PartialScanError](err)
	if !ok {
		t.Fatalf("err = %v, want a partial scan", err)
	}
	if len(partial.Report.Results) != 1 || partial.Report.Results[0].Location.URI != "app/config.yaml" {
		t.Errorf("findings = %+v, want the tree pass's one", partial.Report.Results)
	}
	for _, want := range []string{"over the history of https://github.com/acme/api", "was killed",
		"only in its history were not read", "set `history: false`"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should say %q:\n%v", want, err)
		}
	}
	if !errors.Is(err, toolexec.ErrKilled) {
		t.Error("the kill should stay readable as such")
	}

	// Another failure keeps the findings too, without advice about memory.
	_, err = historyScanner(t, errors.New("exit status 2")).Scan(context.Background(), repo, nil)
	if _, ok := errors.AsType[*plugin.PartialScanError](err); !ok || strings.Contains(err.Error(), "memory") {
		t.Errorf("err = %v, want a partial scan with no memory advice", err)
	}
}

// A history pass ended because the scan was canceled is not a partial result; the scan stops.
func TestACanceledHistoryPassIsNotPartial(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	s := historyScanner(t, nil)
	tree := s.run
	s.run = func(c context.Context, dir string, argv []string) ([]byte, error) {
		if argv[0] == "history" {
			cancel()
			return nil, context.Canceled
		}
		return tree(c, dir, argv)
	}
	_, err := s.Scan(ctx, plugin.RepositoryTarget{URL: "https://github.com/acme/api"}, nil)
	if err == nil {
		t.Fatal("want the canceled pass to fail the scan")
	}
	if _, ok := errors.AsType[*plugin.PartialScanError](err); ok {
		t.Errorf("a canceled scan reported a partial result: %v", err)
	}
}
