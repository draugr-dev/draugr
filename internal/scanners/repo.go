package scanners

import (
	"context"
	"errors"
	"fmt"
	"os/exec"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// repoScanner runs a tool over a checked-out source repository. It checks out the
// RepositoryTarget, runs the tool against the local path, and parses its SARIF output.
// checkout and run are injectable for testing.
type repoScanner struct {
	info     plugin.ScannerInfo
	args     func(dir string, cfg plugin.Config) []string
	checkout func(ctx context.Context, url, revision string) (string, func(), error)
	run      func(ctx context.Context, argv []string) ([]byte, error)
}

func newRepoScanner(info plugin.ScannerInfo, args func(string, plugin.Config) []string) repoScanner {
	return repoScanner{info: info, args: args, checkout: git.Checkout, run: execArgv}
}

// Info describes the scanner.
func (s repoScanner) Info() plugin.ScannerInfo { return s.info }

// Scan checks out the repository target and runs the tool against it.
func (s repoScanner) Scan(ctx context.Context, target plugin.Target, cfg plugin.Config) (sarif.Report, error) {
	repo, ok := target.(plugin.RepositoryTarget)
	if !ok {
		return sarif.Report{}, fmt.Errorf("%s: unsupported target %T (want repository)", s.info.Name, target)
	}
	if repo.URL == "" {
		return sarif.Report{}, fmt.Errorf("%s: repository target has no url", s.info.Name)
	}

	dir, cleanup, err := s.checkout(ctx, repo.URL, repo.Revision)
	if err != nil {
		return sarif.Report{}, fmt.Errorf("%s: %w", s.info.Name, err)
	}
	defer cleanup()

	out, err := s.run(ctx, s.args(dir, cfg))
	if err != nil {
		return sarif.Report{}, fmt.Errorf("run %s: %w", s.info.Name, err)
	}
	report, err := sarif.FromSARIF(out)
	if err != nil {
		return sarif.Report{}, fmt.Errorf("parse %s SARIF: %w", s.info.Name, err)
	}
	if report.Tool == "" {
		report.Tool = s.info.Name
	}
	for i := range report.Results {
		if report.Results[i].Tool == "" {
			report.Results[i].Tool = s.info.Name
		}
	}
	return report, nil
}

func execArgv(ctx context.Context, argv []string) ([]byte, error) {
	if len(argv) == 0 {
		return nil, errors.New("empty command")
	}
	// Executing the configured tool is the point; no shell (exec.CommandContext, not "sh -c")
	// and argv is built from typed config, not user shell input.
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // configured tool invocation // nosem: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	return cmd.Output()
}
