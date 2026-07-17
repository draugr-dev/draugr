package scanners

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

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
	run      func(ctx context.Context, dir string, argv []string) ([]byte, error)
	// cacheVersion, when set, contributes a tool/data version to the cache key (see
	// plugin.CacheVersioner). Nil for scanners with no dynamic version.
	cacheVersion func(ctx context.Context) string
	// prewarm, when set, warms shared tool state before a run (see plugin.Prewarmer). Nil for
	// scanners with nothing to warm.
	prewarm func(ctx context.Context) error
}

// CacheVersion reports the scanner's tool/data version for the cache key, when one is wired
// (implements plugin.CacheVersioner). Empty otherwise.
func (s repoScanner) CacheVersion(ctx context.Context) string {
	if s.cacheVersion == nil {
		return ""
	}
	return s.cacheVersion(ctx)
}

// Prewarm warms shared tool state before a run, when one is wired (implements
// plugin.Prewarmer). No-op otherwise.
func (s repoScanner) Prewarm(ctx context.Context) error {
	if s.prewarm == nil {
		return nil
	}
	return s.prewarm(ctx)
}

func newRepoScanner(info plugin.ScannerInfo, args func(string, plugin.Config) []string) repoScanner {
	return repoScanner{info: info, args: args, checkout: git.Checkout, run: execArgvInDir}
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

	out, err := s.run(ctx, dir, s.args(dir, cfg))
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
		// Findings are reported against the temporary checkout directory; rewrite their paths
		// to be repo-relative so downstream consumers (e.g. GitHub code scanning) can anchor
		// them to files in the repository.
		report.Results[i].Location.URI = repoRelPath(dir, report.Results[i].Location.URI)
	}
	return report, nil
}

// repoRelPath rewrites an absolute finding path that lives under the checkout dir into a path
// relative to it. Already-relative paths, and absolute paths outside the checkout, are left
// unchanged. A leading "file://" scheme is stripped first.
func repoRelPath(dir, uri string) string {
	if uri == "" {
		return uri
	}
	uri = strings.TrimPrefix(uri, "file://")
	if !filepath.IsAbs(uri) {
		return uri
	}
	rel, err := filepath.Rel(dir, uri)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return uri // outside the checkout — leave it alone
	}
	return filepath.ToSlash(rel)
}

func execArgv(ctx context.Context, argv []string) ([]byte, error) {
	return execArgvInDir(ctx, "", argv)
}

// execArgvInDir runs argv with the working directory set to dir (empty = inherit the current
// directory). Some tools resolve their scan target relative to the working directory (e.g.
// gosec loads Go packages via `./...`), so the checkout dir must be the cwd, not just an arg.
func execArgvInDir(ctx context.Context, dir string, argv []string) ([]byte, error) {
	if len(argv) == 0 {
		return nil, errors.New("empty command")
	}
	// Executing the configured tool is the point; no shell (exec.CommandContext, not "sh -c")
	// and argv is built from typed config, not user shell input.
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // configured tool invocation // nosem: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd.Dir = dir
	return cmd.Output()
}
