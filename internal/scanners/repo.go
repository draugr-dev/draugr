package scanners

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/internal/toolexec"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// repoScanner runs a tool over a checked-out source repository. It checks out the
// RepositoryTarget, runs the tool against the local path, and parses its SARIF output.
// checkout and run are injectable for testing.
type repoScanner struct {
	info     plugin.ScannerInfo
	args     func(dir string, cfg plugin.Config) []string
	checkout func(ctx context.Context, url, revision string, scope git.Scope) (string, func(), error)
	// parse decodes the tool's output. Nil means the tool emits SARIF.
	parse func(out []byte, dir string, cfg plugin.Config) (sarif.Report, error)
	run   func(ctx context.Context, dir string, argv []string) ([]byte, error)
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

// newRepoScannerWithParser is newRepoScanner for a tool that doesn't speak SARIF. Everything
// else — checkout, argv, path rewriting, tool stamping — is identical; only the decoding
// differs. parse receives the checkout directory as well as the output, because a tool that
// reports a package rather than a location may need to look in the tree to find one.
func newRepoScannerWithParser(
	info plugin.ScannerInfo,
	args func(string, plugin.Config) []string,
	parse func(out []byte, dir string, cfg plugin.Config) (sarif.Report, error),
) repoScanner {
	s := newRepoScanner(info, args)
	s.parse = parse
	return s
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

	dir, cleanup, err := s.checkout(ctx, repo.URL, repo.Revision,
		git.Scope{Paths: repo.Paths, Ignore: repo.Ignore})
	if err != nil {
		return sarif.Report{}, fmt.Errorf("%s: %w", s.info.Name, err)
	}
	defer cleanup()

	out, err := s.run(ctx, dir, s.args(dir, cfg))
	if err != nil {
		return sarif.Report{}, fmt.Errorf("run %s: %w", s.info.Name, err)
	}
	report, err := s.decode(out, dir, cfg)
	if err != nil {
		return sarif.Report{}, err
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
		// them to files in the repository. The message can also embed the absolute path (e.g.
		// Gitleaks: "…detected secret for file <dir>/x"); strip it there too so messages are
		// stable across scans — otherwise `draugr diff` sees the same finding as new+fixed
		// because the temp dir differs between the base and head scans.
		report.Results[i].Location.URI = repoRelPath(dir, report.Results[i].Location.URI)
		report.Results[i].Message = stripCheckoutDir(dir, report.Results[i].Message)
	}
	return report, nil
}

// decode turns the tool's output into a report, via SARIF unless the scanner supplied its own
// parser.
func (s repoScanner) decode(out []byte, dir string, cfg plugin.Config) (sarif.Report, error) {
	if s.parse != nil {
		report, err := s.parse(out, dir, cfg)
		if err != nil {
			return sarif.Report{}, fmt.Errorf("parse %s output: %w", s.info.Name, err)
		}
		return report, nil
	}
	report, err := sarif.FromSARIF(out)
	if err != nil {
		return sarif.Report{}, fmt.Errorf("parse %s SARIF: %w", s.info.Name, err)
	}
	return report, nil
}

// stripCheckoutDir removes the checkout-directory prefix from any absolute paths embedded in a
// finding message, making messages repo-relative and stable across scans (different temp dirs).
func stripCheckoutDir(dir, msg string) string {
	if dir == "" || msg == "" {
		return msg
	}
	return strings.ReplaceAll(msg, dir+string(filepath.Separator), "")
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

// execArgv and execArgvInDir are thin aliases for toolexec.Run, kept so scanner call sites read
// the way they always have. The implementation moved to internal/toolexec when SBOM generation
// needed the same "run it and say what you ran" behaviour without being a scanner.
func execArgv(ctx context.Context, argv []string) ([]byte, error) {
	return toolexec.Run(ctx, "", argv)
}

func execArgvInDir(ctx context.Context, dir string, argv []string) ([]byte, error) {
	return toolexec.Run(ctx, dir, argv)
}
