package scanners

import (
	"context"
	"regexp"
	"strings"
	"sync"

	"github.com/draugr-dev/draugr/internal/toolexec"
	"github.com/draugr-dev/draugr/internal/version"
)

// toolVersionProbe asks a tool what version it is, once, and remembers the answer.
//
// The cache key is `hash(scanner, version, target, config)`, and most scanners contributed
// nothing for `version`, so a Semgrep upgrade or a Nuclei template refresh left yesterday's "no
// findings" looking current. On a fresh runner that is nearly harmless, because there is nothing
// cached to serve. It stops being harmless the moment a cache outlives one machine, which is
// exactly what https://github.com/draugr-dev/draugr/issues/497 is about.
//
// One probe per tool per process: the version cannot change mid-run, and paying for a subprocess
// on every job to ask again would cost more than the cache saves.
type toolVersionProbe struct {
	once sync.Once
	val  string
	argv []string
	// extract turns the tool's output into a version string, or "" when it cannot be read.
	extract func(out []byte) string
	run     func(ctx context.Context, argv []string) ([]byte, error)
}

// version returns the probe's answer, running the tool at most once.
//
// An unreadable version yields "", and the caller falls back to a version-less key rather than
// inventing one. A wrong version in the key is worse than none: it would make two genuinely
// different tool versions look identical, which is the failure this exists to prevent.
func (p *toolVersionProbe) version(ctx context.Context) string {
	p.once.Do(func() {
		out, err := p.run(ctx, p.argv)
		if err != nil {
			return
		}
		p.val = p.extract(out)
	})
	return p.val
}

// runWithoutSemgrepVersionCheck runs a semgrep command with its update check disabled.
func runWithoutSemgrepVersionCheck(ctx context.Context, argv []string) ([]byte, error) {
	return toolexec.RunWithEnv(ctx, "", argv, []string{"SEMGREP_ENABLE_VERSION_CHECK=0"})
}

// firstMatch returns the first capture of re, trimmed, or "".
func firstMatch(re *regexp.Regexp) func([]byte) string {
	return func(out []byte) string {
		m := re.FindSubmatch(out)
		if len(m) < 2 {
			return ""
		}
		return strings.TrimSpace(string(m[1]))
	}
}

// The version each tool reports, and how it says it.
var (
	// Semgrep prints a bare version: "1.155.0".
	semgrepVersionRE = regexp.MustCompile(`([0-9]+\.[0-9]+\.[0-9]+[^\s]*)`)
	// Gitleaks prints "v8.30.1" or a bare semver depending on how it was built.
	gitleaksVersionRE = regexp.MustCompile(`v?([0-9]+\.[0-9]+\.[0-9]+[^\s]*)`)
	// gosec prints a multi-line block including "Version: 2.22.10".
	gosecVersionRE = regexp.MustCompile(`(?i)version:\s*(\S+)`)
	// Nuclei's *template* version is the one that matters: the binary changes rarely and the
	// template set is republished daily, so it is the template version that decides whether a
	// cached "clean" is still true.
	nucleiTemplateVersionRE = regexp.MustCompile(`nuclei-templates version:\s*(\S+)\s*\(`)
	// retire.js prints a bare version: "5.4.3".
	retireJSVersionRE = regexp.MustCompile(`([0-9]+\.[0-9]+\.[0-9]+[^\s]*)`)
	// govulncheck prints a block naming itself and the database it read:
	//
	//   Scanner: govulncheck@v1.7.0
	//   DB updated: 2026-09-10 14:48:42 +0000 UTC
	//
	// Both matter for the same reason Trivy's pair does: the same binary against a database a
	// week older answers a different question, and a reader comparing two runs needs to know
	// which of the two moved.
	govulncheckScannerRE = regexp.MustCompile(`Scanner:\s*govulncheck@(\S+)`)
	govulncheckDBRE      = regexp.MustCompile(`DB updated:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})`)
)

var (
	// Asked with its update check off. `semgrep --version` otherwise calls semgrep.dev to see
	// whether a newer release exists, so the question "which build is this" would reach the
	// network on every scan, on a machine that may have said it has none. The answer is the same
	// either way, and without the check it is the version and nothing else.
	sharedSemgrepVersion = &toolVersionProbe{
		argv:    []string{"semgrep", "--version"},
		extract: firstMatch(semgrepVersionRE),
		run:     runWithoutSemgrepVersionCheck,
	}
	sharedGitleaksVersion = &toolVersionProbe{
		argv: []string{"gitleaks", "version"}, extract: firstMatch(gitleaksVersionRE), run: execArgv,
	}
	// kube-bench prints a bare version on stdout: "0.15.6".
	sharedKubeBenchVersion = &toolVersionProbe{
		argv: []string{"kube-bench", "version"}, extract: firstMatch(gitleaksVersionRE), run: execArgv,
	}
	sharedGosecVersion = &toolVersionProbe{
		argv: []string{"gosec", "--version"}, extract: firstMatch(gosecVersionRE), run: execArgv,
	}
	// Combined, not stdout: nuclei writes the template version to *stderr* and exits 0, so
	// reading stdout gets an empty string and a probe that silently reports nothing.
	sharedNucleiVersion = &toolVersionProbe{
		argv:    []string{"nuclei", "-templates-version"},
		extract: firstMatch(nucleiTemplateVersionRE),
		run:     execArgvCombined,
	}
	sharedRetireJSVersion = &toolVersionProbe{
		argv: []string{"retire", "--version"}, extract: firstMatch(retireJSVersionRE), run: execArgv,
	}
	sharedGovulncheckVersion = &toolVersionProbe{
		argv: []string{"govulncheck", "-version"}, extract: govulncheckVersion, run: execArgvCombined,
	}
)

// govulncheckVersion reads the scanner and the database out of govulncheck's version block, as
// `v1.7.0;db@2026-09-10 14:48:42`.
//
// The scanner alone where no database line was printed, and "" where neither was: a version that
// names the binary and silently drops the database it read would claim two runs are comparable
// when the thing that changed between them is the half that is missing.
func govulncheckVersion(out []byte) string {
	scanner := firstMatch(govulncheckScannerRE)(out)
	if scanner == "" {
		return ""
	}
	if db := firstMatch(govulncheckDBRE)(out); db != "" {
		return scanner + ";db@" + db
	}
	return scanner
}

// draugrCacheVersion is the cache version for a scanner whose rules live in this binary.
//
// The native scanners, HTTP headers, TLS, the CIS policy set. Have no external tool to ask, so
// the thing that changes their answer is Draugr itself. Without this, adding a CSP check (or
// fixing one) leaves every cached header result standing, and the new check silently does not
// run against anything already scanned.
func draugrCacheVersion() string { return "draugr@" + version.Version }
