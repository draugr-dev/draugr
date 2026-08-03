package scanners

import (
	"context"
	"errors"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

func TestToolVersionProbeExtracts(t *testing.T) {
	cases := []struct {
		name, out, want string
		probe           *toolVersionProbe
	}{
		{"semgrep", "1.155.0\n", "1.155.0", sharedSemgrepVersion},
		{"gitleaks", "v8.30.1\n", "8.30.1", sharedGitleaksVersion},
		{"gosec", "Version: 2.22.10\nGit tag: v2.22.10\n", "2.22.10", sharedGosecVersion},
		{"kube-bench", "0.15.6\n", "0.15.6", sharedKubeBenchVersion},
		{
			// The line nuclei writes, ANSI codes and all — and it writes it to stderr, which is
			// why the probe reads both streams.
			"nuclei",
			"[\x1b[34mINF\x1b[0m] Public nuclei-templates version: v10.4.6 (/home/you/nuclei-templates)\n",
			"v10.4.6", sharedNucleiVersion,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.probe.extract([]byte(c.out)); got != c.want {
				t.Errorf("extract(%q) = %q, want %q", c.out, got, c.want)
			}
		})
	}
}

func TestToolVersionProbeRunsOnce(t *testing.T) {
	calls := 0
	p := &toolVersionProbe{
		argv:    []string{"x"},
		extract: func([]byte) string { return "1.2.3" },
		run: func(context.Context, []string) ([]byte, error) {
			calls++
			return []byte("1.2.3"), nil
		},
	}
	for range 5 {
		if got := p.version(context.Background()); got != "1.2.3" {
			t.Fatalf("got %q", got)
		}
	}
	// A subprocess per scan job would cost more than the cache saves.
	if calls != 1 {
		t.Errorf("probed %d times, want 1", calls)
	}
}

func TestToolVersionProbeUnreadableYieldsEmpty(t *testing.T) {
	// Empty, never a guess. A wrong version in the key makes two genuinely different tool
	// versions look identical, which is worse than no version at all.
	failing := &toolVersionProbe{
		extract: func([]byte) string { return "should not be reached" },
		run:     func(context.Context, []string) ([]byte, error) { return nil, errors.New("not installed") },
	}
	if got := failing.version(context.Background()); got != "" {
		t.Errorf("a tool that would not run reported %q", got)
	}

	garbage := &toolVersionProbe{
		extract: firstMatch(semgrepVersionRE),
		run:     func(context.Context, []string) ([]byte, error) { return []byte("command not found"), nil },
	}
	if got := garbage.version(context.Background()); got != "" {
		t.Errorf("unparseable output reported %q", got)
	}
}

func TestNativeScannersKeyOnDraugrsOwnVersion(t *testing.T) {
	// Their rules ship in this binary, so a Draugr upgrade is what changes the answer. Without
	// this, today's new CSP checks would not run against anything already cached.
	ctx := context.Background()
	for name, got := range map[string]string{
		"draugr-headers": NewHTTPHeaders().(interface {
			CacheVersion(context.Context) string
		}).CacheVersion(ctx),
		"draugr-tls": NewTLSProbe().(interface {
			CacheVersion(context.Context) string
		}).CacheVersion(ctx),
		"draugr-k8s-policies": NewK8sPolicies().(interface {
			CacheVersion(context.Context) string
		}).CacheVersion(ctx),
	} {
		if got == "" {
			t.Errorf("%s contributes nothing to the cache key", name)
		}
	}
}

// TestEveryScannerWiresACacheVersion is white-box on purpose.
//
// The obvious test — "does it implement plugin.CacheVersioner" — passes for every repoScanner
// whether or not anything is wired, because the method exists on the type and returns "" when
// the field is nil. It is the field that carries the meaning, so it is the field that is checked.
//
// A new scanner belongs in this list. The cost of forgetting is a cache that serves yesterday's
// answer after the thing that decides the answer has changed, and nothing says so.
func TestEveryScannerWiresACacheVersion(t *testing.T) {
	all := map[string]plugin.Scanner{
		"trivy":               NewTrivy(),
		"trivy-fs":            NewTrivyFS(),
		"trivy-config":        NewTrivyConfig(),
		"trivy-license":       NewTrivyLicense(),
		"semgrep":             NewSemgrep(),
		"gosec":               NewGosec(),
		"gitleaks":            NewGitleaks(),
		"nuclei":              NewNuclei(),
		"draugr-headers":      NewHTTPHeaders(),
		"draugr-tls":          NewTLSProbe(),
		"draugr-k8s-policies": NewK8sPolicies(),
		"kube-bench":          NewKubeBench(),
		"kube-bench-job":      NewKubeBenchJob(),
	}

	for name, s := range all {
		switch v := s.(type) {
		case repoScanner:
			if v.cacheVersion == nil {
				t.Errorf("%s: repoScanner.cacheVersion is nil, so its cache key carries no tool "+
					"or data version — an upgrade will not invalidate a cached result", name)
			}
		default:
			cv, ok := s.(plugin.CacheVersioner)
			if !ok {
				t.Errorf("%s: implements neither a wired cacheVersion nor plugin.CacheVersioner", name)
				continue
			}
			_ = cv // the value depends on the machine; the wiring is what this asserts
		}
	}
}

// TestNativeAndPinnedScannersAnswerWithoutATool checks the ones that can always answer.
//
// A probe returns "" on a machine without the tool, which is correct and untestable here. These
// four have no such excuse: their version is this binary, a catalogue that ships with it, or a
// digest written in the source.
func TestNativeAndPinnedScannersAnswerWithoutATool(t *testing.T) {
	ctx := context.Background()
	for name, s := range map[string]plugin.Scanner{
		"draugr-headers":      NewHTTPHeaders(),
		"draugr-tls":          NewTLSProbe(),
		"draugr-k8s-policies": NewK8sPolicies(),
		"kube-bench-job":      NewKubeBenchJob(),
	} {
		cv, ok := s.(plugin.CacheVersioner)
		if !ok {
			t.Errorf("%s does not implement plugin.CacheVersioner", name)
			continue
		}
		if got := cv.CacheVersion(ctx); got == "" {
			t.Errorf("%s answered %q — it needs no external tool, so it has no reason not to", name, got)
		}
	}
}
