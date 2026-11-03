package scanners

import (
	"context"
	"slices"
	"testing"

	"github.com/draugr-dev/draugr/internal/netpolicy"
)

// noticeFlags are the two flags Trivy needs together before it skips its request to check.trivy.dev.
var noticeFlags = []string{"--skip-version-check", "--disable-telemetry"}

// withTrivyVersion has the shared probe answer for one Trivy release, as though it had run.
func withTrivyVersion(t *testing.T, version string) {
	t.Helper()
	was := sharedTrivyVersion.val
	t.Cleanup(func() { sharedTrivyVersion.val = was })
	sharedTrivyVersion.val = version
}

// hasNoticeFlags reports whether argv carries both flags, each once, ahead of its last argument.
func hasNoticeFlags(argv []string) bool {
	for _, f := range noticeFlags {
		i := slices.Index(argv, f)
		if i < 0 || i == len(argv)-1 || slices.Contains(argv[i+1:], f) {
			return false
		}
	}
	return true
}

// Every Trivy command line a scan of two components in two repositories runs carries both flags,
// online and offline: the filesystem, license and misconfiguration scans of each repository and the
// vulnerability and license scans of each image. api sets resolveMaven, so its trivy-fs run is the
// one without --offline-scan, and it still carries them.
func TestEveryTrivyRunSkipsTheVersionCheckAndTelemetry(t *testing.T) {
	for _, version := range []string{"trivy@0.63.0;db@2026-07-15T00:56:58Z", "trivy@0.76.1;db@2026-11-02T19:15:11Z"} {
		for _, offline := range []bool{false, true} {
			withTrivyVersion(t, version)
			netpolicy.SetOffline(offline)
			argvs := trivyArgvs(t)
			netpolicy.SetOffline(false)
			if len(argvs) != 10 {
				t.Fatalf("%s offline=%v: %d command lines, want 5 scanners x 2 components", version, offline, len(argvs))
			}
			for key, argv := range argvs {
				if !hasNoticeFlags(argv) {
					t.Errorf("%s offline=%v %s: want %v once each, before the target: %v",
						version, offline, key, noticeFlags, argv)
				}
			}
		}
	}
}

// A Trivy older than 0.63.0 has neither flag and refuses the command line that carries one, so it
// gets neither: 0.62.1 runs `trivy fs` for misconfiguration and 0.52.0 runs `trivy config`. A
// version the probe could not read gets the command Draugr has always run.
func TestOlderTrivyGetsNoNoticeFlags(t *testing.T) {
	for _, version := range []string{"trivy@0.62.1;db@2025-05-06T00:00:00Z", "trivy@0.52.0;db@2024-06-01T00:00:00Z", ""} {
		withTrivyVersion(t, version)
		for key, argv := range trivyArgvs(t) {
			for _, f := range noticeFlags {
				if slices.Contains(argv, f) {
					t.Errorf("%q %s: %s passed to a Trivy without it: %v", version, key, f, argv)
				}
			}
		}
	}
}

// The two warms run ahead of every scan, and so ahead of the cache key that otherwise resolves the
// version. Each resolves it first, then passes both flags where the Trivy has them.
func TestTrivyWarmsSkipTheVersionCheckAndTelemetry(t *testing.T) {
	for _, tc := range []struct {
		version string
		want    bool
	}{
		{"trivy@0.76.1;db@2026-11-02T19:15:11Z", true},
		{"trivy@0.62.1;db@2025-05-06T00:00:00Z", false},
	} {
		withTrivyVersion(t, "")
		resolve := func(context.Context) string {
			sharedTrivyVersion.val = tc.version
			return tc.version
		}
		var ran [][]string
		record := func(_ context.Context, argv []string) ([]byte, error) {
			ran = append(ran, argv)
			return nil, nil
		}
		db := &trivyDBWarmer{run: record, version: resolve}
		checks := &trivyChecksWarmer{run: record, version: resolve,
			dir: func() (string, func(), error) { return "/tmp/empty", func() {}, nil }}
		if err := db.warm(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := checks.warm(t.Context()); err != nil {
			t.Fatal(err)
		}
		if len(ran) != 2 {
			t.Fatalf("%s: ran %v, want one database warm and one checks warm", tc.version, ran)
		}
		for _, argv := range ran {
			if got := slices.Contains(argv, noticeFlags[0]) && slices.Contains(argv, noticeFlags[1]); got != tc.want {
				t.Errorf("%s: %v carries %v = %v, want %v", tc.version, argv, noticeFlags, got, tc.want)
			}
		}
		if last := ran[1][len(ran[1])-1]; last != "/tmp/empty" {
			t.Errorf("checks warm: the directory is no longer last: %v", ran[1])
		}
	}
}
