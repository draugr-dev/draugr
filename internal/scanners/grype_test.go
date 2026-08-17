package scanners

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/internal/netpolicy"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func TestGrypeInfo(t *testing.T) {
	for _, c := range []struct {
		scanner          plugin.Scanner
		name, control    string
		kind             plugin.TargetKind
		wantConfigSchema bool
	}{
		{NewGrype(), "grype", "images", plugin.TargetImage, true},
		{NewGrypeFS(), "grype-fs", "sca", plugin.TargetRepository, true},
	} {
		info := c.scanner.Info()
		if info.Name != c.name {
			t.Errorf("name = %q, want %q", info.Name, c.name)
		}
		if info.Binary != "grype" {
			t.Errorf("%s binary = %q, want grype — both scanners are the same tool", c.name, info.Binary)
		}
		if len(info.Controls) != 1 || info.Controls[0] != c.control {
			t.Errorf("%s controls = %v, want [%s]", c.name, info.Controls, c.control)
		}
		if len(info.TargetKinds) != 1 || info.TargetKinds[0] != c.kind {
			t.Errorf("%s target kinds = %v", c.name, info.TargetKinds)
		}
		// An absent schema accepts any option and then discards it, which is a setting that
		// silently does nothing.
		if c.wantConfigSchema && len(info.ConfigSchema) == 0 {
			t.Errorf("%s declares no config schema", c.name)
		}
	}
}

func TestGrypeArgv(t *testing.T) {
	argv, err := grypeArgv(plugin.ImageTarget{Ref: "repo/app:1.0"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"grype", "registry:repo/app:1.0", "-q", "-o", "sarif", "--by-cve"}
	if !slices.Equal(argv, want) {
		t.Errorf("argv = %v, want %v", argv, want)
	}
}

// TestGrypeArgvAlwaysNamesTheRegistry is the assertion that a bare reference would quietly break.
// Without the scheme Grype tries a local Docker daemon first: on a runner that is a failed
// connection before every scan, and on a workstation it scans whatever the daemon cached under
// that tag instead of what the registry serves.
func TestGrypeArgvAlwaysNamesTheRegistry(t *testing.T) {
	for _, target := range []plugin.ImageTarget{
		{Ref: "repo/app:1.0"},
		{Digest: "sha256:abc"},
		{Ref: "repo/app:1.0", Digest: "sha256:abc"},
	} {
		argv, err := grypeArgv(target, nil)
		if err != nil {
			t.Fatalf("%+v: %v", target, err)
		}
		if !strings.HasPrefix(argv[1], "registry:") {
			t.Errorf("%+v scanned %q, which lets a local daemon answer instead", target, argv[1])
		}
	}
}

func TestGrypeArgvPinsDigest(t *testing.T) {
	argv, _ := grypeArgv(plugin.ImageTarget{Ref: "repo/app:1.0", Digest: "sha256:abc"}, nil)
	if got := argv[1]; got != "registry:repo/app:1.0@sha256:abc" {
		t.Errorf("should scan the pinned ref, got %q", got)
	}
}

func TestGrypeArgvErrors(t *testing.T) {
	if _, err := grypeArgv(plugin.RepositoryTarget{URL: "u"}, nil); err == nil {
		t.Error("a non-image target should error rather than scan something else")
	}
	if _, err := grypeArgv(plugin.ImageTarget{}, nil); err == nil {
		t.Error("an image target with neither ref nor digest should error")
	}
}

func TestGrypeFSArgs(t *testing.T) {
	want := []string{"grype", "dir:/checkout", "-q", "-o", "sarif", "--by-cve"}
	if got := grypeFSArgs("/checkout", nil); !slices.Equal(got, want) {
		t.Errorf("args = %v, want %v", got, want)
	}
}

// TestGrypeByCVEIsOnUnlessRefused pins the departure from Grype's own default. Beside Trivy, an
// un-normalized identifier makes one vulnerability arrive twice under two names, and slips past an
// exclusion written against the CVE.
func TestGrypeByCVEIsOnUnlessRefused(t *testing.T) {
	for _, c := range []struct {
		name string
		cfg  plugin.Config
		want bool
	}{
		{"no config", nil, true},
		{"an unrelated key", plugin.Config{"other": true}, true},
		{"explicitly on", plugin.Config{"byCve": true}, true},
		{"explicitly off", plugin.Config{"byCve": false}, false},
		{"a non-boolean is not an opt-out", plugin.Config{"byCve": "false"}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := slices.Contains(grypeFSArgs("/d", c.cfg), "--by-cve"); got != c.want {
				t.Errorf("--by-cve present = %v, want %v", got, c.want)
			}
			argv, _ := grypeArgv(plugin.ImageTarget{Ref: "r"}, c.cfg)
			if got := slices.Contains(argv, "--by-cve"); got != c.want {
				t.Errorf("image scanner disagrees with the repository one: %v", argv)
			}
		})
	}
}

// TestGrypeNeverFiltersInsideTheTool guards the design rule rather than a flag. A finding dropped
// by the scanner cannot be marked suppressed, and nothing records who accepted it.
func TestGrypeNeverFiltersInsideTheTool(t *testing.T) {
	cfg := plugin.Config{"byCve": true}
	imageArgv, _ := grypeArgv(plugin.ImageTarget{Ref: "r"}, cfg)
	for _, argv := range [][]string{imageArgv, grypeFSArgs("/d", cfg)} {
		for _, banned := range []string{"--fail-on", "-f", "--only-fixed", "--only-notfixed", "--ignore-states", "--exclude"} {
			if slices.Contains(argv, banned) {
				t.Errorf("%v drops findings inside the tool via %s", argv, banned)
			}
		}
	}
}

func TestGrypeEnvOnlyDisablesUpdatesOffline(t *testing.T) {
	if env := grypeEnv(); env != nil {
		t.Errorf("online, Grype should run with the ambient environment, got %v", env)
	}
	netpolicy.SetOffline(true)
	t.Cleanup(func() { netpolicy.SetOffline(false) })
	if got := grypeEnv(); !slices.Contains(got, "GRYPE_DB_AUTO_UPDATE=false") {
		t.Errorf("offline env = %v, want the database update disabled — Grype checks for a newer "+
			"database when a scan starts, not only when asked to update", got)
	}
}

const grypeRepoSARIF = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"grype"}},"results":[
{"ruleId":"CVE-1-requests","level":"error","message":{"text":"vuln"},
 "locations":[{"physicalLocation":{"artifactLocation":{"uri":"/app/requirements.txt"}}}]}]}]}`

// TestGrypeRepoPathsAreRepositoryRelative covers the one transformation this scanner exists to
// apply. Grype roots directory paths at the directory it scanned, so they arrive looking absolute
// and survive the checkout-relative rewrite untouched.
func TestGrypeRepoPathsAreRepositoryRelative(t *testing.T) {
	s := repoScanner{
		info: plugin.ScannerInfo{Name: "grype-fs", Controls: []string{"sca"}},
		args: grypeFSArgs,
		checkout: func(_ context.Context, _, _ string, _ git.Scope) (git.Tree, func(), error) {
			return git.Tree{Dir: "/tmp/checkout-1"}, func() {}, nil
		},
		parse: parseGrypeRepoSARIF,
		run: func(context.Context, string, []string) ([]byte, error) {
			return []byte(grypeRepoSARIF), nil
		},
	}
	rep, err := s.Scan(context.Background(), plugin.RepositoryTarget{URL: "u"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 {
		t.Fatalf("results = %d", len(rep.Results))
	}
	if got := rep.Results[0].Location.URI; got != "app/requirements.txt" {
		t.Errorf("location = %q, want a repository-relative path: a leading slash anchors the "+
			"finding nowhere in code scanning and stops it matching the same package reported "+
			"by another scanner", got)
	}
}

func TestGrypeRepoPath(t *testing.T) {
	for _, c := range []struct{ name, dir, uri, want string }{
		{"scan-root relative", "/tmp/checkout", "/app/requirements.txt", "app/requirements.txt"},
		{"under the checkout", "/tmp/checkout", "/tmp/checkout/go.mod", "go.mod"},
		{"already relative", "/tmp/checkout", "go.mod", "go.mod"},
		{"empty", "/tmp/checkout", "", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := grypeRepoPath(c.dir, c.uri); got != c.want {
				t.Errorf("grypeRepoPath(%q, %q) = %q, want %q", c.dir, c.uri, got, c.want)
			}
		})
	}
}

func TestParseGrypeRepoSARIFRejectsGarbage(t *testing.T) {
	if _, err := parseGrypeRepoSARIF([]byte("not sarif"), "/d", nil); err == nil {
		t.Error("unparseable output should error rather than report a clean scan")
	}
}

func TestGrypeImageLocationsBecomeTheReference(t *testing.T) {
	// Grype locates an OS-package finding inside the image's own filesystem, which is not
	// somewhere a reader can look and is identical for every image a component ships.
	in := sarif.Report{Results: []sarif.Result{{Location: sarif.Location{URI: "alpine//lib/apk/db/installed"}}}}
	got := imageRefLocations(plugin.ImageTarget{Ref: "alpine:3.18"}, in)
	if got.Results[0].Location.URI != "alpine:3.18" {
		t.Errorf("location = %q, want the image reference", got.Results[0].Location.URI)
	}
}

func TestGrypeCacheVersionCombinesToolAndDatabase(t *testing.T) {
	p := &grypeVersionProbe{run: func(_ context.Context, argv []string) ([]byte, error) {
		if slices.Contains(argv, "version") {
			return []byte(`{"version":"0.117.0"}`), nil
		}
		return []byte(`{"built":"2026-08-14T06:39:10Z","valid":true}`), nil
	}}
	want := "grype@0.117.0;db@2026-08-14T06:39:10Z"
	if got := p.cacheVersion(context.Background()); got != want {
		t.Errorf("cacheVersion = %q, want %q — a cache key blind to the database serves "+
			"yesterday's answer about today's advisories", got, want)
	}
}

func TestGrypeCacheVersionDegradesRatherThanGuessing(t *testing.T) {
	for _, c := range []struct {
		name string
		run  func(context.Context, []string) ([]byte, error)
		want string
	}{
		{"grype absent", func(context.Context, []string) ([]byte, error) {
			return nil, errors.New("executable file not found")
		}, ""},
		{"unexpected version output", func(context.Context, []string) ([]byte, error) {
			return []byte(`{}`), nil
		}, ""},
		{"no database yet", func(_ context.Context, argv []string) ([]byte, error) {
			if slices.Contains(argv, "version") {
				return []byte(`{"version":"0.117.0"}`), nil
			}
			return nil, errors.New("database does not exist")
		}, "grype@0.117.0"},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := &grypeVersionProbe{run: c.run}
			if got := p.cacheVersion(context.Background()); got != c.want {
				t.Errorf("cacheVersion = %q, want %q", got, c.want)
			}
		})
	}
}

func TestGrypeDBWarmRunsOnceAndNotOffline(t *testing.T) {
	var calls int
	w := &grypeDBWarmer{run: func(_ context.Context, argv []string) ([]byte, error) {
		calls++
		if !slices.Contains(argv, "update") {
			t.Errorf("warm ran %v, want a database update", argv)
		}
		return nil, nil
	}}
	for range 3 {
		if err := w.warm(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Errorf("warmed %d times, want once — the point is that concurrent jobs share one download", calls)
	}

	netpolicy.SetOffline(true)
	t.Cleanup(func() { netpolicy.SetOffline(false) })
	offline := &grypeDBWarmer{run: func(context.Context, []string) ([]byte, error) {
		t.Error("an offline run must not reach out to warm a database it was told not to fetch")
		return nil, nil
	}}
	if err := offline.warm(context.Background()); err != nil {
		t.Errorf("offline warm should be a no-op, not an error: %v", err)
	}
}

// TestGrypeScannersAreWiredToTheSharedDatabase checks the constructors, not the pieces.
//
// Asking whether the scanner implements CacheVersion or Prewarm proves nothing: both types carry
// those methods whether or not a hook was attached, and answer "" and nil when one wasn't. So the
// shared probe and warmer are replaced with fakes *before* construction — the constructors capture
// them — and the test asserts each one was actually consulted. Left unattached, the scan still
// runs: it re-downloads the database per job and caches against a key that ignores it.
func TestGrypeScannersAreWiredToTheSharedDatabase(t *testing.T) {
	priorVersion, priorDB := sharedGrypeVersion, sharedGrypeDB
	t.Cleanup(func() { sharedGrypeVersion, sharedGrypeDB = priorVersion, priorDB })

	for _, c := range []struct {
		name string
		make func() plugin.Scanner
	}{
		{"grype", NewGrype},
		{"grype-fs", NewGrypeFS},
	} {
		t.Run(c.name, func(t *testing.T) {
			var warmed bool
			sharedGrypeVersion = &grypeVersionProbe{run: func(_ context.Context, argv []string) ([]byte, error) {
				if slices.Contains(argv, "version") {
					return []byte(`{"version":"9.9.9"}`), nil
				}
				return []byte(`{"built":"2026-01-01T00:00:00Z","valid":true}`), nil
			}}
			sharedGrypeDB = &grypeDBWarmer{run: func(context.Context, []string) ([]byte, error) {
				warmed = true
				return nil, nil
			}}

			s := c.make()
			versioner, ok := s.(plugin.CacheVersioner)
			if !ok {
				t.Fatalf("%s reports no cache version", c.name)
			}
			if got := versioner.CacheVersion(context.Background()); got != "grype@9.9.9;db@2026-01-01T00:00:00Z" {
				t.Errorf("%s cache version = %q — the probe was not wired, so a database refresh "+
					"leaves stale results cached", c.name, got)
			}
			warmer, ok := s.(plugin.Prewarmer)
			if !ok {
				t.Fatalf("%s does not prewarm", c.name)
			}
			if err := warmer.Prewarm(context.Background()); err != nil {
				t.Fatal(err)
			}
			if !warmed {
				t.Errorf("%s did not warm the shared database, so every concurrent job cold-starts it", c.name)
			}
		})
	}
}
