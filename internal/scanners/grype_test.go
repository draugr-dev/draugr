package scanners

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
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
			t.Errorf("%s binary = %q, want grype, both scanners are the same tool", c.name, info.Binary)
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
	want := []string{"grype", "registry:repo/app:1.0", "-o", "sarif", "--by-cve"}
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
	want := []string{"grype", "dir:/checkout", "-o", "sarif", "--by-cve"}
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
	if env := grypeEnv(); slices.Contains(env, "GRYPE_DB_AUTO_UPDATE=false") {
		t.Errorf("online env = %v, want Grype free to refresh its database", env)
	}
	netpolicy.SetOffline(true)
	t.Cleanup(func() { netpolicy.SetOffline(false) })
	if got := grypeEnv(); !slices.Contains(got, "GRYPE_DB_AUTO_UPDATE=false") {
		t.Errorf("offline env = %v, want the database update disabled, Grype checks for a newer "+
			"database when a scan starts, not only when asked to update", got)
	}
}

// The application update check reaches toolbox-data.anchore.io from every scan, offline included,
// and logs its failure at ERROR, where it would be the line quoted for an unrelated failure.
func TestGrypeEnvNeverChecksForANewerGrype(t *testing.T) {
	t.Cleanup(func() { netpolicy.SetOffline(false) })
	for _, offline := range []bool{false, true} {
		netpolicy.SetOffline(offline)
		if got := grypeEnv(); !slices.Contains(got, "GRYPE_CHECK_FOR_APP_UPDATE=false") {
			t.Errorf("offline=%v: env = %v, want the application update check off", offline, got)
		}
	}
}

// A failed Grype scan says why. Grype writes the reason to its log, which -q silences, so the
// stand-in refuses -q. The stderr below is what grype 0.121.0 writes when its database no longer
// matches the digest in import.json, with the color codes it adds without NO_COLOR, and the scan
// runs through the real exec path with the stand-in on PATH.
func TestGrypeFSErrorCarriesWhatGrypeSaid(t *testing.T) {
	bin := t.TempDir()
	script := "#!/bin/sh\n" +
		"for a in \"$@\"; do [ \"$a\" = -q ] && exit 3; done\n" +
		"printf '%s\\n' '[0000]  WARN no explicit name and version provided for directory source, deriving artifact ID from the given path (which is not ideal) from=syft' >&2\n" +
		"printf '%s\\n' 'Database checksum invalid, run `grype db delete` to remove it and `grype db update` to update.' >&2\n" +
		"printf '[0000] ERROR \\033[31mfailed to load vulnerability db: bad db checksum (/home/u/.cache/grype/db/6/vulnerability.db): \"xxh64:55000f2cfe183096\" vs \"xxh64:4a9cf99fd7662c01\"\\033[0m\\n' >&2\n" +
		"exit 1\n"
	if err := os.WriteFile(filepath.Join(bin, "grype"), []byte(script), 0o700); err != nil { // #nosec G306 -- an executable the test runs
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	useGrypeDB(t, execGrype)

	for _, repo := range []string{"api", "worker"} {
		s := NewGrypeFS().(repoScanner)
		dir := t.TempDir()
		s.checkout = func(context.Context, string, string, git.Scope) (git.Tree, func(), error) {
			return git.Tree{Dir: dir}, func() {}, nil
		}
		_, err := s.Scan(context.Background(), plugin.RepositoryTarget{URL: repo}, nil)
		if err == nil {
			t.Fatalf("%s: want the scan to fail", repo)
		}
		msg := err.Error()
		if !strings.Contains(msg, "exit status 1") || !strings.Contains(msg, "bad db checksum") {
			t.Errorf("%s: error = %q, want the exit status and grype's reason", repo, msg)
		}
		for _, noise := range []string{"\x1b", "[0000]", "WARN"} {
			if strings.Contains(msg, noise) {
				t.Errorf("%s: error = %q, carries %q", repo, msg, noise)
			}
		}
	}
}

// TestGrypeRepoFindingsAreRepositoryRelativeAndCarryThePackage drives the repository scanner as it
// is constructed, over two repositories, with Grype's own SARIF.
//
// testdata/grype-fs-flask.sarif is what Grype 0.118.0, with a database built 2026-10-04, wrote for
// `grype dir:<root> -q -o sarif --by-cve` over a tree holding app/requirements.txt with flask
// pinned at 0.12.2. Grype roots directory paths at the directory it scanned, so they arrive looking
// absolute and survive the checkout-relative rewrite untouched. It also states the package on the
// rule rather than the result, so the results read on their own carry no package identity.
func TestGrypeRepoFindingsAreRepositoryRelativeAndCarryThePackage(t *testing.T) {
	out, err := os.ReadFile("testdata/grype-fs-flask.sarif")
	if err != nil {
		t.Fatal(err)
	}
	prior := grypeRunInDir
	t.Cleanup(func() { grypeRunInDir = prior })
	grypeRunInDir = func(_ context.Context, _ string, argv []string) ([]byte, error) {
		fakeGrypeOutputs(t, argv, grypeJSON())
		return out, nil
	}

	// The fixing version differs per advisory, so each finding has to take the package from its own
	// rule rather than from whichever rule was read first.
	fixedBy := map[string]string{
		"CVE-2018-1000656-flask": "0.12.3",
		"CVE-2019-1010083-flask": "1.0",
		"CVE-2023-30861-flask":   "2.2.5",
		"CVE-2026-27205-flask":   "3.1.3",
	}
	for _, repo := range []string{"api", "worker"} {
		dir := t.TempDir()
		s := NewGrypeFS().(repoScanner)
		s.checkout = func(context.Context, string, string, git.Scope) (git.Tree, func(), error) {
			return git.Tree{Dir: dir}, func() {}, nil
		}
		rep, err := s.Scan(context.Background(), plugin.RepositoryTarget{URL: repo}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Results) != len(fixedBy) {
			t.Fatalf("%s: results = %d, want one per advisory in Grype's output", repo, len(rep.Results))
		}
		for _, r := range rep.Results {
			if got := r.Location.URI; got != "app/requirements.txt" {
				t.Errorf("%s: %s location = %q, want a repository-relative path: a leading slash "+
					"anchors the finding nowhere in code scanning and stops it matching the same "+
					"package reported by another scanner", repo, r.RuleID, got)
			}
			p := r.Package
			if p == nil {
				t.Errorf("%s: %s carries no package, so no VEX statement or other scanner's finding "+
					"can be matched to it", repo, r.RuleID)
				continue
			}
			if p.PURL != "pkg:pypi/flask@0.12.2" || p.Name != "flask" || p.Version != "0.12.2" || p.Ecosystem != "python" {
				t.Errorf("%s: %s package = %+v", repo, r.RuleID, *p)
			}
			if want, ok := fixedBy[r.RuleID]; !ok || p.FixedVersion != want {
				t.Errorf("%s: %s fixed version = %q, want %q", repo, r.RuleID, p.FixedVersion, want)
			}
		}
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

// grypeImageSARIF is Grype's SARIF for an image, where the package is stated on the rule.
const grypeImageSARIF = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"grype","rules":[{
  "id":"CVE-2018-1000656-flask",
  "help":{"text":"Vulnerability CVE-2018-1000656\nSeverity: high\nPackage: flask\nVersion: 0.12.2\nFix Version: 0.12.3\nType: python\n"},
  "properties":{"purls":["pkg:pypi/flask@0.12.2"]}}]}},
 "results":[{"ruleId":"CVE-2018-1000656-flask","level":"error","message":{"text":"vuln"},
  "locations":[{"physicalLocation":{"artifactLocation":{"uri":"/usr/lib/python3.12/site-packages/Flask-0.12.2.dist-info/METADATA"}}}]}]}]}`

// TestGrypeImageFindingsCarryThePackage drives the image scanner as it is constructed, over two
// images. The purl is what correlates Grype's finding with Trivy's on the same image, so an image
// finding without one is counted twice when both scanners run.
func TestGrypeImageFindingsCarryThePackage(t *testing.T) {
	prior := grypeRun
	t.Cleanup(func() { grypeRun = prior })
	grypeRun = func(_ context.Context, argv []string) ([]byte, error) {
		fakeGrypeOutputs(t, argv, `{"ignoredMatches": []}`)
		return []byte(grypeImageSARIF), nil
	}

	s := NewGrype()
	for _, ref := range []string{"registry.example/api:1.0", "registry.example/worker:1.0"} {
		rep, err := s.Scan(context.Background(), plugin.ImageTarget{Ref: ref}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Results) != 1 {
			t.Fatalf("%s: results = %d, want 1", ref, len(rep.Results))
		}
		got := rep.Results[0]
		if got.Package == nil {
			t.Fatalf("%s: no package on an image finding", ref)
		}
		if got.Package.PURL != "pkg:pypi/flask@0.12.2" || got.Package.Name != "flask" ||
			got.Package.Version != "0.12.2" || got.Package.FixedVersion != "0.12.3" {
			t.Errorf("%s: package = %+v", ref, *got.Package)
		}
		if got.Image != ref || got.Location.URI != ref {
			t.Errorf("%s: image/location = %q/%q, want the image reference", ref, got.Image, got.Location.URI)
		}
	}
}

func TestParseGrypeImageSARIFRejectsGarbage(t *testing.T) {
	if _, err := parseGrypeImageSARIF([]byte("not sarif"), plugin.ImageTarget{Ref: "a:1"}, nil); err == nil {
		t.Error("unparseable output should error rather than report a clean scan")
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
		t.Errorf("cacheVersion = %q, want %q, a cache key blind to the database serves "+
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

// grypeOpen is the command that reads Grype's database without scanning anything.
var grypeOpen = []string{"grype", "db", "providers", "-o", "json"}

func TestGrypeDBWarmUpdatesThenReadsOnceAndNeverUpdatesOffline(t *testing.T) {
	var ran [][]string
	w := &grypeDBWarmer{run: func(_ context.Context, argv []string) ([]byte, error) {
		ran = append(ran, argv)
		return nil, nil
	}}
	for range 3 {
		if err := w.warm(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	want := [][]string{{"grype", "db", "update", "-q"}, grypeOpen}
	if !slices.EqualFunc(ran, want, slices.Equal) {
		t.Errorf("warm ran %v, want %v: one download that concurrent jobs share, then one read "+
			"that migrates what the download left", ran, want)
	}

	netpolicy.SetOffline(true)
	t.Cleanup(func() { netpolicy.SetOffline(false) })
	ran = nil
	offline := &grypeDBWarmer{run: w.run}
	if err := offline.warm(context.Background()); err != nil {
		t.Errorf("offline warm should not be an error: %v", err)
	}
	if want := [][]string{grypeOpen}; !slices.EqualFunc(ran, want, slices.Equal) {
		t.Errorf("offline warm ran %v, want only %v: an offline run must not fetch a database it "+
			"was told not to fetch, and still reads the one on disk", ran, want)
	}
}

// A failed update is the warm's answer, and the database on disk is still read: a run whose
// download failed scans whatever is there, and that is the database that may need migrating.
func TestGrypeDBWarmReadsTheDatabaseAfterAFailedUpdate(t *testing.T) {
	var opened bool
	w := &grypeDBWarmer{run: func(_ context.Context, argv []string) ([]byte, error) {
		if slices.Equal(argv, grypeOpen) {
			opened = true
			return nil, errors.New("exit status 1")
		}
		return nil, errors.New("unable to update vulnerability database")
	}}
	if err := w.warm(context.Background()); err == nil || !strings.Contains(err.Error(), "unable to update") {
		t.Errorf("warm = %v, want the update's error rather than the read's", err)
	}
	if !opened {
		t.Error("the database was not read after the update failed")
	}
}

// useGrypeDB replaces the process-wide database preparation with one that runs run, for the test.
func useGrypeDB(t *testing.T, run func(ctx context.Context, argv []string) ([]byte, error)) {
	t.Helper()
	prior := sharedGrypeDB
	t.Cleanup(func() { sharedGrypeDB = prior })
	sharedGrypeDB = &grypeDBWarmer{run: run}
}

// grypeMigratingStandIn is a grype that behaves as the real one does over a database an older Grype
// imported. `grype db providers` migrates it, which takes a moment, and a scan that starts before
// the migration has finished fails as the real one does, with a checksum that no longer matches.
// Each invocation is logged to $GRYPE_STANDIN_STATE/log so a test can read the order.
const grypeMigratingStandIn = `#!/bin/sh
state="$GRYPE_STANDIN_STATE"
if [ "$1" = db ] && [ "$2" = providers ]; then
  echo open-start >> "$state/log"
  sleep 0.2
  : > "$state/migrated"
  echo open-end >> "$state/log"
  echo '[]'
  exit 0
fi
if [ "$1" = db ]; then
  echo "db $2" >> "$state/log"
  exit 0
fi
echo "scan $1" >> "$state/log"
if [ ! -f "$state/migrated" ]; then
  echo '[0000] ERROR failed to load vulnerability db: bad db checksum' >&2
  exit 1
fi
prev=
for a in "$@"; do
  if [ "$prev" = -o ]; then
    case "$a" in
      json=*) printf '{"matches": [], "ignoredMatches": [], "source": {"type": "directory", "target": "/src"}}' > "${a#json=}" ;;
      cyclonedx-json=*) printf '{"components": []}' > "${a#cyclonedx-json=}" ;;
    esac
  fi
  prev=$a
done
echo '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"grype"}},"results":[]}]}'
`

// TestGrypeScansReadTheDatabaseOnceBeforeAnyScan runs Grype scans of two repositories and an image
// at once, through the real exec path, against a stand-in grype whose database has to be migrated
// before it can be scanned. Every scan has to wait for the one read that migrates it, the read has
// to happen once however many scans arrive, and offline it has to happen too, because an offline
// run has no prewarm to do it.
func TestGrypeScansReadTheDatabaseOnceBeforeAnyScan(t *testing.T) {
	t.Cleanup(func() { netpolicy.SetOffline(false) })
	for _, offline := range []bool{false, true} {
		t.Run(fmt.Sprintf("offline=%v", offline), func(t *testing.T) {
			netpolicy.SetOffline(offline)
			bin, state := t.TempDir(), t.TempDir()
			if err := os.WriteFile(filepath.Join(bin, "grype"), []byte(grypeMigratingStandIn), 0o700); err != nil { // #nosec G306 -- an executable the test runs
				t.Fatal(err)
			}
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("GRYPE_STANDIN_STATE", state)
			useGrypeDB(t, execGrype)

			scans := map[string]func(context.Context) error{}
			for _, repo := range []string{"api", "worker"} {
				s := NewGrypeFS().(repoScanner)
				dir := t.TempDir()
				s.checkout = func(context.Context, string, string, git.Scope) (git.Tree, func(), error) {
					return git.Tree{Dir: dir}, func() {}, nil
				}
				scans["repository "+repo] = func(ctx context.Context) error {
					_, err := s.Scan(ctx, plugin.RepositoryTarget{URL: repo}, nil)
					return err
				}
			}
			image := NewGrype()
			scans["image"] = func(ctx context.Context) error {
				_, err := image.Scan(ctx, plugin.ImageTarget{Ref: "registry.example/app:1"}, nil)
				return err
			}

			start := make(chan struct{})
			var wg sync.WaitGroup
			errs := make(map[string]error, len(scans))
			var mu sync.Mutex
			for name, scan := range scans {
				wg.Go(func() {
					<-start
					err := scan(context.Background())
					mu.Lock()
					errs[name] = err
					mu.Unlock()
				})
			}
			close(start)
			wg.Wait()
			for name, err := range errs {
				if err != nil {
					t.Errorf("%s: %v", name, err)
				}
			}

			log, err := os.ReadFile(filepath.Join(state, "log")) // #nosec G304 -- under the test's temp dir
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Fields(strings.ReplaceAll(string(log), " ", "_"))
			if n := slices.Index(lines, "open-end"); n != 1 || lines[0] != "open-start" {
				t.Errorf("grype ran %v, want the database read to finish before any scan starts", lines)
			}
			if n := strings.Count(string(log), "open-start"); n != 1 {
				t.Errorf("the database was read %d times, want once however many scans run", n)
			}
			if n := strings.Count(string(log), "scan "); n != len(scans) {
				t.Errorf("grype scanned %d times, want %d", n, len(scans))
			}
			if strings.Contains(string(log), "db update") {
				t.Errorf("a scan ran `grype db update`, which belongs to the prewarm alone: %v", lines)
			}
		})
	}
}

// TestGrypeScannersAreWiredToTheSharedDatabase checks the constructors, not the pieces.
//
// Asking whether the scanner implements CacheVersion or Prewarm proves nothing: both types carry
// those methods whether or not a hook was attached, and answer "" and nil when one wasn't. So the
// shared probe and warmer are replaced with fakes *before* construction, the constructors capture
// them, and the test asserts each one was actually consulted. Left unattached, the scan still
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
				t.Errorf("%s cache version = %q, the probe was not wired, so a database refresh "+
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

func TestGrypePackagesReadsWhatTheRuleCarries(t *testing.T) {
	// Grype states the dependency on the rule rather than the result, a purl in its property bag, the
	// fixing version in its help text, so the generic SARIF reader never saw it and every Grype
	// finding arrived with no package identity at all.
	out := []byte(`{"runs":[{"tool":{"driver":{"rules":[{
	  "id":"CVE-2019-1010083-flask",
	  "help":{"text":"Vulnerability CVE-2019-1010083\nSeverity: high\nPackage: flask\nVersion: 0.12.2\nFix Version: 1.0\nType: python\n"},
	  "properties":{"purls":["pkg:pypi/flask@0.12.2"]}}]}}}]}`)
	got := grypePackages(out)
	pkg, ok := got["CVE-2019-1010083-flask"]
	if !ok {
		t.Fatalf("no package for the rule: %+v", got)
	}
	if pkg.Name != "flask" || pkg.Version != "0.12.2" {
		t.Errorf("name/version = %q/%q", pkg.Name, pkg.Version)
	}
	if pkg.FixedVersion != "1.0" {
		t.Errorf("fixedVersion = %q, want the version that resolves it", pkg.FixedVersion)
	}
	if pkg.PURL != "pkg:pypi/flask@0.12.2" {
		t.Errorf("purl = %q, this is the identifier another scanner's finding is matched on", pkg.PURL)
	}
	if pkg.Ecosystem != "python" {
		t.Errorf("ecosystem = %q", pkg.Ecosystem)
	}
}

func TestGrypePackagesSkipsRulesWithNoPURL(t *testing.T) {
	out := []byte(`{"runs":[{"tool":{"driver":{"rules":[{"id":"x","properties":{}}]}}}]}`)
	if got := grypePackages(out); len(got) != 0 {
		t.Errorf("got %+v, want nothing for a rule that names no package", got)
	}
}

func TestGrypePackagesToleratesOutputItCannotRead(t *testing.T) {
	// The report itself already parsed by this point; a property bag we cannot read is a missing
	// detail, not a failed scan.
	if got := grypePackages([]byte("{not json")); got != nil {
		t.Errorf("got %+v, want nil", got)
	}
}
