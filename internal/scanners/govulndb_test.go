package scanners

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/internal/feeds"
	"github.com/draugr-dev/draugr/internal/netpolicy"
	"github.com/draugr-dev/draugr/pkg/plugin"
)

func TestMain(m *testing.M) {
	// No test reads the developer's own ~/.draugr/feeds. A copy fetched there would otherwise
	// change what govulncheck is pointed at, and a test that passes on one machine fails on the
	// next for a reason nobody can see.
	findLocalGoVulnDB = func(time.Time, time.Duration) (feeds.LocalGoVulnDB, error) {
		return feeds.LocalGoVulnDB{}, feeds.ErrNoLocalGoVulnDB
	}
	os.Exit(m.Run())
}

// useGoVulnDB makes find the source of the local database for one test, and resets the choice
// either side of it.
func useGoVulnDB(t *testing.T, find func(time.Time, time.Duration) (feeds.LocalGoVulnDB, error)) {
	t.Helper()
	orig := findLocalGoVulnDB
	findLocalGoVulnDB = find
	SetFeedMaxAge(feeds.DefaultMaxAge)
	t.Cleanup(func() {
		findLocalGoVulnDB = orig
		SetFeedMaxAge(feeds.DefaultMaxAge)
	})
}

var fetched = time.Date(2026, 9, 23, 8, 0, 0, 0, time.UTC)

func localCopy(time.Time, time.Duration) (feeds.LocalGoVulnDB, error) {
	return feeds.LocalGoVulnDB{Path: "/cache/govulndb", Record: feeds.Record{FetchedAt: fetched}}, nil
}

func refusedCopy(time.Time, time.Duration) (feeds.LocalGoVulnDB, error) {
	return feeds.LocalGoVulnDB{}, errors.New("local Go vulnerability database: index/modules.json lists no modules")
}

func noCopy(time.Time, time.Duration) (feeds.LocalGoVulnDB, error) {
	return feeds.LocalGoVulnDB{}, feeds.ErrNoLocalGoVulnDB
}

func offline(t *testing.T) {
	t.Helper()
	netpolicy.SetOffline(true)
	t.Cleanup(func() { netpolicy.SetOffline(false) })
}

func goModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/m\n\ngo 1.21\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func dbArg(argv []string) string {
	if i := slices.Index(argv, "-db"); i >= 0 && i+1 < len(argv) {
		return argv[i+1]
	}
	return ""
}

func TestGovulncheckReadsACheckedLocalCopy(t *testing.T) {
	useGoVulnDB(t, localCopy)
	for _, argv := range govulncheckArgs(goModule(t), plugin.Config{}) {
		if got := dbArg(argv); got != "file:///cache/govulndb" {
			t.Errorf("argv = %v, want -db file:///cache/govulndb", argv)
		}
		// -db is a flag of the scan, so it must come before the package pattern.
		if slices.Index(argv, "-db") > slices.Index(argv, "./...") {
			t.Errorf("-db after the pattern: %v", argv)
		}
	}
	if got := resolveGovulnDB().describe(); got != "local copy, fetched 2026-09-23" {
		t.Errorf("describe = %q", got)
	}
	if err := govulncheckPreflight(context.Background()); err != nil {
		t.Errorf("a usable copy was refused: %v", err)
	}
}

// Offline makes no difference to a usable copy: it is what the operator put there.
func TestGovulncheckReadsTheLocalCopyOffline(t *testing.T) {
	offline(t)
	useGoVulnDB(t, localCopy)
	if err := govulncheckPreflight(context.Background()); err != nil {
		t.Fatalf("offline with a usable copy: %v", err)
	}
	if got := dbArg(govulncheckArgs(goModule(t), plugin.Config{})[0]); got == "" {
		t.Error("offline with a usable copy, and govulncheck was not pointed at it")
	}
}

// govulncheck reports "No vulnerabilities found" and exits 0 against an empty database, so a copy
// that fails its checks must never reach -db, online or off.
func TestGovulncheckNeverReadsARefusedCopy(t *testing.T) {
	useGoVulnDB(t, refusedCopy)
	for _, argv := range govulncheckArgs(goModule(t), plugin.Config{}) {
		if got := dbArg(argv); got != "" {
			t.Errorf("a refused copy was passed to govulncheck: %v", argv)
		}
	}
	// Online, the run queries vuln.go.dev and the report says why the copy was not used.
	if err := govulncheckPreflight(context.Background()); err != nil {
		t.Errorf("online, a refused copy should fall back to vuln.go.dev: %v", err)
	}
	if got := resolveGovulnDB().describe(); !strings.HasPrefix(got, "vuln.go.dev (local Go vulnerability database: ") ||
		!strings.Contains(got, "lists no modules") {
		t.Errorf("describe = %q, want vuln.go.dev with the reason the copy was refused", got)
	}
}

func TestGovulncheckRefusesToRunOfflineWithoutAUsableCopy(t *testing.T) {
	for name, find := range map[string]func(time.Time, time.Duration) (feeds.LocalGoVulnDB, error){
		"refused copy": refusedCopy,
		"no copy":      noCopy,
	} {
		t.Run(name, func(t *testing.T) {
			offline(t)
			useGoVulnDB(t, find)
			err := govulncheckPreflight(context.Background())
			if err == nil || !strings.Contains(err.Error(), "cannot run offline") {
				t.Fatalf("err = %v, want govulncheck refused offline", err)
			}

			// Through Scan, before any checkout: a control error, never a clean result.
			s := NewGovulncheck().(repoScanner)
			_, err = s.Scan(context.Background(), plugin.RepositoryTarget{URL: "https://example.com/r.git"}, nil)
			if err == nil || !strings.Contains(err.Error(), "cannot run offline") {
				t.Errorf("Scan err = %v, want the offline refusal", err)
			}
		})
	}
}

func TestGovulncheckWithNoCopyUsesTheDefaultDatabase(t *testing.T) {
	useGoVulnDB(t, noCopy)
	if got := dbArg(govulncheckArgs(goModule(t), plugin.Config{})[0]); got != "" {
		t.Errorf("-db %q with no local copy", got)
	}
	if got := resolveGovulnDB().describe(); got != "vuln.go.dev" {
		t.Errorf("describe = %q, want vuln.go.dev", got)
	}
}

// The limit the scan configures is the one the lookup is asked to apply.
func TestSetFeedMaxAgeReachesTheLookup(t *testing.T) {
	var asked time.Duration
	useGoVulnDB(t, func(_ time.Time, maxAge time.Duration) (feeds.LocalGoVulnDB, error) {
		asked = maxAge
		return noCopy(time.Time{}, 0)
	})
	SetFeedMaxAge(72 * time.Hour)
	resolveGovulnDB()
	if asked != 72*time.Hour {
		t.Errorf("lookup asked for %v, want 72h", asked)
	}
}

// The choice is made once per run, so every module and every component reads one database and
// the report makes one statement about it.
func TestGovulnDBIsResolvedOnce(t *testing.T) {
	calls := 0
	useGoVulnDB(t, func(now time.Time, maxAge time.Duration) (feeds.LocalGoVulnDB, error) {
		calls++
		return localCopy(now, maxAge)
	})
	for range 3 {
		resolveGovulnDB()
	}
	if calls != 1 {
		t.Errorf("resolved %d times, want once", calls)
	}
}

func TestParseGovulncheckNamesTheDatabase(t *testing.T) {
	useGoVulnDB(t, localCopy)
	out, err := os.ReadFile("testdata/govulncheck-reachable.json")
	if err != nil {
		t.Fatal(err)
	}
	report, err := parseGovulncheck(out, "", plugin.Config{})
	if err != nil {
		t.Fatal(err)
	}
	var got string
	for _, p := range report.Provenance {
		for _, f := range p.Fields {
			if f.Key == "database" {
				got = f.Value
			}
		}
	}
	if got != "local copy, fetched 2026-09-23" {
		t.Errorf("database = %q, want the local copy and its fetch date", got)
	}
}

// Refreshing the local copy must invalidate cached results, so the cache version is read from
// the copy govulncheck will use.
func TestGovulncheckCacheVersionReadsTheLocalCopy(t *testing.T) {
	useGoVulnDB(t, localCopy)
	url := "file:///cache/govulndb"
	var argv []string
	localVersionMu.Lock()
	localVersionProbes[url] = &toolVersionProbe{
		argv: []string{"govulncheck", "-db", url, "-version"}, extract: govulncheckVersion,
		run: func(_ context.Context, a []string) ([]byte, error) {
			argv = a
			return []byte("Scanner: govulncheck@v1.7.0\nDB updated: 2026-09-20 00:00:00 +0000 UTC\n"), nil
		},
	}
	localVersionMu.Unlock()
	t.Cleanup(func() {
		localVersionMu.Lock()
		delete(localVersionProbes, url)
		localVersionMu.Unlock()
	})

	if got, want := govulncheckCacheVersion(context.Background()), "v1.7.0;db@2026-09-20 00:00:00"; got != want {
		t.Errorf("cache version = %q, want %q", got, want)
	}
	if dbArg(argv) != url {
		t.Errorf("version probe argv = %v, want it pointed at the local copy", argv)
	}
	// A second lookup reuses the probe rather than building another.
	if p := localGovulncheckVersion(url); p != localVersionProbes[url] {
		t.Error("the probe for one database was built twice")
	}
	if p := localGovulncheckVersion("file:///elsewhere"); p == localVersionProbes[url] || dbArg(p.argv) != "file:///elsewhere" {
		t.Errorf("a second database shared the first one's probe: %v", p.argv)
	}
}
