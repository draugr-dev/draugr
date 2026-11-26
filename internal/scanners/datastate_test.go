package scanners

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

// Trimmed from `trivy version --format json`, Trivy 0.69.3.
const trivyVersionOut = `{"Version":"0.69.3","VulnerabilityDB":{"Version":2,"NextUpdate":"2026-10-11T18:59:50.889010572Z",` +
	`"UpdatedAt":"2026-10-10T18:59:50.889010923Z","DownloadedAt":"2026-10-11T00:02:00.356094704Z"},` +
	`"CheckBundle":{"Digest":"sha256:1583562f8b90ed2a071b99f0e5ffff6b57e4ceb6ca3e4796577b4e6a339eb74c",` +
	`"DownloadedAt":"2026-10-11T00:01:54.237757977Z"}}`

// From `grype db status -o json` for a database Grype refuses as too old; it exits 1 and still
// prints its status.
const grypeStaleOut = `{
 "schemaVersion": "v6.1.10",
 "built": "2026-10-04T08:11:47Z",
 "path": "%s",
 "valid": false,
 "error": "the vulnerability database was built 1 week ago (max allowed age is 5 days)"
}`

func answering(out string, err error) func(context.Context, []string) ([]byte, error) {
	return func(context.Context, []string) ([]byte, error) { return []byte(out), err }
}

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestTrivyReportsItsDatabaseAndChecksBundle(t *testing.T) {
	calls := 0
	r := &trivyDataReader{run: func(context.Context, []string) ([]byte, error) {
		calls++
		return []byte(trivyVersionOut), nil
	}}
	db := r.database(context.Background())
	want := plugin.DataState{Name: "vulnerability database", Version: "schema 2",
		Published: at("2026-10-10T18:59:50.889010923Z"), Downloaded: at("2026-10-11T00:02:00.356094704Z")}
	if len(db) != 1 || !db[0].Published.Equal(want.Published) || !db[0].Downloaded.Equal(want.Downloaded) ||
		db[0].Name != want.Name || db[0].Version != want.Version {
		t.Errorf("database = %+v, want %+v", db, want)
	}
	checks := r.checks(context.Background())
	if len(checks) != 1 || checks[0].Version != "1583562f8b90" || !checks[0].Published.IsZero() ||
		!checks[0].Downloaded.Equal(at("2026-10-11T00:01:54.237757977Z")) {
		t.Errorf("checks = %+v", checks)
	}
	if calls != 1 {
		t.Errorf("trivy was asked %d times, want once for both", calls)
	}
}

// A Trivy that cannot answer, or that has neither, reports nothing rather than an empty entry.
func TestTrivyWithNothingToSayReportsNothing(t *testing.T) {
	for name, r := range map[string]*trivyDataReader{
		"fails":        {run: answering("", errors.New("exit 1"))},
		"unreadable":   {run: answering("not json", nil)},
		"no data held": {run: answering(`{"Version":"0.69.3"}`, nil)},
	} {
		if got := r.database(context.Background()); got != nil {
			t.Errorf("%s: database = %+v", name, got)
		}
		if got := r.checks(context.Background()); got != nil {
			t.Errorf("%s: checks = %+v", name, got)
		}
	}
	r := &trivyDataReader{run: answering(`{"VulnerabilityDB":{"DownloadedAt":"2026-10-11T00:02:00Z"}}`, nil)}
	if got := r.database(context.Background()); len(got) != 1 || got[0].Version != "" {
		t.Errorf("a database with no schema = %+v, want one entry with no version", got)
	}
}

// A database Grype refuses is the case most worth reporting, and Grype says so by exiting non-zero
// with its status still printed.
func TestGrypeReportsADatabaseItRefuses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	fetched := time.Date(2026, 10, 4, 9, 0, 0, 0, time.UTC)
	if err := os.Chtimes(path, fetched, fetched); err != nil {
		t.Fatal(err)
	}
	r := &grypeDataReader{run: answering(fmt.Sprintf(grypeStaleOut, path), errors.New("exit status 1"))}
	got := r.database(context.Background())
	if len(got) != 1 {
		t.Fatalf("database = %+v", got)
	}
	g := got[0]
	if g.Version != "v6.1.10" || !g.Published.Equal(at("2026-10-04T08:11:47Z")) || !g.Downloaded.Equal(fetched) ||
		g.TooOld != "the vulnerability database was built 1 week ago (max allowed age is 5 days)" {
		t.Errorf("database = %+v", g)
	}

	valid := &grypeDataReader{run: answering(`{"schemaVersion":"v6.1.10","built":"2026-10-15T08:11:47Z","path":"/gone","valid":true}`, nil)}
	if got := valid.database(context.Background()); len(got) != 1 || got[0].TooOld != "" || !got[0].Downloaded.IsZero() {
		t.Errorf("a valid database at a path that is gone = %+v", got)
	}
	none := &grypeDataReader{run: answering(`{"valid":false,"error":"no database"}`, errors.New("exit 1"))}
	if got := none.database(context.Background()); got != nil {
		t.Errorf("no database = %+v", got)
	}
}

// Nuclei's template set is dated by the checksum file it rewrites on update, or by the directory
// where that file is absent.
func TestNucleiDatesItsTemplateSet(t *testing.T) {
	dir := t.TempDir()
	updated := time.Date(2026, 9, 25, 0, 12, 5, 0, time.UTC)
	if err := os.WriteFile(filepath.Join(dir, ".checksum"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Join(dir, ".checksum"), updated, updated); err != nil {
		t.Fatal(err)
	}
	// As Nuclei prints it, to stderr, with its log prefix.
	out := "[INF] Public nuclei-templates version: v10.4.9 (" + dir + ")\n"
	r := &nucleiDataReader{run: answering(out, nil)}
	got := r.templates(context.Background())
	if len(got) != 1 || got[0].Version != "v10.4.9" || !got[0].Downloaded.Equal(updated) {
		t.Errorf("templates = %+v", got)
	}

	if err := os.Remove(filepath.Join(dir, ".checksum")); err != nil {
		t.Fatal(err)
	}
	r = &nucleiDataReader{run: answering(out, nil)}
	if got := r.templates(context.Background()); len(got) != 1 || got[0].Downloaded.IsZero() {
		t.Errorf("templates with no checksum file = %+v, want the directory's time", got)
	}

	for name, r := range map[string]*nucleiDataReader{
		"fails":       {run: answering("", errors.New("exit 1"))},
		"no template": {run: answering("[INF] Public nuclei-templates version: (/nowhere)\n", nil)},
	} {
		if got := r.templates(context.Background()); got != nil {
			t.Errorf("%s: templates = %+v", name, got)
		}
	}
}

// retire.js keeps no version or build time, so its database is dated by the file the index names.
func TestRetireDatesItsAdvisoryDatabase(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if got := retireData(context.Background()); got != nil {
		t.Errorf("no cache = %+v", got)
	}
	cache := filepath.Join(home, ".draugr", "data", "retirejs")
	if err := os.MkdirAll(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	writeRetireCache(t, cache, "111.json")
	fetched := time.Date(2026, 10, 11, 15, 38, 29, 0, time.UTC)
	if err := os.Chtimes(filepath.Join(cache, "111.json"), fetched, fetched); err != nil {
		t.Fatal(err)
	}
	got := retireData(context.Background())
	if len(got) != 1 || got[0].Name != "advisory database" || !got[0].Downloaded.Equal(fetched) {
		t.Errorf("retireData = %+v", got)
	}
}

// A repository scanner with no reader wired reports nothing rather than an empty entry.
func TestARepoScannerWithNoReaderReportsNothing(t *testing.T) {
	if got := (repoScanner{}).DataState(context.Background()); got != nil {
		t.Errorf("DataState = %+v", got)
	}
	if modTime("") != (time.Time{}) || shortDigest("abc") != "abc" {
		t.Error("modTime or shortDigest mishandled an empty path or a short digest")
	}
}

// writeTUFRepo caches root metadata at the version given in a mirror's directory under cache, the
// layout cosign leaves, with the last refresh recorded beside it when refreshed is not zero.
func writeTUFRepo(t *testing.T, cache, dirName string, version int, refreshed time.Time) {
	t.Helper()
	repo := filepath.Join(cache, dirName)
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	root := fmt.Sprintf(`{"signed":{"_type":"root","version":%d,"expires":"2027-04-22T19:27:31Z"}}`, version)
	if err := os.WriteFile(filepath.Join(repo, "root.json"), []byte(root), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "timestamp.json"), []byte(`{"signed":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if refreshed.IsZero() {
		return
	}
	stamp := `{"lastTimestamp":"` + refreshed.Format(time.RFC3339Nano) + `"}`
	if err := os.WriteFile(repo+".json", []byte(stamp), 0o600); err != nil {
		t.Fatal(err)
	}
}

// cosign's trust root is dated by the refresh cosign records and named by its root version, from
// the cache under the home directory where nothing moves it.
func TestCosignDatesItsTrustRoot(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("TUF_ROOT", "")
	t.Setenv("TUF_MIRROR", "")
	if got := cosignTrustRoot(context.Background()); got != nil {
		t.Errorf("no cache = %+v", got)
	}
	refreshed := time.Date(2026, 11, 26, 12, 19, 26, 488079031, time.FixedZone("CST", -6*3600))
	writeTUFRepo(t, filepath.Join(home, ".sigstore", "root"), "tuf-repo-cdn.sigstore.dev", 16, refreshed)
	got := cosignTrustRoot(context.Background())
	if len(got) != 1 || got[0].Name != "Sigstore trust root" || got[0].Version != "root 16" ||
		!got[0].Downloaded.Equal(refreshed) || got[0].Downloaded.Location() != time.UTC {
		t.Errorf("cosignTrustRoot = %+v", got)
	}
}

// The cache follows TUF_ROOT, and the mirror follows TUF_MIRROR over the one `cosign initialize`
// recorded, so the copy reported is the one cosign reads.
func TestCosignFollowsTheCacheAndMirrorItIsGiven(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cache := t.TempDir()
	t.Setenv("TUF_ROOT", cache)
	t.Setenv("TUF_MIRROR", "")
	refreshed := time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC)
	if err := os.WriteFile(filepath.Join(cache, "remote.json"), []byte(`{"mirror":"https://Mirror.example:8443/tuf/root"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	writeTUFRepo(t, cache, "mirror.example-8443-tuf-root", 3, refreshed)
	writeTUFRepo(t, cache, "tuf-repo-cdn.sigstore.dev", 16, refreshed)
	if got := cosignTrustRoot(context.Background()); len(got) != 1 || got[0].Version != "root 3" {
		t.Errorf("remote.json's mirror = %+v", got)
	}
	t.Setenv("TUF_MIRROR", "https://tuf-repo-cdn.sigstore.dev")
	if got := cosignTrustRoot(context.Background()); len(got) != 1 || got[0].Version != "root 16" {
		t.Errorf("TUF_MIRROR = %+v", got)
	}
}

// Where cosign recorded no refresh, the timestamp metadata's modification time stands for one, and
// root metadata that cannot be read reports nothing rather than a version nobody read.
func TestCosignWithoutARecordedRefreshOrARootToRead(t *testing.T) {
	cache := t.TempDir()
	t.Setenv("TUF_ROOT", cache)
	t.Setenv("TUF_MIRROR", "")
	writeTUFRepo(t, cache, "tuf-repo-cdn.sigstore.dev", 16, time.Time{})
	fetched := time.Date(2026, 11, 1, 9, 30, 0, 0, time.UTC)
	repo := filepath.Join(cache, "tuf-repo-cdn.sigstore.dev")
	if err := os.Chtimes(filepath.Join(repo, "timestamp.json"), fetched, fetched); err != nil {
		t.Fatal(err)
	}
	if got := (&cosignVerifier{}).DataState(context.Background()); len(got) != 1 || !got[0].Downloaded.Equal(fetched) {
		t.Errorf("DataState = %+v", got)
	}
	for _, root := range []string{`not json`, `{"signed":{"version":0}}`} {
		if err := os.WriteFile(filepath.Join(repo, "root.json"), []byte(root), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := cosignTrustRoot(context.Background()); got != nil {
			t.Errorf("root.json %q = %+v", root, got)
		}
	}
	t.Setenv("TUF_ROOT", "")
	t.Setenv("HOME", "")
	if got := cosignTrustRoot(context.Background()); got != nil {
		t.Errorf("no home directory = %+v", got)
	}
}
