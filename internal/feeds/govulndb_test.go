package feeds

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// goVulnDBFiles is the smallest database govulncheck accepts: the documented index files and one
// advisory.
var goVulnDBFiles = map[string]string{
	"index/db.json":        `{"modified":"2026-09-20T00:00:00Z"}`,
	"index/modules.json":   `[{"path":"golang.org/x/text","vulns":[{"id":"GO-2021-0113","modified":"2026-09-20T00:00:00Z","fixed":"0.3.7"}]}]`,
	"index/vulns.json":     `[{"id":"GO-2021-0113","modified":"2026-09-20T00:00:00Z","aliases":["CVE-2021-38561"]}]`,
	"ID/GO-2021-0113.json": `{"id":"GO-2021-0113"}`,
}

// goVulnZip builds a zip archive holding files, in the shape vuln.go.dev publishes.
func goVulnZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func with(files map[string]string, name, body string) map[string]string {
	out := map[string]string{}
	for k, v := range files {
		out[k] = v
	}
	if body == "" {
		delete(out, name)
	} else {
		out[name] = body
	}
	return out
}

func TestCheckGoVulnDB(t *testing.T) {
	cases := map[string]struct {
		files map[string]string
		want  string
	}{
		"sound":              {goVulnDBFiles, ""},
		"no db.json":         {with(goVulnDBFiles, "index/db.json", ""), "no index/db.json"},
		"db.json unreadable": {with(goVulnDBFiles, "index/db.json", "{"), "index/db.json cannot be read"},
		"no modified date":   {with(goVulnDBFiles, "index/db.json", "{}"), "index/db.json cannot be read"},
		"no modules.json":    {with(goVulnDBFiles, "index/modules.json", ""), "no index/modules.json"},
		"modules unreadable": {with(goVulnDBFiles, "index/modules.json", `{"a":1}`), "index/modules.json cannot be read"},
		// The case the check exists for: govulncheck reads an empty index as "no vulnerabilities".
		"no modules": {with(goVulnDBFiles, "index/modules.json", "[]"), "lists no modules"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			for f, body := range tc.files {
				path := filepath.Join(dir, filepath.FromSlash(f))
				if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			err := CheckGoVulnDB(dir)
			switch {
			case tc.want == "" && err != nil:
				t.Errorf("a sound database was refused: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Errorf("err = %v, want one naming %q", err, tc.want)
			}
		})
	}
}

// serveZip points the Go database source at a stub returning body.
func serveZip(t *testing.T, body []byte) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	t.Cleanup(srv.Close)
	orig := sources
	t.Cleanup(func() { sources = orig })
	sources = map[Name]source{GoVulnDB: {url: srv.URL, file: "govulndb", zipped: true, check: CheckGoVulnDB, describe: "test Go vulnerability database"}}
}

func TestAFailedFetchKeepsTheGoodCopy(t *testing.T) {
	dir := t.TempDir()
	serveZip(t, goVulnZip(t, goVulnDBFiles))
	if _, err := Fetch(context.Background(), dir, GoVulnDB, nil); err != nil {
		t.Fatal(err)
	}

	// Upstream now serves an empty index. Unpacked in place, it would replace a database that
	// answers with one that reports every module clean.
	serveZip(t, goVulnZip(t, with(goVulnDBFiles, "index/modules.json", "[]")))
	_, err := Fetch(context.Background(), dir, GoVulnDB, nil)
	if err == nil || !strings.Contains(err.Error(), "lists no modules") {
		t.Fatalf("an empty database was accepted: %v", err)
	}
	if err := CheckGoVulnDB(Path(dir, GoVulnDB)); err != nil {
		t.Errorf("the previous copy was not kept: %v", err)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(dir, ".draugr-feed-*")); len(leftovers) != 0 {
		t.Errorf("a refused archive left its temporary directory behind: %v", leftovers)
	}

	// A good archive replaces the copy and leaves nothing beside it.
	serveZip(t, goVulnZip(t, goVulnDBFiles))
	if _, err := Fetch(context.Background(), dir, GoVulnDB, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(Path(dir, GoVulnDB) + ".old"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the replaced copy was left behind: %v", err)
	}
}

func TestExtractRefusesBadArchives(t *testing.T) {
	cases := map[string]struct {
		data []byte
		want string
	}{
		"escapes the archive": {goVulnZip(t, map[string]string{"../evil.json": "{}"}), "outside the archive"},
		"absolute path":       {goVulnZip(t, map[string]string{"/etc/evil.json": "{}"}), "outside the archive"},
		"not a zip":           {[]byte("<html>maintenance</html>"), "zip"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			err := extractAtomic(dir, filepath.Join(dir, "govulndb"), tc.data, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want one naming %q", err, tc.want)
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "evil.json")); err == nil {
				t.Error("an entry was written outside the cache")
			}
		})
	}
}

func TestExtractCreatesDirectoryEntries(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if _, err := zw.Create("index/"); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := extractAtomic(dir, filepath.Join(dir, "db"), buf.Bytes(), nil); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(dir, "db", "index")); err != nil || !fi.IsDir() {
		t.Errorf("directory entry not created: %v", err)
	}
}

func TestFindGoVulnDB(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()

	if _, err := FindGoVulnDB(dir, now, DefaultMaxAge); !errors.Is(err, ErrNoLocalGoVulnDB) {
		t.Errorf("nothing fetched: err = %v, want ErrNoLocalGoVulnDB", err)
	}

	serveZip(t, goVulnZip(t, goVulnDBFiles))
	if _, err := Fetch(context.Background(), dir, GoVulnDB, nil); err != nil {
		t.Fatal(err)
	}
	got, err := FindGoVulnDB(dir, now, DefaultMaxAge)
	if err != nil {
		t.Fatalf("a fresh, sound copy was refused: %v", err)
	}
	if got.Path != Path(dir, GoVulnDB) || got.Record.FetchedAt.IsZero() {
		t.Errorf("incomplete result %+v", got)
	}

	// Age is judged from the fetch, so a copy two days old is refused under the default limit
	// and accepted with no limit.
	later := now.Add(48 * time.Hour)
	if _, err := FindGoVulnDB(dir, later, DefaultMaxAge); err == nil || !strings.Contains(err.Error(), "older than 24h") {
		t.Errorf("a stale copy was not refused by age: %v", err)
	}
	if _, err := FindGoVulnDB(dir, later, 0); err != nil {
		t.Errorf("no limit should accept any age: %v", err)
	}

	// A copy damaged after it was fetched fails the structural check.
	if err := os.WriteFile(filepath.Join(Path(dir, GoVulnDB), "index", "modules.json"), []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := FindGoVulnDB(dir, now, DefaultMaxAge); err == nil || !strings.Contains(err.Error(), "lists no modules") {
		t.Errorf("an emptied copy was accepted: %v", err)
	}
}

func TestExtractRefusesAnArchiveThatExpandsPastTheCap(t *testing.T) {
	orig := maxFeedBytes
	maxFeedBytes = 64
	t.Cleanup(func() { maxFeedBytes = orig })

	data := goVulnZip(t, map[string]string{"ID/big.json": strings.Repeat("x", 1024)})
	dir := t.TempDir()
	err := extractAtomic(dir, filepath.Join(dir, "govulndb"), data, nil)
	if err == nil || !strings.Contains(err.Error(), "expands past") {
		t.Errorf("err = %v, want the archive refused for its expanded size", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "govulndb")); !errors.Is(err, os.ErrNotExist) {
		t.Error("a refused archive was installed")
	}
}

func TestExtractIntoAnUnwritableCache(t *testing.T) {
	// A file where the cache directory should be, so the temporary directory cannot be created.
	blocked := filepath.Join(t.TempDir(), "feeds")
	if err := os.WriteFile(blocked, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := extractAtomic(blocked, filepath.Join(blocked, "govulndb"), goVulnZip(t, goVulnDBFiles), nil); err == nil {
		t.Error("extracting into a cache that is not a directory succeeded")
	}
}

func TestShortDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{
		24 * time.Hour:   "24h",
		90 * time.Minute: "1h30m",
		45 * time.Second: "45s",
	} {
		if got := shortDuration(d); got != want {
			t.Errorf("shortDuration(%v) = %q, want %q", d, got, want)
		}
	}
}
