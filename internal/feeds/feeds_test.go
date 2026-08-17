package feeds

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// serve stands in for an upstream feed, returning body at the KEV and EPSS paths. The EPSS
// response is gzipped, as the real one is.
func serve(t *testing.T, kev string, epss string, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		if r.URL.Path == "/epss" {
			var buf bytes.Buffer
			zw := gzip.NewWriter(&buf)
			_, _ = zw.Write([]byte(epss))
			_ = zw.Close()
			_, _ = w.Write(buf.Bytes())
			return
		}
		_, _ = w.Write([]byte(kev))
	}))
	t.Cleanup(srv.Close)

	// Point the pinned sources at the stub for the duration of the test.
	orig := sources
	t.Cleanup(func() { sources = orig })
	sources = map[Name]source{
		KEV:  {url: srv.URL + "/kev", file: "kev.json", describe: "test KEV"},
		EPSS: {url: srv.URL + "/epss", file: "epss.csv", gzipped: true, describe: "test EPSS"},
	}
	return srv
}

const kevBody = `{"vulnerabilities":[{"cveID":"CVE-2021-44228"}]}`
const epssBody = "cve,epss,percentile\nCVE-2021-44228,0.97,0.99\n"

func TestFetchWritesAndRecords(t *testing.T) {
	serve(t, kevBody, epssBody, http.StatusOK)
	dir := t.TempDir()
	ctx := context.Background()

	for _, n := range Names() {
		rec, err := Fetch(ctx, dir, n, nil)
		if err != nil {
			t.Fatalf("fetch %s: %v", n, err)
		}
		if rec.SHA256 == "" || rec.Bytes == 0 || rec.FetchedAt.IsZero() {
			t.Errorf("%s: incomplete record %+v", n, rec)
		}
	}

	// EPSS arrives gzipped and must land decompressed: the parser reads a CSV, not a stream.
	got, err := os.ReadFile(Path(dir, EPSS))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != epssBody {
		t.Errorf("epss on disk = %q, want the decompressed csv", got)
	}

	m := Load(dir)
	if len(m) != 2 {
		t.Fatalf("manifest has %d entries, want 2", len(m))
	}
	if m[KEV].URL == "" {
		t.Error("the record does not say where it came from, which is the point of keeping it")
	}
}

func TestLoadForgetsDeletedFiles(t *testing.T) {
	serve(t, kevBody, epssBody, http.StatusOK)
	dir := t.TempDir()
	if _, err := Fetch(context.Background(), dir, KEV, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(Path(dir, KEV)); err != nil {
		t.Fatal(err)
	}
	// "Cached" and "on disk" must not be able to disagree — otherwise a scan is told to read
	// a file that is not there.
	if _, ok := Load(dir)[KEV]; ok {
		t.Error("manifest still claims a feed whose file was deleted")
	}
}

func TestFetchErrors(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	if _, err := Fetch(ctx, dir, Name("nvd"), nil); err == nil {
		t.Error("unknown feed accepted")
	}

	serve(t, kevBody, epssBody, http.StatusInternalServerError)
	if _, err := Fetch(ctx, dir, KEV, nil); err == nil {
		t.Error("a 500 was accepted")
	}
	// A failed fetch leaves nothing behind: a half-written catalog read as a complete one is
	// the failure this guards against.
	if _, err := os.Stat(Path(dir, KEV)); !os.IsNotExist(err) {
		t.Error("a failed fetch left a file behind")
	}
	if entries, _ := filepath.Glob(filepath.Join(dir, ".draugr-feed-*")); len(entries) > 0 {
		t.Errorf("temporary files left behind: %v", entries)
	}
}

func TestFetchRejectsBadGzip(t *testing.T) {
	// The EPSS handler is the gzipped one; serving plain text through it is what a captive
	// portal or an error page looks like.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>sign in to continue</html>"))
	}))
	defer srv.Close()
	orig := sources
	defer func() { sources = orig }()
	sources = map[Name]source{EPSS: {url: srv.URL, file: "epss.csv", gzipped: true, describe: "test"}}

	if _, err := Fetch(context.Background(), t.TempDir(), EPSS, nil); err == nil {
		t.Error("accepted a response that was not gzip")
	}
}

func TestStaleAndAge(t *testing.T) {
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	rec := Record{FetchedAt: now.Add(-30 * time.Hour)}

	if got := rec.Age(now); got != 30*time.Hour {
		t.Errorf("age = %v, want 30h", got)
	}
	if !rec.Stale(now, DefaultMaxAge) {
		t.Error("30 hours is not stale against a 24-hour bar")
	}
	if rec.Stale(now, 0) {
		t.Error("a maxAge of zero means the caller does not care; nothing is stale")
	}
	if (Record{FetchedAt: now.Add(-time.Hour)}).Stale(now, DefaultMaxAge) {
		t.Error("an hour old is not stale")
	}
}

func TestDescribeAndURL(t *testing.T) {
	for _, n := range Names() {
		if Describe(n) == "" || URL(n) == "" {
			t.Errorf("%s has no description or url", n)
		}
	}
	if URL(Name("nvd")) != "" {
		t.Error("an unknown feed reported a url")
	}
}

func TestDir(t *testing.T) {
	t.Setenv("HOME", "/tmp/draugr-feeds-home-test")
	dir, err := Dir()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join("/tmp/draugr-feeds-home-test", ".draugr", "feeds"); dir != want {
		t.Errorf("Dir() = %q, want %q", dir, want)
	}
}

func TestFetchIntoAnUnwritableCache(t *testing.T) {
	serve(t, kevBody, epssBody, http.StatusOK)
	// A file where the cache directory should be: MkdirAll fails, and the error has to name
	// the cache rather than surfacing as a bare syscall error.
	parent := t.TempDir()
	blocked := filepath.Join(parent, "feeds")
	if err := os.WriteFile(blocked, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Fetch(context.Background(), blocked, KEV, nil)
	if err == nil {
		t.Fatal("fetched into a path that is a file")
	}
	if !strings.Contains(err.Error(), "feed cache") {
		t.Errorf("error does not name the cache: %v", err)
	}
}

func TestFetchCanceled(t *testing.T) {
	serve(t, kevBody, epssBody, http.StatusOK)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Fetch(ctx, t.TempDir(), KEV, nil); err == nil {
		t.Error("a canceled context still fetched")
	}
}

func TestWriteAtomicFailsCleanly(t *testing.T) {
	// A destination directory that does not exist: CreateTemp fails, and nothing is written.
	err := writeAtomic(filepath.Join(t.TempDir(), "nope", "kev.json"), []byte("x"))
	if err == nil {
		t.Error("wrote into a directory that does not exist")
	}
}

func TestRecordSurvivesACorruptManifest(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, manifestName), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A corrupt manifest must not wedge the cache: it is a record of what we did, not a lock.
	if err := record(dir, KEV, Record{URL: "u", SHA256: "s", Bytes: 1}); err != nil {
		t.Fatalf("record over a corrupt manifest: %v", err)
	}
	if err := os.WriteFile(Path(dir, KEV), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := Load(dir)[KEV]; !ok {
		t.Error("the rewritten manifest does not contain the entry")
	}
}

func TestWriteAtomicRenameFailure(t *testing.T) {
	// The destination exists and is a directory: the rename fails, and the temporary file must
	// not be left behind for someone to find later and wonder about.
	dir := t.TempDir()
	dest := filepath.Join(dir, "kev.json")
	if err := os.Mkdir(dest, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(dest, []byte("x")); err == nil {
		t.Error("renamed over a directory")
	}
	left, _ := filepath.Glob(filepath.Join(dir, ".draugr-feed-*"))
	if len(left) > 0 {
		t.Errorf("temporary files left behind: %v", left)
	}
}

func TestFetchReportsAnUnwritableManifest(t *testing.T) {
	serve(t, kevBody, epssBody, http.StatusOK)
	dir := t.TempDir()
	// A directory where the manifest belongs. The data lands, and the failure to record it is
	// still reported — a cache that cannot say when it was filled is not a cache we can trust
	// a staleness decision to.
	if err := os.Mkdir(filepath.Join(dir, manifestName), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := Fetch(context.Background(), dir, KEV, nil); err == nil {
		t.Error("an unrecordable fetch was reported as a success")
	}
	if _, err := os.Stat(Path(dir, KEV)); err != nil {
		t.Errorf("the data itself should still have landed: %v", err)
	}
}
