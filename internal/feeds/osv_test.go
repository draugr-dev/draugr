package feeds

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// osvZip builds an OSV.dev-shaped archive, one JSON file per record.
func osvZip(t *testing.T, records map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range records {
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

// Records shaped as OSV.dev's crates.io archive held them on 2026-11-25: RustSec's state their
// license on the record, GitHub's do not, and malicious-package reports carry a MAL- id.
var crateRecords = map[string]string{
	"RUSTSEC-2016-0001.json": `{"id":"RUSTSEC-2016-0001","aliases":["CVE-2016-10931","GHSA-34p9-f4q3-c4r7"],"database_specific":{"license":"CC0-1.0"}}`,
	"GHSA-34p9-f4q3-c4r7.json": `{"id":"GHSA-34p9-f4q3-c4r7","aliases":["CVE-2016-10931","RUSTSEC-2016-0001"],` +
		`"database_specific":{"github_reviewed":true}}`,
	"MAL-2025-1.json": `{"id":"MAL-2025-1","aliases":[]}`,
}

// serveOSV points every OSV feed at a stub returning body.
func serveOSV(t *testing.T, body []byte) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	t.Cleanup(srv.Close)
	orig := sources
	t.Cleanup(func() { sources = orig })
	sources = map[Name]source{}
	for k, v := range orig {
		if v.index != nil {
			v.url = srv.URL
		}
		sources[k] = v
	}
}

// A fetch keeps each record's id, aliases and stated license, drops malicious-package reports,
// and leaves no archive behind.
func TestFetchIndexesAnOSVArchive(t *testing.T) {
	dir := t.TempDir()
	serveOSV(t, osvZip(t, crateRecords))
	rec, err := Fetch(context.Background(), dir, OSVCrates, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ReadOSVIndex(Path(dir, OSVCrates))
	if err != nil {
		t.Fatal(err)
	}
	want := []OSVRecord{
		{ID: "GHSA-34p9-f4q3-c4r7", Aliases: []string{"CVE-2016-10931", "RUSTSEC-2016-0001"}},
		{ID: "RUSTSEC-2016-0001", Aliases: []string{"CVE-2016-10931", "GHSA-34p9-f4q3-c4r7"}, License: "CC0-1.0"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("index = %+v, want %+v", got, want)
	}
	if rec.Bytes == 0 || rec.SHA256 == "" || Load(dir)[OSVCrates].SHA256 != rec.SHA256 {
		t.Errorf("record = %+v, manifest = %+v", rec, Load(dir)[OSVCrates])
	}
	if leftovers, _ := filepath.Glob(filepath.Join(dir, ".draugr-feed-*")); len(leftovers) != 0 {
		t.Errorf("the archive was left behind: %v", leftovers)
	}
}

// An archive holding nothing but malicious-package reports, or nothing at all, is refused, and
// the copy already cached stays.
func TestAnEmptyOSVArchiveKeepsTheCachedIndex(t *testing.T) {
	dir := t.TempDir()
	serveOSV(t, osvZip(t, crateRecords))
	if _, err := Fetch(context.Background(), dir, OSVCrates, nil); err != nil {
		t.Fatal(err)
	}
	serveOSV(t, osvZip(t, map[string]string{"MAL-2025-1.json": `{"id":"MAL-2025-1"}`}))
	if _, err := Fetch(context.Background(), dir, OSVCrates, nil); err == nil || !strings.Contains(err.Error(), "no advisory records") {
		t.Fatalf("err = %v, want the empty archive refused", err)
	}
	if got, err := ReadOSVIndex(Path(dir, OSVCrates)); err != nil || len(got) != 2 {
		t.Errorf("the cached index was replaced: %v, %v", got, err)
	}
}

func TestFetchRefusesABadOSVArchive(t *testing.T) {
	for name, c := range map[string]struct {
		body []byte
		want string
		cap  int64
	}{
		"not a zip":     {[]byte("not a zip"), "index", 0},
		"bad record":    {osvZip(t, map[string]string{"GHSA-x.json": "{"}), "GHSA-x.json", 0},
		"over the cap":  {osvZip(t, crateRecords), "larger than", 64},
		"huge record":   {osvZip(t, map[string]string{"GHSA-y.json": `{"id":"GHSA-y","summary":"` + strings.Repeat("x", 128) + `"}`}), "larger than any advisory", -1},
		"404 upstream:": {nil, "unexpected status", 0},
	} {
		t.Run(name, func(t *testing.T) {
			if c.body == nil {
				srv := httptest.NewServer(http.NotFoundHandler())
				t.Cleanup(srv.Close)
				orig := sources
				t.Cleanup(func() { sources = orig })
				s := orig[OSVCrates]
				s.url = srv.URL
				sources = map[Name]source{OSVCrates: s}
			} else {
				serveOSV(t, c.body)
			}
			switch {
			case c.cap > 0:
				orig := maxArchiveBytes
				maxArchiveBytes = c.cap
				t.Cleanup(func() { maxArchiveBytes = orig })
			case c.cap < 0:
				orig := maxRecordBytes
				maxRecordBytes = 64
				t.Cleanup(func() { maxRecordBytes = orig })
			}
			_, err := Fetch(context.Background(), t.TempDir(), OSVCrates, nil)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want it to mention %q", err, c.want)
			}
		})
	}
}

func TestReadOSVIndexRefusesWhatCannotAnswer(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{"empty.json": "[]", "bad.json": "{"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadOSVIndex(filepath.Join(dir, name)); err == nil {
			t.Errorf("%s was read as an index", name)
		}
	}
	if _, err := ReadOSVIndex(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("a missing index was read")
	}
}

// Each ecosystem the descriptor can name has a feed, fetched from OSV.dev's bucket.
func TestEveryAdvisoryEcosystemHasAFeed(t *testing.T) {
	if len(Ecosystems) != len(AdvisoryNames()) {
		t.Fatalf("Ecosystems %v and AdvisoryNames %v disagree", Ecosystems, AdvisoryNames())
	}
	for eco, n := range Ecosystems {
		if !strings.HasPrefix(URL(n), osvBucket) || !strings.HasSuffix(URL(n), "/all.zip") || Describe(n) == "" {
			t.Errorf("%s: feed %s has url %q, description %q", eco, n, URL(n), Describe(n))
		}
	}
}
