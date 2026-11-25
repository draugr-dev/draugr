package feeds

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

// The OSV.dev advisory feeds, one per ecosystem. Each is read only to find the CVE of a finding its
// scanner named by another advisory id, so KEV and EPSS can match it, and only where a descriptor
// asks for that ecosystem in config.exploitability.advisories.
const (
	OSVNpm    Name = "osv-npm"
	OSVPyPI   Name = "osv-pypi"
	OSVCrates Name = "osv-crates.io"
	OSVGo     Name = "osv-go"
)

// AdvisoryNames lists the OSV.dev advisory feeds, in the order commands present them. They are kept
// apart from Names because nothing reads them unless a descriptor opts in, and an archive can weigh
// hundreds of megabytes.
func AdvisoryNames() []Name { return []Name{OSVNpm, OSVPyPI, OSVCrates, OSVGo} }

// Ecosystems maps the value config.exploitability.advisories takes to the feed it reads.
var Ecosystems = map[string]Name{"npm": OSVNpm, "pypi": OSVPyPI, "crates.io": OSVCrates, "go": OSVGo}

// maxArchiveBytes caps an OSV.dev archive's download. npm's measured 211 MB on 2026-11-17, and the
// archive is read from disk entry by entry rather than held in memory, so the cap is a bound on
// disk and time, set well above that.
var maxArchiveBytes int64 = 1 << 30 // a var so tests can lower it

// maxRecordBytes caps one record inside an archive. A record is a few kilobytes of JSON.
var maxRecordBytes int64 = 4 << 20

// osvBucket is where OSV.dev publishes each ecosystem's records as one archive.
const osvBucket = "https://storage.googleapis.com/osv-vulnerabilities/"

func init() {
	for _, f := range []struct {
		name      Name
		directory string
		describe  string
	}{
		{OSVNpm, "npm", "OSV.dev advisories for npm"},
		{OSVPyPI, "PyPI", "OSV.dev advisories for PyPI"},
		{OSVCrates, "crates.io", "OSV.dev advisories for crates.io"},
		{OSVGo, "Go", "OSV.dev advisories for Go"},
	} {
		sources[f.name] = source{
			url:        osvBucket + f.directory + "/all.zip",
			file:       string(f.name) + ".json",
			index:      IndexOSVArchive,
			describe:   f.describe,
			publisher:  "OSV.dev",
			licenseURL: "https://google.github.io/osv.dev/data/",
		}
	}
}

// OSVRecord is one OSV.dev record as the advisory index keeps it: its id, the ids it lists as the
// same vulnerability elsewhere, and the license its source states on the record, where it states
// one.
type OSVRecord struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases,omitempty"`
	License string   `json:"license,omitempty"`
}

// IndexOSVArchive reads an OSV.dev ecosystem archive at zipPath into the index the cache keeps:
// every record's id, aliases and stated license, sorted by id.
//
// Records of the OpenSSF Malicious Packages project (`MAL-…`) are left out. They describe a package
// published to do harm, not a flaw with a CVE, and Draugr reads them through its own malicious
// package check. An archive with no record left is an error rather than an empty index, because a
// lookup against no records finds no CVE for every finding and would read as though none had one.
func IndexOSVArchive(zipPath string) ([]byte, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = zr.Close() }()
	var out []OSVRecord
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || path.Ext(f.Name) != ".json" || strings.HasPrefix(path.Base(f.Name), "MAL-") {
			continue
		}
		rec, err := readOSVRecord(f)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.Name, err)
		}
		if rec.ID == "" || strings.HasPrefix(rec.ID, "MAL-") {
			continue
		}
		out = append(out, rec)
	}
	if len(out) == 0 {
		return nil, errors.New("the archive holds no advisory records")
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return json.Marshal(out)
}

// readOSVRecord decodes the part of one archive entry the index keeps.
func readOSVRecord(f *zip.File) (OSVRecord, error) {
	rc, err := f.Open()
	if err != nil {
		return OSVRecord{}, err
	}
	defer func() { _ = rc.Close() }()
	var raw struct {
		ID               string   `json:"id"`
		Aliases          []string `json:"aliases"`
		DatabaseSpecific struct {
			License string `json:"license"`
		} `json:"database_specific"`
	}
	data, err := io.ReadAll(io.LimitReader(rc, maxRecordBytes+1))
	if err != nil {
		return OSVRecord{}, err
	}
	if int64(len(data)) > maxRecordBytes {
		return OSVRecord{}, errors.New("the record is larger than any advisory should be")
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return OSVRecord{}, err
	}
	return OSVRecord{ID: raw.ID, Aliases: raw.Aliases, License: raw.DatabaseSpecific.License}, nil
}

// ReadOSVIndex reads the advisory index a fetch wrote at path. A missing, unreadable or empty index
// is an error, for the reason IndexOSVArchive refuses an empty archive.
func ReadOSVIndex(path string) ([]OSVRecord, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- a path under the feed cache
	if err != nil {
		return nil, errors.New("no advisory index")
	}
	var out []OSVRecord
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, errors.New("the advisory index cannot be read")
	}
	if len(out) == 0 {
		return nil, errors.New("the advisory index lists no records")
	}
	return out, nil
}

// fetchIndexed downloads an archive to a temporary file beside the cache, indexes it with
// src.index, and writes the index in place of the archive. The record describes the index on disk,
// as every other feed's describes the bytes on disk.
func fetchIndexed(ctx context.Context, client *http.Client, dir string, n Name, src source) (Record, error) {
	tmp, err := os.CreateTemp(dir, ".draugr-feed-*.zip")
	if err != nil {
		return Record{}, err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	err = download(ctx, client, src.url, tmp, maxArchiveBytes)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return Record{}, fmt.Errorf("fetch %s: %w", src.describe, err)
	}
	index, err := src.index(name)
	if err != nil {
		return Record{}, fmt.Errorf("index %s: %w", src.describe, err)
	}
	dest := Path(dir, n)
	if err := writeAtomic(dest, index); err != nil {
		return Record{}, fmt.Errorf("write %s: %w", dest, err)
	}
	sum := sha256.Sum256(index)
	rec := Record{URL: src.url, FetchedAt: time.Now().UTC(), SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(index))}
	if err := record(dir, n, rec); err != nil {
		return rec, fmt.Errorf("record the fetch: %w", err)
	}
	return rec, nil
}

// download copies a URL's body into w, refusing anything but 200 and a body larger than limit.
func download(ctx context.Context, client *http.Client, url string, w io.Writer, limit int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %s", resp.Status)
	}
	n, err := io.Copy(w, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return err
	}
	if n > limit {
		return fmt.Errorf("the download is larger than %d MiB", limit>>20)
	}
	return nil
}
