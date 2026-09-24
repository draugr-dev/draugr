package feeds

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// extractAtomic unpacks a zip archive into dest, replacing what was there only once the new copy
// is complete and has passed check.
//
// Extracted beside dest and renamed into place, so a scan never reads a half-unpacked database. An
// entry naming a path outside the archive is refused rather than skipped: an archive that tries it
// is not the one that was published.
func extractAtomic(dir, dest string, data []byte, check func(string) error) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(dir, ".draugr-feed-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }() // no-op once the rename has succeeded

	var total int64
	for _, f := range zr.File {
		name := filepath.Clean(filepath.FromSlash(f.Name))
		if filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
			return fmt.Errorf("archive entry %q is outside the archive", f.Name)
		}
		target := filepath.Join(tmp, name)
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o750); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			return err
		}
		n, err := extractFile(f, target, maxFeedBytes-total)
		if err != nil {
			return err
		}
		if total += n; total >= maxFeedBytes {
			return fmt.Errorf("archive expands past %d bytes", maxFeedBytes)
		}
	}
	if check != nil {
		if err := check(tmp); err != nil {
			return err
		}
	}

	old := dest + ".old"
	_ = os.RemoveAll(old)
	if _, err := os.Stat(dest); err == nil {
		if err := os.Rename(dest, old); err != nil {
			return err
		}
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Rename(old, dest) // put the previous copy back rather than leave nothing
		return err
	}
	return os.RemoveAll(old)
}

// extractFile writes one archive entry, reading at most limit bytes of it.
func extractFile(f *zip.File, target string, limit int64) (int64, error) {
	rc, err := f.Open()
	if err != nil {
		return 0, err
	}
	defer func() { _ = rc.Close() }()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304 -- target is inside a temp dir this function created, checked above
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(out, io.LimitReader(rc, limit))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return n, err
}

// CheckGoVulnDB reports whether path holds a Go vulnerability database govulncheck can answer
// from: an index that parses, and at least one module in it.
//
// The shape is the documented offline form (`index/db.json`, `index/modules.json`, `ID/*.json`).
// Both checks exist because govulncheck reports "No vulnerabilities found" against a database that
// is empty or unreadable, and a scan must never read that as a clean result.
func CheckGoVulnDB(path string) error {
	raw, err := os.ReadFile(filepath.Join(path, "index", "db.json")) // #nosec G304 -- a path under the feed cache
	if err != nil {
		return errors.New("no index/db.json")
	}
	var meta struct {
		Modified time.Time `json:"modified"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil || meta.Modified.IsZero() {
		return errors.New("index/db.json cannot be read")
	}
	raw, err = os.ReadFile(filepath.Join(path, "index", "modules.json")) // #nosec G304 -- a path under the feed cache
	if err != nil {
		return errors.New("no index/modules.json")
	}
	var modules []json.RawMessage
	if err := json.Unmarshal(raw, &modules); err != nil {
		return errors.New("index/modules.json cannot be read")
	}
	if len(modules) == 0 {
		return errors.New("index/modules.json lists no modules")
	}
	return nil
}

// ErrNoLocalGoVulnDB means no local copy of the Go vulnerability database has been fetched.
var ErrNoLocalGoVulnDB = errors.New("no local Go vulnerability database")

// LocalGoVulnDB is a local copy of the Go vulnerability database that passed its checks.
type LocalGoVulnDB struct {
	Path   string
	Record Record
}

// FindGoVulnDB returns the cached Go vulnerability database if it is usable as of now: fetched,
// no older than maxAge, and structurally sound. The error names the check that failed.
//
// Age is measured from when Draugr fetched the copy, not from the database's own modified date,
// which moves only when an advisory changes and so can lag a copy fetched this morning by days.
func FindGoVulnDB(dir string, now time.Time, maxAge time.Duration) (LocalGoVulnDB, error) {
	rec, ok := Load(dir)[GoVulnDB]
	if !ok {
		return LocalGoVulnDB{}, ErrNoLocalGoVulnDB
	}
	path := Path(dir, GoVulnDB)
	if rec.Stale(now, maxAge) {
		return LocalGoVulnDB{}, fmt.Errorf("local Go vulnerability database fetched %s, older than %s",
			rec.FetchedAt.UTC().Format("2006-01-02 15:04 UTC"), shortDuration(maxAge))
	}
	if err := CheckGoVulnDB(path); err != nil {
		return LocalGoVulnDB{}, fmt.Errorf("local Go vulnerability database: %w", err)
	}
	return LocalGoVulnDB{Path: path, Record: rec}, nil
}

// shortDuration renders a limit the way it is written in a descriptor: 24h, not 24h0m0s.
func shortDuration(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}
