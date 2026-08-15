// Package cache stores scan results keyed by content hash so unchanged targets are not
// re-scanned. Keys come from plugin.ComputeCacheKey (a hex SHA, safe as a filename).
package cache

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// Cache stores and retrieves scan reports by key.
type Cache interface {
	// Get returns the cached report for key, or ok=false on miss/expiry.
	Get(key string) (sarif.Report, bool)
	// Put stores report under key.
	Put(key string, report sarif.Report) error
}

// entry is a stored record with its creation time (for TTL).
type entry struct {
	Report   sarif.Report `json:"report"`
	StoredAt time.Time    `json:"storedAt"`
}

// Noop is a cache that stores nothing and always misses.
type Noop struct{}

// Get always misses.
func (Noop) Get(string) (sarif.Report, bool) { return sarif.Report{}, false }

// Put discards the report.
func (Noop) Put(string, sarif.Report) error { return nil }

// Memory is a process-lifetime in-memory cache (no TTL). Safe for concurrent use.
type Memory struct {
	mu sync.RWMutex
	m  map[string]sarif.Report
}

// NewMemory returns an empty in-memory cache.
func NewMemory() *Memory { return &Memory{m: make(map[string]sarif.Report)} }

// Get returns the cached report for key.
func (c *Memory) Get(key string) (sarif.Report, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	r, ok := c.m[key]
	return r, ok
}

// Put stores report under key.
func (c *Memory) Put(key string, report sarif.Report) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[key] = report
	return nil
}

// Local is a filesystem-backed cache with optional TTL expiry. Safe for concurrent use.
type Local struct {
	dir string
	ttl time.Duration
	now func() time.Time
	mu  sync.RWMutex
}

// NewLocal returns a cache storing entries under dir. A ttl of 0 disables expiry.
func NewLocal(dir string, ttl time.Duration) *Local {
	return &Local{dir: dir, ttl: ttl, now: time.Now}
}

// ReadOnly returns a view of c that serves entries and stores none.
//
// For a run whose results should not be trusted by the next one — a pull request from a fork
// being the case that matters, where the code deciding what the scan sees is not the code the
// cache is meant to describe. Reading stays useful: the entries already there were written by
// runs that were trusted.
//
// A wrapper rather than a flag on Local so the guarantee is structural. A boolean checked inside
// Put is a boolean somebody can forget to check.
func ReadOnly(c Cache) Cache { return readOnly{c} }

type readOnly struct{ Cache }

// Put discards the report. Silently: a read-only cache is a deliberate configuration, not an
// error, and a scan that failed because it could not write a cache would be absurd.
func (readOnly) Put(string, sarif.Report) error { return nil }

// entrySuffix is the extension a cache entry is written with. It names what the bytes are: a
// gzipped JSON envelope.
const entrySuffix = ".json.gz"

// legacySuffix is what entries were called before they were compressed. Nothing reads these —
// the name was accurate when it was chosen and stopped being so when compression landed — but
// Put removes the one it is replacing, because the cache evicts nothing on its own and a file
// that is never read and never removed is a leak rather than a leftover.
const legacySuffix = ".json"

func (l *Local) pathFor(key string) string {
	return filepath.Join(l.dir, key+entrySuffix)
}

func (l *Local) legacyPathFor(key string) string {
	return filepath.Join(l.dir, key+legacySuffix)
}

// Get returns the cached report for key, missing on absence, unreadable data, or expiry.
func (l *Local) Get(key string) (sarif.Report, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	data, err := os.ReadFile(l.pathFor(key)) //nolint:gosec // key is a content-hash filename
	if err != nil {
		return sarif.Report{}, false
	}
	if data, err = gunzip(data); err != nil {
		return sarif.Report{}, false
	}
	var e entry
	if err := json.Unmarshal(data, &e); err != nil {
		return sarif.Report{}, false
	}
	if l.ttl > 0 && l.now().Sub(e.StoredAt) > l.ttl {
		return sarif.Report{}, false
	}
	return e.Report, true
}

// Put stores report under key with the current timestamp.
func (l *Local) Put(key string, report sarif.Report) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if err := os.MkdirAll(l.dir, 0o750); err != nil {
		return err
	}
	data, err := json.Marshal(entry{Report: report, StoredAt: l.now()})
	if err != nil {
		return err
	}
	packed, err := gzipBytes(data)
	if err != nil {
		return err
	}
	if err := os.WriteFile(l.pathFor(key), packed, 0o600); err != nil {
		return err
	}
	// Best-effort: this key's entry under the pre-compression name is now superseded and would
	// otherwise sit there forever, since expiry only makes a read miss and nothing sweeps the
	// directory. Failing to remove it is not worth failing a scan over.
	_ = os.Remove(l.legacyPathFor(key))
	return nil
}

// gzipBytes compresses an entry for storage.
//
// A cached entry is a whole SARIF report, which is repetitive by construction — a measured entry
// went from 375 KB to 60 KB, and a project with a few hundred of them is the difference between
// a cache that is cheap to keep and one that costs more to restore than the scan it saves.
func gzipBytes(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// gunzip decompresses an entry. Anything that does not decompress is a miss, like every other
// unreadable entry — the file is one Draugr wrote, so the only way it is not gzip is damage.
func gunzip(data []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer func() { _ = zr.Close() }()
	return io.ReadAll(zr)
}
