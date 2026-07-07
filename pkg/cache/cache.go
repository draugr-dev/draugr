// Package cache stores scan results keyed by content hash so unchanged targets are not
// re-scanned. Keys come from plugin.ComputeCacheKey (a hex SHA, safe as a filename).
package cache

import (
	"encoding/json"
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

func (l *Local) pathFor(key string) string {
	return filepath.Join(l.dir, key+".json")
}

// Get returns the cached report for key, missing on absence, unreadable data, or expiry.
func (l *Local) Get(key string) (sarif.Report, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	data, err := os.ReadFile(l.pathFor(key)) //nolint:gosec // key is a content-hash filename
	if err != nil {
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
	return os.WriteFile(l.pathFor(key), data, 0o600)
}
