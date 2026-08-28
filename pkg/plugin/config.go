package plugin

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Config is scanner/plugin configuration. It is validated against the plugin's declared
// JSON Schema (ScannerInfo.ConfigSchema) before use.
type Config map[string]any

// CacheKey uniquely identifies the inputs of a scan, so an unchanged target is never
// re-scanned. See ComputeCacheKey.
type CacheKey string

// ComputeCacheKey derives a stable cache key from the scan inputs: the scanner name and
// version, the target kind and identity, and the effective config. It is deterministic
// and independent of config map ordering.
func ComputeCacheKey(scanner, version string, t Target, cfg Config) CacheKey {
	parts := []string{scanner, version, string(t.Kind()), t.Identity()}

	keys := make([]string, 0, len(cfg))
	for k := range cfg {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts = append(parts, k+"="+fmt.Sprintf("%v", cfg[k]))
	}

	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return CacheKey(hex.EncodeToString(sum[:]))
}
