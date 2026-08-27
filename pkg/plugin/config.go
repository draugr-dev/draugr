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

// EntryID reads the identifier out of one entry in a policy list, which may be written either
// way: the identifier alone, or a mapping carrying it together with the reason somebody had.
//
//	deny: [AGPL-3.0-only]
//
//	deny:
//	  - id: AGPL-3.0-only
//	    reason: >-
//	      We ship binaries to customers, and a network-copyleft dependency
//	      would put obligations on them that nobody has agreed to.
//
// The reason is not returned, because nothing here judges by it: what a scanner needs is the
// identifier, and the argument travels in the descriptor to whoever reads the policy later.
//
// The second result is false for anything that is neither — which a descriptor cannot produce,
// since the scanner's schema rejects it first. Reporting it rather than skipping it keeps that
// true: a list quietly shortened by one entry is a policy weakened with nothing to show for it.
func EntryID(entry any) (string, bool) {
	switch v := entry.(type) {
	case string:
		return v, v != ""
	case map[string]any:
		id, ok := v["id"].(string)
		return id, ok && id != ""
	}
	return "", false
}
