package plugin

import "testing"

func TestComputeCacheKeyDeterministic(t *testing.T) {
	tgt := ImageTarget{Digest: "sha256:abc"}
	a := ComputeCacheKey("trivy", "0.50.0", tgt, Config{"severity": "high", "scanners": "vuln"})
	b := ComputeCacheKey("trivy", "0.50.0", tgt, Config{"scanners": "vuln", "severity": "high"})
	if a != b {
		t.Fatalf("cache key must be independent of config ordering:\n a=%s\n b=%s", a, b)
	}
	if a == "" {
		t.Fatal("cache key must not be empty")
	}
}

func TestComputeCacheKeySensitivity(t *testing.T) {
	tgt := ImageTarget{Digest: "sha256:abc"}
	base := ComputeCacheKey("trivy", "0.50.0", tgt, Config{"severity": "high"})

	diffs := map[string]CacheKey{
		"version":  ComputeCacheKey("trivy", "0.51.0", tgt, Config{"severity": "high"}),
		"scanner":  ComputeCacheKey("grype", "0.50.0", tgt, Config{"severity": "high"}),
		"config":   ComputeCacheKey("trivy", "0.50.0", tgt, Config{"severity": "low"}),
		"target":   ComputeCacheKey("trivy", "0.50.0", ImageTarget{Digest: "sha256:def"}, Config{"severity": "high"}),
		"targetkd": ComputeCacheKey("trivy", "0.50.0", HostTarget{URL: "sha256:abc"}, Config{"severity": "high"}),
	}
	for name, k := range diffs {
		if k == base {
			t.Errorf("cache key should change when %s changes", name)
		}
	}
}

// A policy list may be written either way, and a scanner judges by the identifier in both.
func TestEntryID(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		entry any
		want  string
		ok    bool
	}{
		{"the identifier alone", "AGPL-3.0-only", "AGPL-3.0-only", true},
		{"written long", map[string]any{"id": "SSPL-1.0", "reason": "not OSI-approved"}, "SSPL-1.0", true},
		{"an empty identifier", "", "", false},
		{"long with no id", map[string]any{"reason": "we forgot the license"}, "", false},
		{"an id that is not a string", map[string]any{"id": 7}, "", false},
		{"neither shape", []any{"AGPL-3.0-only"}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := EntryID(tc.entry)
			if got != tc.want || ok != tc.ok {
				t.Errorf("EntryID(%#v) = %q, %v; want %q, %v", tc.entry, got, ok, tc.want, tc.ok)
			}
		})
	}
}
