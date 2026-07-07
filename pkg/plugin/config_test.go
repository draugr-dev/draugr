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
