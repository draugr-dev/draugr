package report

import (
	"slices"
	"strings"

	"github.com/draugr-dev/draugr/internal/versionorder"
)

// upgradeTarget is the lowest release that clears every finding in an upgrade, by the package's own
// ecosystem's order, or "" when that order cannot be established.
//
// Advisories disagree about which release resolves them: the openssl in one image carries forty
// findings naming seven fixed versions, and one upgrade, to the highest, clears them all. Working
// that out takes the ecosystem's ordering, which a reader's package manager has and a comparison of
// dotted numbers does not, so where the ecosystem is not one Draugr can order the answer is "" and
// the reader gets the versions the advisories named instead.
//
// A finding may name one fix per release line, as Trivy's "2.3.2, 2.2.5" does for Flask. A release
// clears it when it is at or past the highest of them, or at or past one of them on that one's line.
func upgradeTarget(findings []finding) string {
	var (
		ecosystem  string
		candidates []string
		mixed      bool
	)
	for _, f := range findings {
		if f.pkg == nil || f.pkg.FixedVersion == "" {
			continue
		}
		e := versionorder.Ecosystem(f.pkg.PURL, f.pkg.Ecosystem)
		if ecosystem != "" && e != ecosystem {
			mixed = true
		}
		ecosystem = e
		for _, v := range fixesOf(f) {
			if !slices.Contains(candidates, v) {
				candidates = append(candidates, v)
			}
		}
	}
	if len(candidates) == 0 {
		return ""
	}
	if mixed || ecosystem == "" {
		// The advisories agree on one release, which needs no ordering to name.
		if len(candidates) == 1 {
			return candidates[0]
		}
		return ""
	}
	sorted, ok := sortVersions(ecosystem, candidates)
	if !ok {
		return ""
	}
	for _, c := range sorted {
		all := true
		for _, f := range findings {
			if f.pkg == nil || f.pkg.FixedVersion == "" {
				continue
			}
			cleared, known := releaseClears(ecosystem, c, f.pkg.Version, fixesOf(f))
			if !known {
				return ""
			}
			if !cleared {
				all = false
				break
			}
		}
		if all {
			return spelledLike(ecosystem, c, findings)
		}
	}
	return ""
}

// fixesOf is the releases one finding names as fixing it. A scanner that writes the fix as a bound,
// ">=1.9.0", means the release it names.
func fixesOf(f finding) []string {
	var out []string
	for _, v := range strings.Split(f.pkg.FixedVersion, ",") {
		v = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(v), ">="))
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// sortVersions orders versions oldest first, or reports that two of them have no known order.
func sortVersions(ecosystem string, versions []string) ([]string, bool) {
	out := slices.Clone(versions)
	known := true
	slices.SortStableFunc(out, func(a, b string) int {
		order, ok := versionorder.Compare(ecosystem, a, b)
		if !ok {
			known = false
		}
		return order
	})
	return out, known
}

// releaseClears reports whether moving to release c resolves a finding at installed that names fixes, and
// whether that could be decided.
func releaseClears(ecosystem, c, installed string, fixes []string) (cleared, known bool) {
	// Never a release at or below what is installed: that is a downgrade, whatever line it is on.
	if installed != "" {
		order, ok := versionorder.Compare(ecosystem, c, installed)
		if !ok {
			return false, false
		}
		if order <= 0 {
			return false, true
		}
	}
	sorted, ok := sortVersions(ecosystem, fixes)
	if !ok {
		return false, false
	}
	if order, _ := versionorder.Compare(ecosystem, c, sorted[len(sorted)-1]); order >= 0 {
		return true, true
	}
	for _, fix := range sorted[:len(sorted)-1] {
		if order, _ := versionorder.Compare(ecosystem, c, fix); order >= 0 && releaseLine(c) == releaseLine(fix) {
			return true, true
		}
	}
	return false, true
}

// releaseLine is a version's first two numbers, the line a backported fix is released on: "2.2"
// for "2.2.5", "3.0" for "3.0.22-1~deb12u1".
func releaseLine(v string) string {
	if i := strings.IndexByte(v, ':'); i >= 0 {
		v = v[i+1:] // an epoch
	}
	v = strings.TrimPrefix(v, "v")
	var parts []string
	start := -1
	for i := 0; i <= len(v); i++ {
		digit := i < len(v) && v[i] >= '0' && v[i] <= '9'
		switch {
		case digit && start < 0:
			start = i
		case !digit && start >= 0:
			parts = append(parts, v[start:i])
			start = -1
			if len(parts) == 2 || i == len(v) || v[i] != '.' {
				return strings.Join(parts, ".")
			}
		}
	}
	return strings.Join(parts, ".")
}

// spelledLike writes a Go module version the way the installed one is written. Scanners disagree
// about the "v", and "v0.3.0 → 0.39.0" reads as two different things.
func spelledLike(ecosystem, target string, findings []finding) string {
	if ecosystem != "Go" || strings.HasPrefix(target, "v") {
		return target
	}
	for _, f := range findings {
		if f.pkg != nil && strings.HasPrefix(f.pkg.Version, "v") {
			return "v" + target
		}
	}
	return target
}
