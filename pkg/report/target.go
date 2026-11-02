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
//
// Whether a release clears a finding depends only on the version installed and the fixes it names,
// so each candidate is checked once against each distinct pair rather than once per finding. A large
// repository's upgrade carries thousands of findings over a handful of versions.
func upgradeTarget(findings []finding) string {
	var (
		ecosystem string
		mixed     bool
		pairs     []fixPair
		seen      = map[fixPair]bool{}
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
		if p := (fixPair{installed: f.pkg.Version, fixed: f.pkg.FixedVersion}); !seen[p] {
			seen[p] = true
			pairs = append(pairs, p)
		}
	}
	var candidates []string
	fixes := make([][]string, len(pairs))
	for i, p := range pairs {
		fixes[i] = splitFixes(p.fixed)
		for _, v := range fixes[i] {
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
	vs := newVersions(ecosystem)
	sorted, ok := sortVersions(vs, candidates)
	if !ok {
		return ""
	}
	for _, c := range sorted {
		all := true
		for i, p := range pairs {
			cleared, known := releaseClears(vs, c, p.installed, fixes[i])
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

// fixPair is the version a finding's package is installed at and the fixes its advisory names, as
// the scanner wrote them: all that decides whether a release clears the finding.
type fixPair struct {
	installed, fixed string
}

// fixesOf is the releases one finding names as fixing it. A scanner that writes the fix as a bound,
// ">=1.9.0", means the release it names.
func fixesOf(f finding) []string {
	return splitFixes(f.pkg.FixedVersion)
}

// splitFixes is the releases a package's fixed version names, one per release line.
func splitFixes(fixed string) []string {
	var out []string
	for _, v := range strings.Split(fixed, ",") {
		v = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(v), ">="))
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// versions orders the versions of one ecosystem, parsing each string and comparing each pair once
// for the length of one call. Working out a target compares a handful of versions many times over,
// and some ecosystems' comparisons, Debian's among them, allocate on every call.
type versions struct {
	ecosystem string
	parsed    map[string]parsedVersion
	orders    map[[2]string]versionOrder
}

// parsedVersion is one string as versions read it, and whether it parsed.
type parsedVersion struct {
	v  versionorder.Version
	ok bool
}

// versionOrder is the order of one pair of versions, and whether it is known.
type versionOrder struct {
	order int
	ok    bool
}

func newVersions(ecosystem string) *versions {
	return &versions{ecosystem: ecosystem, parsed: map[string]parsedVersion{}, orders: map[[2]string]versionOrder{}}
}

// compare is versionorder.Compare under the ecosystem vs orders.
func (vs *versions) compare(a, b string) (order int, ok bool) {
	key := [2]string{a, b}
	if o, seen := vs.orders[key]; seen {
		return o.order, o.ok
	}
	order, ok = vs.compareParsed(a, b)
	vs.orders[key] = versionOrder{order: order, ok: ok}
	return order, ok
}

func (vs *versions) compareParsed(a, b string) (order int, ok bool) {
	va, ok := vs.parse(a)
	if !ok {
		return 0, false
	}
	vb, ok := vs.parse(b)
	if !ok {
		return 0, false
	}
	return va.Compare(vb)
}

func (vs *versions) parse(s string) (versionorder.Version, bool) {
	if p, seen := vs.parsed[s]; seen {
		return p.v, p.ok
	}
	v, ok := versionorder.Parse(vs.ecosystem, s)
	vs.parsed[s] = parsedVersion{v: v, ok: ok}
	return v, ok
}

// sortVersions orders versions oldest first, or reports that two of them have no known order.
func sortVersions(vs *versions, list []string) ([]string, bool) {
	out := slices.Clone(list)
	known := true
	slices.SortStableFunc(out, func(a, b string) int {
		order, ok := vs.compare(a, b)
		if !ok {
			known = false
		}
		return order
	})
	return out, known
}

// releaseClears reports whether moving to release c resolves a finding at installed that names fixes, and
// whether that could be decided.
func releaseClears(vs *versions, c, installed string, fixes []string) (cleared, known bool) {
	// Never a release at or below what is installed: that is a downgrade, whatever line it is on.
	if installed != "" {
		order, ok := vs.compare(c, installed)
		if !ok {
			return false, false
		}
		if order <= 0 {
			return false, true
		}
	}
	sorted, ok := sortVersions(vs, fixes)
	if !ok {
		return false, false
	}
	if order, _ := vs.compare(c, sorted[len(sorted)-1]); order >= 0 {
		return true, true
	}
	for _, fix := range sorted[:len(sorted)-1] {
		if order, _ := vs.compare(c, fix); order >= 0 && releaseLine(c) == releaseLine(fix) {
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
