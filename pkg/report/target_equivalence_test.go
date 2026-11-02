package report

import (
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/versionorder"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// The reference below checks every candidate against every finding and compares versions with
// versionorder.Compare, which parses both strings each time. It is the straightforward reading of
// the rule, and upgradeTarget and lowestWithin have to give its answer on any input.

func referenceUpgradeTarget(findings []finding) string {
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
		if len(candidates) == 1 {
			return candidates[0]
		}
		return ""
	}
	sorted, ok := referenceSort(ecosystem, candidates)
	if !ok {
		return ""
	}
	for _, c := range sorted {
		all := true
		for _, f := range findings {
			if f.pkg == nil || f.pkg.FixedVersion == "" {
				continue
			}
			cleared, known := referenceClears(ecosystem, c, f.pkg.Version, fixesOf(f))
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

func referenceLowestWithin(ecosystem, installed string, findings []finding, policy saga.UpgradeStep) string {
	var candidates []string
	for _, f := range findings {
		for _, fix := range fixesOf(f) {
			if step, ok := stepOf(ecosystem, installed, fix); ok && allows(policy, step) {
				candidates = append(candidates, fix)
			}
		}
	}
	sorted, ok := referenceSort(ecosystem, candidates)
	if !ok {
		return ""
	}
	for _, c := range sorted {
		all := true
		for _, f := range findings {
			cleared, known := referenceClears(ecosystem, c, installed, fixesOf(f))
			if !known || !cleared {
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

func referenceSort(ecosystem string, versions []string) ([]string, bool) {
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

func referenceClears(ecosystem, c, installed string, fixes []string) (cleared, known bool) {
	if installed != "" {
		order, ok := versionorder.Compare(ecosystem, c, installed)
		if !ok {
			return false, false
		}
		if order <= 0 {
			return false, true
		}
	}
	sorted, ok := referenceSort(ecosystem, fixes)
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

// randomPackage is a package as scanners report it: a package URL type, the ecosystem the scanner
// names, and the versions its findings carry, among them ones that do not parse.
type randomPackage struct {
	purlType, reported string
	versions           []string
}

var randomPackages = []randomPackage{
	{"npm", "npm", []string{"1.0.0", "1.2.0", "1.2.6", "1.8.3", "1.9.0", "1.12.2", "2.999.999", "3.0.0", "3.4.0", "1.9.0b1", "v1.2.0", "next"}},
	{"pypi", "pip", []string{"0.12.2", "2.0.1", "2.2.5", "2.3.0", "2.3.1", "2.3.2", "1.0rc1", "1.0", "1.0.post1", "5.4", "not a version"}},
	{"deb", "debian", []string{"3.0.14-1~deb12u2", "3.0.15-1~deb12u1", "3.0.17-1~deb12u2", "3.0.17-1~deb12u3", "3.0.22-1~deb12u1", "1:2.3.4-1", "1.0~rc1"}},
	{"golang", "gomod", []string{"v0.3.0", "0.3.8", "v0.3.8", "0.39.0", "v0.39.0", "1.24.13", "1.25.2", "1.25.7", "1.26.0-rc.3"}},
	{"maven", "jar", []string{"2.13.4", "2.13.4.2", "2.14.1", "2.15.0", "5.3.0.RELEASE", "31.1-jre"}},
	{"conda", "conda-pkg", []string{"1.0", "1.2", "1.3", "2.1"}},
}

// randomFindings is one group of findings in pkg: mostly one installed version and one ecosystem,
// with the occasional finding in another, with no package, or naming no fix, so every branch of the
// rule is reached.
func randomFindings(rng *rand.Rand, pkg randomPackage) []finding {
	pick := func(vs []string) string { return vs[rng.IntN(len(vs))] }
	installed := []string{pick(pkg.versions), pick(pkg.versions)}
	if rng.IntN(10) == 0 {
		installed = append(installed, "")
	}
	fixedVersion := func(p randomPackage) string {
		var fixes []string
		for range 1 + rng.IntN(3) {
			fix := pick(p.versions)
			if rng.IntN(6) == 0 {
				fix = ">=" + fix
			}
			if rng.IntN(8) == 0 {
				fix = " " + fix + " "
			}
			fixes = append(fixes, fix)
		}
		return strings.Join(fixes, pick([]string{", ", ","}))
	}
	// Few distinct fixed versions, each named by many findings, as a large repository's are.
	pool := make([]string, 1+rng.IntN(5))
	for i := range pool {
		pool[i] = fixedVersion(pkg)
	}
	out := make([]finding, rng.IntN(40))
	for i := range out {
		if rng.IntN(25) == 0 {
			continue // no package
		}
		p := pkg
		fixed := pick(pool)
		if rng.IntN(15) == 0 {
			p = randomPackages[rng.IntN(len(randomPackages))]
			fixed = fixedVersion(p)
		}
		if rng.IntN(12) == 0 {
			fixed = ""
		}
		purl := "pkg:" + p.purlType + "/p@" + installed[0]
		if rng.IntN(4) == 0 {
			purl = ""
		}
		out[i] = finding{pkg: &sarif.Package{
			Name: "p", Version: pick(installed), FixedVersion: fixed, PURL: purl, Ecosystem: p.reported,
		}}
	}
	return out
}

// The target is the one the reference names, on inputs drawn to repeat versions many times over, to
// mix ecosystems, and to carry versions that do not parse.
func TestUpgradeTargetNamesTheReferencesRelease(t *testing.T) {
	rng := rand.New(rand.NewPCG(1748, 2026)) // #nosec G404 -- seeded so a failing trial reproduces
	named := 0
	for trial := range 5000 {
		pkg := randomPackages[rng.IntN(len(randomPackages))]
		fs := randomFindings(rng, pkg)
		want := referenceUpgradeTarget(fs)
		if got := upgradeTarget(fs); got != want {
			t.Fatalf("trial %d: upgradeTarget = %q, reference = %q, findings:\n%s", trial, got, want, describeFindings(fs))
		}
		if want != "" {
			named++
		}
	}
	// A comparison that only ever agreed on "" would prove nothing.
	t.Logf("%d of 5000 trials named a release", named)
	if named < 500 {
		t.Errorf("only %d trials named a release", named)
	}
}

// The release within an upgrade policy is the one the reference names.
func TestLowestWithinNamesTheReferencesRelease(t *testing.T) {
	rng := rand.New(rand.NewPCG(1748, 2027)) // #nosec G404 -- seeded so a failing trial reproduces
	named := 0
	for trial := range 5000 {
		pkg := randomPackages[rng.IntN(len(randomPackages))]
		var fs []finding
		for _, f := range randomFindings(rng, pkg) {
			// An upgrade's findings, which all have a package and name a fix.
			if f.pkg != nil && f.pkg.FixedVersion != "" {
				fs = append(fs, f)
			}
		}
		// Fewer findings, so a release within the policy clears them all often enough to compare.
		fs = fs[:min(len(fs), 1+rng.IntN(6))]
		ecosystem := versionorder.Ecosystem("pkg:"+pkg.purlType+"/p@1", "")
		installed := pkg.versions[rng.IntN(len(pkg.versions))]
		policy := []saga.UpgradeStep{saga.UpgradePatch, saga.UpgradeMinor}[rng.IntN(2)]
		want := referenceLowestWithin(ecosystem, installed, fs, policy)
		if got := lowestWithin(ecosystem, installed, fs, policy); got != want {
			t.Fatalf("trial %d: lowestWithin(%s, %s, %s) = %q, reference = %q, findings:\n%s",
				trial, ecosystem, installed, policy, got, want, describeFindings(fs))
		}
		if want != "" {
			named++
		}
	}
	t.Logf("%d of 5000 trials named a release", named)
	if named < 250 {
		t.Errorf("only %d trials named a release", named)
	}
}

func describeFindings(fs []finding) string {
	var b strings.Builder
	for _, f := range fs {
		if f.pkg == nil {
			b.WriteString("  (no package)\n")
			continue
		}
		b.WriteString("  " + f.pkg.PURL + " " + f.pkg.Ecosystem + " " + f.pkg.Version + " fixed " + f.pkg.FixedVersion + "\n")
	}
	return b.String()
}
