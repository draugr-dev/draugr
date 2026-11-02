package report

import (
	"fmt"
	"math/rand/v2"
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// benchLadder is one ecosystem's package as a large fleet carries it: a PURL type, the scanner's
// ecosystem, and the release at each step of its ladder, step 0 being the one installed.
type benchLadder struct {
	purlType, ecosystem string
	release             func(step int) string
}

var benchLadders = []benchLadder{
	{"npm", "npm", func(i int) string { return fmt.Sprintf("4.17.%d", 4+i) }},
	{"pypi", "pip", func(i int) string { return fmt.Sprintf("2.%d.%d", i/3, i%3) }},
	{"deb", "debian", func(i int) string { return fmt.Sprintf("3.0.%d-1~deb12u%d", 14+i/2, 1+i%2) }},
	{"golang", "gomod", func(i int) string {
		if i == 0 {
			return "v0.7.0" // the module's spelling; Trivy writes the fixes without the "v"
		}
		return fmt.Sprintf("0.%d.0", 7+i)
	}},
	{"maven", "jar", func(i int) string { return fmt.Sprintf("2.9.%d", 8+i) }},
}

// manyFixableFindings is a fix list's input at the size a fleet reaches: many findings over few
// distinct versions. Each component holds each package at one installed version, and its advisories
// name one of the ladder's releases as the fix, mostly the older ones, as a library some years out of
// date carries, with one in five naming a fix on two release lines.
func manyFixableFindings(components, packages, perPackage, steps int) []sarif.Result {
	rng := rand.New(rand.NewPCG(1748, 1748))
	var out []sarif.Result
	n := 0
	for c := range components {
		component := fmt.Sprintf("service-%d", c)
		for _, l := range benchLadders {
			for p := range packages {
				name := fmt.Sprintf("%s-lib-%d", l.purlType, p)
				installed := l.release(0)
				for range perPackage {
					u := rng.Float64()
					step := 1 + int(float64(steps-1)*u*u*u)
					fixed := l.release(step)
					if rng.IntN(5) == 0 {
						fixed = l.release(1+rng.IntN(steps-1)) + ", " + fixed
					}
					n++
					out = append(out, sarif.Result{
						Tool: "trivy", RuleID: fmt.Sprintf("CVE-2024-%05d", n), Level: sarif.LevelError, Priority: "P2",
						Component: component, Repository: "repo-" + component,
						Location: sarif.Location{URI: "lockfile", StartLine: 1 + n%400},
						Package: &sarif.Package{Name: name, Version: installed, FixedVersion: fixed,
							Ecosystem: l.ecosystem, PURL: fmt.Sprintf("pkg:%s/%s@%s", l.purlType, name, installed)},
					})
				}
			}
		}
	}
	return out
}

// BenchmarkActionsForManyFindings builds the fix list for 64,000 fixable findings in four components
// and five ecosystems, each package on a ladder of twenty releases. Checking an upgrade's candidate
// releases costs in proportion to the distinct versions its findings name.
func BenchmarkActionsForManyFindings(b *testing.B) {
	reports := map[string]sarif.Report{"sca": {Results: manyFixableFindings(4, 4, 800, 20)}}
	b.ReportAllocs()
	for b.Loop() {
		ActionsFor(reports)
	}
}

// BenchmarkUpgradeTargetManyFindings names the target of each upgrade in the same input, 3,200
// findings a package, without the rest of the fix list.
func BenchmarkUpgradeTargetManyFindings(b *testing.B) {
	byPackage := map[string][]finding{}
	var order []string
	for _, res := range manyFixableFindings(1, 4, 3200, 20) {
		key := res.Package.PURL
		if _, seen := byPackage[key]; !seen {
			order = append(order, key)
		}
		byPackage[key] = append(byPackage[key], findingOf("sca", sarif.Report{}, res))
	}
	b.ReportAllocs()
	for b.Loop() {
		for _, key := range order {
			if upgradeTarget(byPackage[key]) == "" {
				b.Fatalf("no target for %s", key)
			}
		}
	}
}
