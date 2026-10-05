package report

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/draugr-dev/draugr/internal/english"
	"github.com/draugr-dev/draugr/internal/versionorder"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// policyStep is where an upgrade action stands against its component's fixes.upgrade.
type policyStep struct {
	// policy is the component's fixes.upgrade, patch or minor.
	policy saga.UpgradeStep
	// applies is false where the versions are not semantic, so no step could be sized.
	applies bool
	// beyond is the size of a step past the policy, minor or major. Empty for a step within it.
	beyond saga.UpgradeStep
	// after is the ID of the step this one presumes has been taken, for the step past the policy
	// that follows one within it.
	after string
	// target is the release the step moves to, where it is not the one upgradeTarget would name for
	// the same findings.
	target string
}

// label is what the console and the HTML report print after the title, or "" for none.
func (s *policyStep) label() string {
	if s == nil || !s.applies || s.beyond == "" {
		return ""
	}
	return fmt.Sprintf("%s · beyond policy %s", s.beyond, s.policy)
}

// splitByPolicy divides each upgrade whose component set fixes.upgrade below major into the step
// the policy allows and the step past it.
//
// Every finding stays in exactly one action. The step within the policy is banded by what it
// clears; the step past it by what only it clears, so a major upgrade that alone resolves the
// urgent findings is ranked by them rather than hidden in a note under the minor one.
func splitByPolicy(actions []action) []action {
	out := make([]action, 0, len(actions))
	for _, a := range actions {
		out = append(out, splitOne(a)...)
	}
	return out
}

func splitOne(a action) []action {
	policy := a.policyOf()
	if policy == "" {
		return []action{a}
	}
	f := a.findings[0]
	ecosystem := versionorder.Ecosystem(f.pkg.PURL, f.pkg.Ecosystem)
	installed := f.pkg.Version

	var within, beyond []finding
	for _, f := range a.findings {
		fits, sized := fitsPolicy(ecosystem, installed, fixesOf(f), policy)
		if !sized {
			a.step = &policyStep{policy: policy}
			return []action{a}
		}
		if fits {
			within = append(within, f)
		} else {
			beyond = append(beyond, f)
		}
	}

	// A release the policy allows that clears every finding inside it. Without one there is no
	// step within the policy to propose, and the action stays whole, sized by where it goes.
	var target string
	if len(within) > 0 {
		target = lowestWithin(ecosystem, installed, within, policy)
	}
	if target == "" {
		a.step = &policyStep{policy: policy, applies: true}
		if t := a.target(); t != "" {
			if step, ok := stepOf(ecosystem, installed, t); ok && !allows(policy, step) {
				a.step.beyond = step
			}
		}
		return []action{a}
	}

	w := a
	w.findings = within
	w.priority = worstPriority(within)
	w.step = &policyStep{policy: policy, applies: true, target: target}
	if len(beyond) == 0 {
		return []action{w}
	}

	b := a
	b.key = a.key + "\x00beyond"
	b.findings = beyond
	b.priority = worstPriority(beyond)
	b.title = fmt.Sprintf("Upgrade %s %s", f.pkg.Name, target)
	b.step = &policyStep{policy: policy, applies: true, after: w.id()}
	if t := upgradeTarget(beyond); t != "" {
		b.step.target = t
		if step, ok := stepOf(ecosystem, target, t); ok {
			b.step.beyond = step
		}
	}
	if b.step.beyond == "" {
		// The step past the policy could not be sized from the release it follows, so it is sized
		// from what is installed: still past the policy, which is why it is its own action.
		b.step.beyond = saga.UpgradeMajor
	}
	return []action{w, b}
}

// policyOf is the fixes.upgrade an upgrade action's findings carry, or "" where the action is not
// an upgrade or its component left the default.
func (a action) policyOf() saga.UpgradeStep {
	if !strings.HasPrefix(a.key, "upgrade\x00") || len(a.findings) == 0 || a.findings[0].pkg == nil {
		return ""
	}
	p := saga.UpgradeStep(a.findings[0].upgradePolicy)
	if !p.Valid() || p == saga.UpgradeMajor {
		return ""
	}
	return p
}

// fitsPolicy reports whether some release a finding names as its fix is within policy of the
// installed version, and whether every version involved could be sized at all.
func fitsPolicy(ecosystem, installed string, fixes []string, policy saga.UpgradeStep) (fits, sized bool) {
	if !semanticEcosystem(ecosystem) {
		return false, false
	}
	for _, fix := range fixes {
		step, ok := stepOf(ecosystem, installed, fix)
		if !ok {
			return false, false
		}
		if allows(policy, step) {
			fits = true
		}
	}
	return fits, true
}

// lowestWithin is the lowest release the policy allows that clears every finding given, or "".
func lowestWithin(ecosystem, installed string, findings []finding, policy saga.UpgradeStep) string {
	var candidates []string
	for _, f := range findings {
		for _, fix := range fixesOf(f) {
			if step, ok := stepOf(ecosystem, installed, fix); ok && allows(policy, step) {
				candidates = append(candidates, fix)
			}
		}
	}
	sorted, ok := sortVersions(ecosystem, candidates)
	if !ok {
		return ""
	}
	for _, c := range sorted {
		all := true
		for _, f := range findings {
			cleared, known := releaseClears(ecosystem, c, installed, fixesOf(f))
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

// semanticEcosystem reports whether an ecosystem's versions say how large a change is. A
// distribution's are set by the distribution: Debian ships a fix as 3.0.11-1~deb12u2 on the same
// upstream release, and moving the upstream release is moving the distribution.
func semanticEcosystem(ecosystem string) bool {
	switch ecosystem {
	case "", "Debian", "Alpine", "Red Hat":
		return false
	}
	return true
}

// semver is a version's numbers: a major, and optionally a minor, a patch and one more, then
// optionally a pre-release, as npm's 1.9.0-beta.1 or PyPI's 1.9.0b1 write one.
var semver = regexp.MustCompile(`^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.\d+)?(?:[-.]?[A-Za-z][0-9A-Za-z.]*)?$`)

// numeric is a version that is only numbers, which is all Maven's are semantic in: a qualifier,
// 31.1-jre or 5.3.0.RELEASE, names a flavor or a channel rather than a pre-release.
var numeric = regexp.MustCompile(`^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.\d+)?$`)

// stepOf is the size of the change from one version to another, and whether both could be read.
//
// A major below 1000, so a calendar version, 2024.1 to 2025.3, is not read as a major upgrade it
// is not. In 0.x a minor step is a major one, as npm's and Cargo's caret ranges treat it: 0.12 to
// 0.13 may break.
func stepOf(ecosystem, from, to string) (saga.UpgradeStep, bool) {
	a, okA := versionParts(ecosystem, from)
	b, okB := versionParts(ecosystem, to)
	if !okA || !okB {
		return "", false
	}
	switch {
	case a[0] != b[0]:
		return saga.UpgradeMajor, true
	case a[1] != b[1] && a[0] == 0:
		return saga.UpgradeMajor, true
	case a[1] != b[1]:
		return saga.UpgradeMinor, true
	}
	return saga.UpgradePatch, true
}

// versionParts reads a semantic version's major, minor and patch.
func versionParts(ecosystem, v string) ([3]int, bool) {
	pattern := semver
	if ecosystem == "Maven" {
		pattern = numeric
	}
	m := pattern.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return [3]int{}, false
	}
	var out [3]int
	for i, s := range m[1:4] {
		if s == "" {
			continue
		}
		n, err := strconv.Atoi(s)
		if err != nil {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, out[0] < 1000
}

// allows reports whether a policy admits a step of the given size.
func allows(policy, step saga.UpgradeStep) bool {
	rank := map[saga.UpgradeStep]int{saga.UpgradePatch: 0, saga.UpgradeMinor: 1, saga.UpgradeMajor: 2}
	return rank[step] <= rank[policy]
}

// worstPriority is the highest band among findings, which arrive most urgent first.
func worstPriority(fs []finding) string {
	for _, f := range fs {
		if f.priority != "" {
			return f.priority
		}
	}
	return ""
}

// policyNotes are the lines saying where a component's fixes.upgrade could not apply, one per
// policy: how many of the actions given were left whole, and in which ecosystems.
//
// Once for the list rather than on each row. A distribution's revision is its upgrade, and nobody
// weighs it against minor or major, so there is nothing on the row for a reader to act on, and a
// mark repeated on every Debian package buries the rows past the policy that do need a decision.
func policyNotes(actions []action) []string {
	by := map[saga.UpgradeStep]map[string]int{}
	for _, a := range actions {
		if a.step == nil || a.step.applies {
			continue
		}
		if by[a.step.policy] == nil {
			by[a.step.policy] = map[string]int{}
		}
		by[a.step.policy][ecosystemName(a)]++
	}
	var out []string
	for _, policy := range saga.UpgradeSteps {
		counts := by[policy]
		if len(counts) == 0 {
			continue
		}
		names := make([]string, 0, len(counts))
		total := 0
		for name, n := range counts {
			names = append(names, name)
			total += n
		}
		sort.Slice(names, func(i, j int) bool {
			if counts[names[i]] != counts[names[j]] {
				return counts[names[i]] > counts[names[j]]
			}
			return names[i] < names[j]
		})
		parts := []string{fmt.Sprintf("policy %s", policy), "not applied to " + english.Count(total, "action")}
		for _, name := range names {
			parts = append(parts, fmt.Sprintf("%s %d", name, counts[name]))
		}
		out = append(out, strings.Join(parts, " · "))
	}
	return out
}

// ecosystemName is what a policy note calls an action's ecosystem: the one whose rules order its
// versions, else the one the scanner reported, in lower case.
func ecosystemName(a action) string {
	f := a.findings[0]
	if f.pkg == nil {
		return "unknown"
	}
	name := versionorder.Ecosystem(f.pkg.PURL, f.pkg.Ecosystem)
	if name == "" {
		name = f.pkg.Ecosystem
	}
	if name == "" {
		return "unknown"
	}
	return strings.ToLower(name)
}
