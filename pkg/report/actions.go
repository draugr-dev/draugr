package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// action is one thing a reader can do, and every finding it resolves.
//
// The unit of a fix list should be the fix. Eight vulnerabilities in one library are one upgrade;
// the same misconfiguration in three Dockerfiles is one habit; a release past end of service life
// is one move for everything in its layer. Listing them as eight, three and hundreds of rows
// makes a list that is long, repetitive, and — because the repetitive part crowds out the rest —
// worse at the one job it has.
type action struct {
	// title is what to do, in the imperative.
	title string
	// control the findings came from, and the worst priority among them.
	control  string
	priority string
	// findings are every finding this action resolves, most urgent first.
	findings []finding
	// cached marks an action whose findings all came from a cache entry keyed on something that
	// can be rebuilt under the same name. The row is still worth acting on; it may describe an
	// earlier build of the thing it names, and that belongs beside the row rather than in a
	// caveat further down that the reader has to connect back.
	cached bool
}

// count is how many findings the action resolves.
func (a action) count() int { return len(a.findings) }

// where lists the distinct locations, in order, for the ones worth naming.
func (a action) where(limit int) []string {
	seen := map[string]bool{}
	out := make([]string, 0, limit)
	for _, f := range a.findings {
		if f.location == "" || seen[f.location] {
			continue
		}
		seen[f.location] = true
		if len(out) == limit {
			return append(out, fmt.Sprintf("and %d more", countDistinct(a.findings)-limit))
		}
		out = append(out, f.location)
	}
	return out
}

func countDistinct(fs []finding) int {
	seen := map[string]bool{}
	for _, f := range fs {
		if f.location != "" {
			seen[f.location] = true
		}
	}
	return len(seen)
}

// groupActions folds findings into the actions that resolve them, most urgent first.
//
// Only groups where the fix genuinely is one fix. Twelve different benchmark checks against one
// cluster are twelve things to change, and collapsing them because they share a prefix would hide
// eleven of them — the opposite failure to the one this exists to fix, and the worse of the two.
//
// Findings nobody running the scan can act on are not here at all. They are counted and reported
// elsewhere: a list of things to fix that opens with work the reader cannot do teaches them the
// list is not worth reading.
func groupActions(findings []finding, unpinned []string) (actions []action, external []finding) {
	fromCache := make(map[string]bool, len(unpinned))
	for _, ref := range unpinned {
		fromCache[ref] = true
	}
	order := []string{}
	byKey := map[string]*action{}

	for _, f := range findings {
		if f.remediation == sarif.RemediationExternal {
			external = append(external, f)
			continue
		}
		key, title := actionFor(f)
		a, seen := byKey[key]
		if !seen {
			a = &action{title: title, control: f.control, priority: f.priority}
			byKey[key] = a
			order = append(order, key)
		}
		// Findings arrive most urgent first, so the first one sets the band and no later, lesser
		// one lowers it: an action that clears a P1 is P1 work whatever else it clears.
		a.findings = append(a.findings, f)
	}

	for _, key := range order {
		a := *byKey[key]
		// Every finding, not any: an action grouping one stale row with three fresh ones is not
		// a stale action, and marking it so would tell a reader to distrust work that is current.
		a.cached = len(a.findings) > 0
		for _, f := range a.findings {
			if !fromCache[f.location] {
				a.cached = false
				break
			}
		}
		actions = append(actions, a)
	}
	sort.SliceStable(actions, func(i, j int) bool { return moreUrgent(actions[i], actions[j]) })
	return actions, external
}

// moreUrgent orders actions by the worst priority they clear, then by how many findings that is.
//
// Priority first, always. An action clearing one P1 outranks one clearing forty P4s, because a P1
// is not something to trade away for volume — sorting by count first would bury the urgent work
// under the plentiful kind.
func moreUrgent(a, b action) bool {
	if a.priority != b.priority {
		// An unprioritized finding has no band to compare, and sorts last rather than first:
		// "" is lexically below "P1" and would otherwise lead the list.
		switch {
		case a.priority == "":
			return false
		case b.priority == "":
			return true
		}
		return a.priority < b.priority
	}
	return a.count() > b.count()
}

// actionFor returns the key two findings share when one fix clears both, and how to say it.
func actionFor(f finding) (key, title string) {
	switch {
	// An upgrade is one action however many vulnerabilities it resolves, which is the case that
	// pays off most: a library a year out of date carries a dozen findings and one fix.
	//
	// Keyed on the package rather than on the version that fixes it. Advisories disagree about
	// which release resolves them — three findings in one library can name three different fixed
	// versions — and treating those as three actions describes one upgrade as three, which is
	// the grouping failure this exists to remove.
	case f.pkg != nil && f.pkg.Name != "" && f.pkg.FixedVersion != "":
		return "upgrade\x00" + f.pkg.Ecosystem + "\x00" + f.pkg.Name,
			fmt.Sprintf("Upgrade %s %s", f.pkg.Name, f.pkg.Version)

	// Nothing fixes these where they are, and the release underneath is the fix — one move for
	// every finding in that layer, and usually the largest single reduction available.
	case f.remediation == sarif.RemediationUpstream && f.operatingSystem != "":
		return "os\x00" + f.operatingSystem,
			fmt.Sprintf("Move off %s — past end of service life, so no fix is coming",
				f.operatingSystem)

	// The same rule in several places is one thing to understand and apply, whether that is a
	// missing directive in three Dockerfiles or a credential committed to four files.
	default:
		return f.control + "\x00" + f.ruleID, titleFor(f)
	}
}

// titleFor writes the imperative for a finding that is its own action.
//
// The scanner's own sentence, which already describes the problem, rather than a phrasing of
// Draugr's invention: a rule's message is written by whoever knows the rule.
func titleFor(f finding) string {
	title := strings.TrimSpace(f.message)
	if title == "" {
		title = f.ruleID
	}
	// First line only. A scanner's message often carries a paragraph after it, and the first line
	// is the part written to be read on its own.
	if i := strings.IndexByte(title, '\n'); i > 0 {
		title = strings.TrimSpace(title[:i])
	}
	// A sentence boundary is a full stop followed by a space. Splitting on the full stop alone
	// cuts "str.format_map" to "str" and a version to its major — the punctuation inside an
	// identifier looks exactly like the punctuation at the end of a sentence.
	if i := strings.Index(title, ". "); i > 0 {
		title = title[:i]
	}
	return truncate(title, actionTitleWidth)
}

// actionTitleWidth keeps an action row inside a normal terminal alongside its control and count.
const actionTitleWidth = 72

// truncate shortens to n runes, marking that it did.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return strings.TrimSpace(string(r[:n-1])) + "…"
}

// fixedVersions lists the releases the findings say resolve them, in the order first seen.
//
// Draugr does not pick one. Version ordering is the ecosystem's own — 5.10 is above 5.9 in most
// and below it as a string — and naming the wrong release as sufficient is worse advice than
// naming several: it reads as "upgrade to this and you are done" when it would leave findings
// behind. Listing them lets the reader apply the ordering their package manager already knows.
func (a action) fixedVersions() []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range a.findings {
		if f.pkg == nil || f.pkg.FixedVersion == "" || seen[f.pkg.FixedVersion] {
			continue
		}
		seen[f.pkg.FixedVersion] = true
		out = append(out, f.pkg.FixedVersion)
	}
	return out
}

// detail is the second line under an action: where it applies, or which releases fix it.
func (a action) detail(locations int) string {
	if fixes := a.fixedVersions(); len(fixes) > 0 {
		if len(fixes) == 1 {
			return "fixed in " + fixes[0]
		}
		// A few, then a count. The advisories disagree and the reader's package manager settles
		// it; naming all six fills the line without changing what they type.
		const named = 3
		if len(fixes) > named {
			return fmt.Sprintf("fixed in %s and %d other releases — take the latest",
				strings.Join(fixes[:named], ", "), len(fixes)-named)
		}
		return "fixed in " + strings.Join(fixes, ", ") + " — take the latest"
	}
	return strings.Join(a.where(locations), " · ")
}
