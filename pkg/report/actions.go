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
	// key is the identity findings group under — what makes two of them one action. Held so a
	// caller can be told it, rather than having to work out membership from a title.
	key string
	// title is what to do, in the imperative.
	title string
	// control the findings came from, and the worst priority among them.
	control  string
	priority string
	// findings are every finding this action resolves, most urgent first.
	findings []finding
	// upstream marks an action whose unit of work is an image somebody else publishes. The image
	// names itself in the title, so the row has nothing to add below it.
	upstream bool
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
		out = append(out, displayLocation(f))
	}
	return out
}

// displayLocation shortens a location that is an image reference.
//
// A digest-pinned reference from a private registry runs past 130 characters, and two of them
// leave no room for anything else on the line. The digest is what makes the scan reproducible and
// belongs in the report and the SARIF; what a reader needs here is which image to rebuild, and
// the repository and tag say that.
//
// Only for image findings. A file path shortened to its basename loses the directory, which is
// the part that distinguishes two Dockerfiles.
func displayLocation(f finding) string {
	if f.control != "images" {
		return f.location
	}
	ref := f.location
	if at := strings.Index(ref, "@"); at > 0 {
		ref = ref[:at]
	}
	// Drop the registry host, keep everything that names the image. The host is the same for
	// every image in most descriptors, so it is the part carrying no information here — and the
	// namespace is not: "chainguard-sync/redis" and "istio/redis" are different images.
	//
	// A first segment containing a dot or a colon is a host, which is the rule a container
	// runtime itself uses to tell "myteam/app" from "registry.example.com/app".
	if slash := strings.Index(ref, "/"); slash > 0 {
		if head := ref[:slash]; strings.ContainsAny(head, ".:") {
			return ref[slash+1:]
		}
	}
	return ref
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
			a = &action{key: key, title: title, control: f.control, priority: f.priority}
			byKey[key] = a
			order = append(order, key)
		}
		// Findings arrive most urgent first, so the first one sets the band and no later, lesser
		// one lowers it: an action that clears a P1 is P1 work whatever else it clears.
		a.findings = append(a.findings, f)
	}

	for _, key := range order {
		a := *byKey[key]
		if f, ok := a.exemplar(); ok {
			a.upstream = f.builtUpstream
		}
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
	// An image somebody else publishes is one action however many packages are wrong inside it,
	// and the action is the image. Nobody running the scan can upgrade a library they do not
	// build: the fix is a newer image, or a wait for whoever publishes it. Grouping these by
	// package would scatter one action — take a newer redis — across every library in it, and
	// name none of them something the reader can do.
	//
	// Before the package case, because a finding is both: it names a package, and the package is
	// not the unit of work here.
	case f.builtUpstream && f.control == "images" && f.location != "":
		// The image is the title, so the row does not repeat it below, and the reason it is the
		// unit of work goes in the meta as one word rather than a clause on every line.
		return "image\x00" + f.location, "Update " + displayLocation(f)

	// The same argument one level up, for a repository somebody else publishes. The unit of work
	// is their software, not a file inside it: keying on the location here would title the action
	// "Update requirements.txt", which is an instruction to edit a file in a repository the reader
	// cannot push to — precisely the advice declaring `builtBy: upstream` exists to stop.
	//
	// Falls back to the component when the repository is a local path, which is what a scan of a
	// checkout reports. "Update ." names nothing.
	case f.builtUpstream && upstreamUnit(f) != "":
		return "upstream\x00" + upstreamUnit(f), "Update " + upstreamUnit(f)

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

// target is the version to upgrade to, when every advisory in the group agrees on one.
//
// Only when they agree. Where they disagree there is no single answer Draugr can give — version
// ordering belongs to the ecosystem, and naming the wrong release as sufficient reads as "do this
// and you are done" while leaving findings behind. The reader's package manager settles it.
func (a action) target() string {
	fixes := a.fixedVersions()
	if len(fixes) == 1 {
		return fixes[0]
	}
	return ""
}

// exemplar is one finding from the group, for a reader who wants to read about it.
func (a action) exemplar() (finding, bool) {
	if len(a.findings) == 0 {
		return finding{}, false
	}
	return a.findings[0], true
}

// Action is one thing to do and what doing it clears, for a consumer outside this package.
//
// Exported so the MCP server answers "what should I do" with the same grouping the console
// prints. The keying is the subtle part — which findings are one fix and which only look alike —
// and a second implementation of it would drift from this one silently, leaving an assistant and
// a terminal describing the same report differently.
type Action struct {
	// Title is what to do, in the imperative.
	Title string `json:"title"`
	// Control the findings came from, and the worst priority among them.
	Control  string `json:"control,omitempty"`
	Priority string `json:"priority,omitempty"`
	// Clears is how many findings this one action resolves.
	Clears int `json:"clears"`
	// Upstream marks an action whose unit of work is something somebody else publishes: the fix
	// is to take a newer one, not to change anything inside it.
	Upstream bool `json:"upstream,omitempty"`
	// Where lists the distinct places this applies, capped.
	Where []string `json:"where,omitempty"`
	// RuleIDs are the rules this action resolves, capped, so a caller can look any of them up.
	RuleIDs []string `json:"ruleIds,omitempty"`
	// Key is what these findings grouped under: the identity that makes two of them one action.
	//
	// Opaque, and deliberately — its shape is this package's business and changes when the
	// grouping does. What it is for is membership: a caller holding the findings can ask this
	// package which action each one belongs to and match on this, instead of inferring it from a
	// title. Title is written for a reader and is not an identity — an action fed by two controls
	// takes one of their names, and matching on that silently drops the other's findings.
	//
	// Not serialized. It is an identity for a caller holding this package's own output in memory,
	// and it contains a separator that has no business in a JSON document an assistant reads.
	Key string `json:"-"`
	// FixedVersions are the releases that clear this, in the order the advisories named them.
	//
	// Every one of them, not the newest: advisories disagree about which release resolves them,
	// and version ordering belongs to the ecosystem rather than here. One entry is the answer;
	// several means the reader's package manager settles it, and naming one of them as sufficient
	// would read as "do this and you are done" while leaving findings behind.
	FixedVersions []string `json:"fixedVersions,omitempty"`
}

// ActionsFor groups a run's findings into the fix list, most urgent first.
//
// Suppressed findings are left out for the same reason the console leaves them out: an excluded
// finding is a decision somebody recorded, and proposing it as work is proposing to undo that
// decision without the reason they gave.
//
// Keyed by control, as a run holds them, because the grouping keys on it: two controls reporting
// the same rule id are two things to do. A caller holding only a merged results.sarif has no
// control to give and can pass a single entry under "" — grouping then falls back to the rule id,
// which is the right answer for a file that has already lost the distinction.
func ActionsFor(reports map[string]sarif.Report) []Action {
	const most = 5

	names := make([]string, 0, len(reports))
	for name := range reports {
		names = append(names, name)
	}
	sort.Strings(names)

	var findings []finding
	for _, name := range names {
		rep := reports[name]
		for _, res := range rep.Results {
			if res.Suppressed() {
				continue
			}
			findings = append(findings, finding{
				control: name, ruleID: res.RuleID, tool: res.Tool, priority: res.Priority,
				component: res.Component, repository: res.Repository,
				location: locationOf(res), message: res.Message,
				level: res.Level, severity: res.Severity(""),
				helpURI: rep.HelpURI(res.RuleID),
				score:   res.Score, hasScore: res.HasScore,
				remediation:     res.Remediation(),
				builtUpstream:   res.BuiltUpstream,
				pkg:             res.Package,
				operatingSystem: res.OperatingSystem,
			})
		}
	}
	sortFindings(findings)

	grouped, external := groupActions(findings, nil)
	out := make([]Action, 0, len(grouped)+len(external))
	for _, a := range grouped {
		rules := make([]string, 0, most)
		seen := map[string]bool{}
		for _, f := range a.findings {
			if seen[f.ruleID] || f.ruleID == "" {
				continue
			}
			seen[f.ruleID] = true
			if len(rules) == most {
				break
			}
			rules = append(rules, f.ruleID)
		}
		out = append(out, Action{
			Title:         a.title,
			Control:       a.control,
			Priority:      a.priority,
			Clears:        a.count(),
			Upstream:      a.upstream,
			Where:         a.where(most),
			RuleIDs:       rules,
			Key:           a.key,
			FixedVersions: a.fixedVersions(),
		})
	}
	return out
}

// upstreamUnit names the thing a reader would have to take a newer version of.
//
// The repository where it identifies one, and the component otherwise — a scan of a local checkout
// records the path it was given, and "." is not something anybody can go and update. Empty when
// neither is known, which leaves the finding to the ordinary package and code cases below rather
// than titling an action after nothing.
func upstreamUnit(f finding) string {
	if r := f.repository; r != "" && r != "." && !strings.HasPrefix(r, "/") && !strings.HasPrefix(r, ".") {
		return shortRepository(r)
	}
	return f.component
}
