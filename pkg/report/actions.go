package report

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/draugr-dev/draugr/internal/manifests"
	"github.com/draugr-dev/draugr/pkg/prioritization"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/skald"
)

// action is one thing a reader can do, and every finding it resolves.
//
// The unit of a fix list should be the fix. Eight vulnerabilities in one library are one upgrade;
// the same misconfiguration in three Dockerfiles is one habit; a release past end of service life
// is one move for everything in its layer. Listing them as eight, three and hundreds of rows makes
// a list that is long, repetitive, and, because the repetitive part crowds out the rest, worse at
// the one job it has.
type action struct {
	// key is the identity findings group under. What makes two of them one action. Held so a caller
	// can be told it, rather than having to work out membership from a title.
	key string
	// title is what to do, in the imperative.
	title string
	// kind is who does the work and how: bump, code, infrastructure, credential, wait or decide.
	kind skald.ActionKind
	// summary is the scanner's own one-line description of what is wrong, for an action titled by a
	// rule's name. Empty where the title already says it, and where the findings describe
	// themselves differently: one of several descriptions, printed as though it were all of them,
	// would be wrong about the rest.
	summary string
	// control the findings came from, and the worst priority among them.
	control  string
	priority string
	// component every finding belongs to, empty where they span several or none. A dependency
	// action is one per component, because a row with two owners cannot be handed to either.
	component string
	// byRule marks an action grouped on a rule rather than on one change that clears it.
	byRule bool
	// nameRepository marks an action for one line of code in a list whose findings span more than
	// one repository. Its location then names the repository, because the same path in another
	// repository is another action with the same title, and the two rows would read alike.
	nameRepository bool
	// findings are every finding this action resolves, most urgent first.
	findings []finding
	// upstream marks an action whose unit of work is an image somebody else publishes. The image
	// names itself in the title, so the row has nothing to add below it.
	upstream bool
	// step is where an upgrade stands against its component's fixes.upgrade, nil where the
	// component left the default or the action is not an upgrade.
	step *policyStep
	// cached marks an action whose findings all came from a cache entry keyed on something that
	// can be rebuilt under the same name. The row is still worth acting on; it may describe an
	// earlier build of the thing it names, and that belongs beside the row rather than in a
	// caveat further down that the reader has to connect back.
	cached bool
}

// count is how many findings the action resolves.
func (a action) count() int { return len(a.findings) }

// where lists the distinct locations, in order, for the ones worth naming.
//
// A location is a path in a repository, so the same path in two repositories is two places, and
// each names its repository where the action spans more than one. A vendored copy is marked: in a
// dependency action, replacing a copy of the library is a different edit from bumping it in a
// manifest, and a reader who bumps the lockfile has not touched the file beside it.
func (a action) where(limit int) []string {
	seen := map[string]bool{}
	spans := len(a.repositories()) > 1 || a.nameRepository
	out := make([]string, 0, limit)
	for _, f := range a.findings {
		k := locationKey(f)
		if f.location == "" || seen[k] {
			continue
		}
		seen[k] = true
		if len(out) == limit {
			return append(out, fmt.Sprintf("and %d more", countDistinct(a.findings)-limit))
		}
		place := displayLocation(f)
		if spans && f.repository != "" {
			place = shortRepository(f.repository) + " " + place
		}
		if vendored(f) {
			place += " vendored"
		}
		out = append(out, place)
	}
	return out
}

// repositories are the distinct repositories the action's findings were found in.
func (a action) repositories() map[string]bool {
	out := map[string]bool{}
	for _, f := range a.findings {
		if f.repository != "" {
			out[f.repository] = true
		}
	}
	return out
}

// locationKey is a finding's place: its repository and the path in it.
func locationKey(f finding) string { return f.repository + "\x00" + f.location }

// lineSuffix is the ":12" a location carries after its path.
var lineSuffix = regexp.MustCompile(`:\d+$`)

// vendored reports whether a dependency finding sits in a copy of the library rather than in a
// manifest or lockfile that declares it. A retire.js finding on a minified file is the common one.
func vendored(f finding) bool { return f.location != "" && locationKind(f) == skald.LocationVendored }

// locationKind is what kind of place a finding is in: an image, a dependency's manifest, lockfile
// or vendored copy, or any other file.
func locationKind(f finding) string {
	if f.control == "images" || f.image != "" {
		// A file read inside an image, a license Trivy found in one, is in the image rather than in
		// the tree, so it is never a copy somebody committed.
		if f.image == "" || f.location == f.image {
			return skald.LocationImage
		}
		return skald.LocationFile
	}
	if !aboutDependency(f) {
		return skald.LocationFile
	}
	path := lineSuffix.ReplaceAllString(f.location, "")
	switch {
	case manifests.IsLockfile(path):
		return skald.LocationLockfile
	case manifests.FormatOf(path) != "":
		return skald.LocationManifest
	}
	return skald.LocationVendored
}

// aboutDependency reports whether a finding is about one package: a vulnerability in it, or the
// license it carries. Only then can the file it is in be a manifest, a lockfile or a copy; a SAST
// finding in setup.py is about the code in setup.py.
func aboutDependency(f finding) bool {
	if f.pkg != nil && f.pkg.Name != "" {
		return true
	}
	rest, ok := strings.CutPrefix(f.ruleID, "license/")
	if !ok || f.control != "licenses" {
		return false
	}
	_, pkg, _ := strings.Cut(rest, "/")
	return pkg != ""
}

// locations are every distinct place the action's findings are, in the order first seen.
func (a action) locations() []ActionLocation {
	seen := map[string]bool{}
	var out []ActionLocation
	for _, f := range a.findings {
		k := locationKey(f)
		if f.location == "" || seen[k] {
			continue
		}
		seen[k] = true
		l := ActionLocation{Repository: f.repository, Path: f.location, Kind: locationKind(f)}
		// Not for an image: `redis:7` ends in what looks like a line.
		if m := lineSuffix.FindString(f.location); m != "" && l.Kind != skald.LocationImage {
			l.Path = strings.TrimSuffix(f.location, m)
			l.Line, _ = strconv.Atoi(m[1:])
		}
		out = append(out, l)
	}
	return out
}

// id identifies the action across runs: its grouping key and the version it moves to.
func (a action) id() string {
	sum := sha256.Sum256([]byte(a.key + "\x00" + a.target()))
	return hex.EncodeToString(sum[:])[:16]
}

// dependency is the package an upgrade or a replacement is about, or nil for any other action.
func (a action) dependency() *sarif.Package {
	if !strings.HasPrefix(a.key, "upgrade\x00") && !strings.HasPrefix(a.key, "nofix\x00") {
		return nil
	}
	for _, f := range a.findings {
		if f.pkg != nil {
			return f.pkg
		}
	}
	return nil
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
	return displayImage(f.location)
}

// displayImage is an image reference without its digest or registry host.
func displayImage(ref string) string {
	if at := strings.Index(ref, "@"); at > 0 {
		ref = ref[:at]
	}
	// Drop the registry host, keep everything that names the image. The host is the same for every
	// image in most descriptors, so it is the part carrying no information here. And the namespace is
	// not: "chainguard-sync/redis" and "istio/redis" are different images.
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
			seen[locationKey(f)] = true
		}
	}
	return len(seen)
}

// groupActions folds findings into the actions that resolve them, most urgent first.
//
// Only groups where the fix genuinely is one fix. Twelve different benchmark checks against one
// cluster are twelve things to change, and collapsing them because they share a prefix would hide
// eleven of them, the opposite failure to the one this exists to fix, and the worse of the two.
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
	homes := componentRepositories(findings)

	for _, f := range findings {
		if f.remediation == sarif.RemediationExternal {
			external = append(external, f)
			continue
		}
		// A SARIF file another tool wrote names paths and no repository, so its finding at a line
		// is placed in the repository the rest of its component was scanned in. Left unplaced, Bandit's
		// finding on a line would be one row and Semgrep's three on the same line another.
		if onALine(f) && f.repository == "" {
			f.repository = homes[f.component]
		}
		key, title, kind, byRule := actionFor(f)
		a, seen := byKey[key]
		if !seen {
			a = &action{key: key, title: title, kind: kind, control: f.control, priority: f.priority, byRule: byRule}
			byKey[key] = a
			order = append(order, key)
		}
		// Findings arrive most urgent first, so the first one sets the band and no later, lesser
		// one lowers it: an action that clears a P1 is P1 work whatever else it clears.
		a.findings = append(a.findings, f)
	}

	var listed []finding
	for _, key := range order {
		listed = append(listed, byKey[key].findings...)
	}
	spansRepositories := manyRepositories(listed)
	for _, key := range order {
		a := *byKey[key]
		if f, ok := a.exemplar(); ok {
			a.upstream = f.builtUpstream
		}
		if a.byRule {
			a.summary = summaryFor(a)
		}
		if a.atOneLine() {
			a.title, a.summary = lineTitle(a.findings)
			a.nameRepository = spansRepositories
		}
		a.component = commonComponent(a.findings)
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
	actions = splitByPolicy(actions)
	ranks := packageRanks(actions)
	sort.SliceStable(ranks, func(i, j int) bool { return moreUrgent(ranks[i], ranks[j]) })
	sorted := make([]action, len(ranks))
	for i, r := range ranks {
		sorted[i] = *r.action
	}
	return sorted, external
}

// rankedAction is an action and what it is ranked by: its own band, severity, exploitation signal
// and count, or for one step of an upgrade the policy split, the package's.
type rankedAction struct {
	*action
	priority string
	// severity is the rank of the worst severity it clears, as the band was computed from it.
	severity int
	// signal is the strongest exploitation evidence among what it clears: 2 for KEV, 1 for EPSS.
	signal int
	count  int
	group  string
	beyond bool
}

// packageRanks pairs each action with what it is ranked by. The steps of one package's upgrade
// rank together, by the worst band either clears and the findings both clear, so the major step
// that clears the urgent findings is read beside the minor step it follows.
func packageRanks(actions []action) []rankedAction {
	worst := map[string]string{}
	severity := map[string]int{}
	signal := map[string]int{}
	total := map[string]int{}
	group := func(a action) string { return strings.TrimSuffix(a.key, "\x00beyond") }
	for _, a := range actions {
		g := group(a)
		if w, ok := worst[g]; !ok || moreUrgentBand(a.priority, w) {
			worst[g] = a.priority
		}
		for _, f := range a.findings {
			severity[g] = max(severity[g], rankedSeverity(f).Rank())
			signal[g] = max(signal[g], exploitationSignal(f))
		}
		total[g] += a.count()
	}
	out := make([]rankedAction, len(actions))
	for i := range actions {
		g := group(actions[i])
		out[i] = rankedAction{action: &actions[i], priority: worst[g], severity: severity[g],
			signal: signal[g], count: total[g], group: g, beyond: actions[i].key != g}
	}
	return out
}

// exploitationSignal ranks the evidence that a finding's flaw is exploited: 2 when it is on KEV, 1
// when EPSS raised it, 0 otherwise. KEV outranks EPSS wherever both fire, so the signal that set
// the rating is the strongest one.
func exploitationSignal(f finding) int {
	if f.escalation == nil {
		return 0
	}
	switch f.escalation.Signal {
	case "kev":
		return 2
	case "epss":
		return 1
	}
	return 0
}

// commonComponent is the component every finding belongs to, or "" where they differ.
func commonComponent(fs []finding) string {
	if len(fs) == 0 {
		return ""
	}
	c := fs[0].component
	for _, f := range fs[1:] {
		if f.component != c {
			return ""
		}
	}
	return c
}

// moreUrgent orders actions by the worst priority they clear, then by the evidence that what they
// clear is exploited, then by its worst severity, then by how many findings that is.
//
// Priority first, always. An action clearing one P1 outranks one clearing forty P4s, because a P1
// is not something to trade away for volume. Inside a band, exploitation evidence comes next: a
// flaw on KEV has been used against somebody, and EPSS estimates that it will be, which no rating
// of how bad a flaw would be can say. Then severity, the rating the band was computed from. Count
// decides only between actions alike in all three, because a scanner that reports one finding per
// package per advisory makes volume a measure of how it splits its output more than of urgency.
func moreUrgent(a, b rankedAction) bool {
	if a.priority != b.priority {
		return moreUrgentBand(a.priority, b.priority)
	}
	if a.signal != b.signal {
		return a.signal > b.signal
	}
	if a.severity != b.severity {
		return a.severity > b.severity
	}
	if a.count != b.count {
		return a.count > b.count
	}
	// Two steps of one upgrade: the one within the policy first, because the other presumes it.
	return a.group == b.group && !a.beyond && b.beyond
}

// moreUrgentBand reports whether band a outranks band b. An unprioritized finding has no band to
// compare, and sorts last rather than first: "" is lexically below "P1" and would otherwise lead.
func moreUrgentBand(a, b string) bool {
	switch {
	case a == b:
		return false
	case a == "":
		return false
	case b == "":
		return true
	}
	return a < b
}

// actionFor returns the key two findings share when one fix clears both, how to say it, and the
// kind of work it is. byRule reports an action titled by the name of the rule it groups on, which is
// the one kind of title that does not say what is wrong.
//
// The kind is decided here, by the same case that decides the title, so the two cannot disagree
// about what an action is.
func actionFor(f finding) (key, title string, kind skald.ActionKind, byRule bool) {
	switch {
	// The licenses in an image or a repository somebody else publishes are one review. Nobody running
	// the scan can swap a package inside it, so what is left is to read what it carries and decide
	// whether that is acceptable to ship, once for the whole of it.
	//
	// Before the upstream cases below, which would title this "Update" and send the reader for a
	// newer version carrying the same licenses.
	case f.control == "licenses" && f.builtUpstream && licenseUnit(f) != "":
		return "licenses\x00" + licenseUnit(f), "Review the licenses in " + licenseUnit(f), skald.KindDecide, false

	// A license in the reader's own dependencies is a decision about one package: replace it, or
	// accept the terms it comes with. No version is named, because no version changes a license.
	case f.control == "licenses":
		return f.control + "\x00" + f.ruleID, licenseTitle(f), skald.KindDecide, false

	// An image somebody else publishes is one action however many packages are wrong inside it,
	// and the action is the image. Nobody running the scan can upgrade a library they do not
	// build: the fix is a newer image, or a wait for whoever publishes it. Grouping these by
	// package would scatter one action, take a newer redis, across every library in it, and
	// name none of them something the reader can do.
	//
	// Before the package case, because a finding is both: it names a package, and the package is
	// not the unit of work here.
	case f.builtUpstream && f.control == "images" && f.location != "":
		// The image is the title, so the row does not repeat it below, and the reason it is the
		// unit of work goes in the meta as one word rather than a clause on every line.
		return "image\x00" + f.location, "Update " + displayLocation(f), skald.KindWait, false

	// The same argument one level up, for a repository somebody else publishes. The unit of work is
	// their software, not a file inside it: keying on the location here would title the action
	// "Update requirements.txt", which is an instruction to edit a file in a repository the reader
	// cannot push to, precisely the advice declaring `builtBy: upstream` exists to stop.
	//
	// Falls back to the component when the repository is a local path, which is what a scan of a
	// checkout reports. "Update ." names nothing.
	case f.builtUpstream && upstreamUnit(f) != "":
		return "upstream\x00" + upstreamUnit(f), "Update " + upstreamUnit(f), skald.KindWait, false

	// An upgrade is one action however many vulnerabilities it resolves, which is the case that
	// pays off most: a library a year out of date carries a dozen findings and one fix.
	//
	// Keyed on the package rather than on the version that fixes it. Advisories disagree about which
	// release resolves them, three findings in one library can name three different fixed versions,
	// and treating those as three actions describes one upgrade as three, which is the grouping
	// failure this exists to remove.
	//
	// One per component and installed version. Two components are two owners, and a row naming
	// one version over a second copy at another is wrong about the second.
	case f.pkg != nil && f.pkg.Name != "" && f.pkg.FixedVersion != "":
		return "upgrade\x00" + packageUnit(f),
			fmt.Sprintf("Upgrade %s %s", f.pkg.Name, f.pkg.Version), skald.KindBump, false

	// A dependency nobody has fixed yet. Still one decision per package rather than one per
	// advisory, and still an action: there is no version to move to, so the choice is to replace
	// the library, to accept it, or to wait, and a reader has to make it once for the package.
	//
	// Without this the finding falls through to its own rule and the row is titled with the
	// advisory's description of the flaw, which describes what is wrong and never says what to do.
	case f.pkg != nil && f.pkg.Name != "" && f.remediation != sarif.RemediationUpstream:
		return "nofix\x00" + packageUnit(f),
			fmt.Sprintf("Replace or accept %s %s, no fix available", f.pkg.Name, f.pkg.Version), skald.KindWait, false

	// Nothing fixes these where they are, and the release underneath is the fix, one move for every
	// finding in that layer, and usually the largest single reduction available.
	case f.remediation == sarif.RemediationUpstream && f.operatingSystem != "":
		return "os\x00" + f.operatingSystem,
			fmt.Sprintf("Move off %s, past end of service life, so no fix is coming",
				f.operatingSystem), skald.KindDecide, false

	// A flaw in the code is one edit at one line, however many rules recognize it. SAST rules
	// overlap: a shell command built from request input is Bandit's B602 and three Semgrep rules,
	// and a row per rule shows one bug as four chores, each ranked as though it cleared one finding.
	// A rule that flags many lines is as many actions, because each line is its own edit.
	//
	// One per component and repository, as a dependency is. Paths are repository-relative, so two
	// repositories' main.go:12 are two files, and two components are two owners.
	//
	// The title is provisional. It describes the whole line, so groupActions writes it once every
	// finding on the line is known.
	case onALine(f):
		title, _ := lineTitle([]finding{f})
		return lineKey + f.component + "\x00" + f.repository + "\x00" + f.location, title, ruleKind(f), false

	// The same rule in several places is one thing to understand and apply, whether that is a
	// missing directive in three Dockerfiles or a credential committed to four files.
	default:
		return f.control + "\x00" + f.ruleID, titleFor(f), ruleKind(f), true
	}
}

// ruleKind is the kind of work an action grouped on a rule is, from the control that found it and
// the verb its title takes. A control that could be either code or infrastructure counts as code.
func ruleKind(f finding) skald.ActionKind {
	switch {
	case f.control == "secrets":
		return skald.KindCredential
	case f.control == "threats":
		return skald.KindCode
	case f.hasScore && f.score < informationalBelow:
		return skald.KindDecide
	case f.control == "iac" || f.control == "kubernetes" || f.control == "cloud":
		return skald.KindInfrastructure
	}
	return skald.KindCode
}

// lineKey opens the key of an action for one line of code.
const lineKey = "line\x00"

// onALine reports whether a finding is a flaw at one line of code, which is one edit however many
// rules recognize it. A SAST finding without a line is about a whole file or none, and keeps the
// grouping on its rule.
func onALine(f finding) bool {
	return f.control == "sast" && lineSuffix.MatchString(f.location)
}

// atOneLine reports whether the action is every finding at one line of code.
func (a action) atOneLine() bool { return strings.HasPrefix(a.key, lineKey) }

// componentRepositories maps each component whose findings all name one repository to that
// repository. A component whose findings name two has no entry, because then a path alone does not
// say which repository's file it is.
func componentRepositories(fs []finding) map[string]string {
	out := map[string]string{}
	many := map[string]bool{}
	for _, f := range fs {
		if f.repository == "" || many[f.component] {
			continue
		}
		if r, ok := out[f.component]; ok && r != f.repository {
			delete(out, f.component)
			many[f.component] = true
			continue
		}
		out[f.component] = f.repository
	}
	return out
}

// lineTitle is what to do about one line of code, and the description to print under the title
// when the title does not carry it.
//
// The verb, then the scanner's own one-line description of the flaw, quoted, because it is the
// scanner's wording and often not a sentence of its own. titleFinding says which finding's
// description it is. A line one rule flags, whose description would be cut short, is titled by the
// rule's name instead, with the description whole under it, the shape of every action named for a
// rule. Where several rules flag the line, the title quotes one of them, cut if it must be, because
// the rule's name would leave the others out.
func lineTitle(fs []finding) (title, summary string) {
	f := titleFinding(fs)
	d := describe(f)
	switch {
	case d != "" && f.ruleID != "" && !fitsTitle(f, d) && oneRule(fs):
		return truncate(actionVerb(f)+" "+shortRuleName(f.ruleID), actionTitleWidth), d
	case d != "":
		return quoted(actionVerb(f)+" ", d, actionTitleWidth), ""
	case f.ruleID != "":
		return truncate(actionVerb(f)+" "+shortRuleName(f.ruleID), actionTitleWidth), ""
	}
	return truncate(actionVerb(f)+" "+f.location, actionTitleWidth), ""
}

// oneRule reports whether every finding is the same scanner's same rule.
func oneRule(fs []finding) bool {
	for _, f := range fs[1:] {
		if f.tool != fs[0].tool || f.ruleID != fs[0].ruleID {
			return false
		}
	}
	return true
}

// quoted is prefix, then text in quotation marks, within width. Where the whole does not fit, the
// quoted text gives way and the closing mark stays, so a title cut short still reads as a quotation
// that ends.
func quoted(prefix, text string, width int) string {
	whole := prefix + "“" + text + "”"
	if utf8.RuneCountInString(whole) <= width {
		return whole
	}
	room := width - utf8.RuneCountInString(prefix) - 2
	if room < 2 {
		return truncate(whole, width)
	}
	return prefix + "“" + truncate(text, room) + "”"
}

// titleFinding is the finding whose description titles an action for one line.
//
// Several rules on one line describe it differently, and the choice is made by rule rather than by
// whichever scanner finished first, so a line is titled the same on every run:
//
//   - the worst band, then the highest severity, then the highest score, so the title describes
//     what the row is ranked for;
//   - among findings that rank alike, a description that fits the title whole, because one cut
//     short loses the end of the sentence, which is where it says what is wrong;
//   - then the longest description, the one that says the most about the line;
//   - then the lowest rule id, which only two equally long descriptions reach.
func titleFinding(fs []finding) finding {
	best := fs[0]
	for _, f := range fs[1:] {
		if titlesBetter(f, best) {
			best = f
		}
	}
	return best
}

// titlesBetter reports whether a's description is the better title for a line than b's.
func titlesBetter(a, b finding) bool {
	if ra, rb := prioritization.Priority(a.priority).Rank(), prioritization.Priority(b.priority).Rank(); ra != rb {
		return ra > rb
	}
	if sa, sb := severityRank(rankedSeverity(a)), severityRank(rankedSeverity(b)); sa != sb {
		return sa > sb
	}
	if a.score != b.score {
		return a.score > b.score
	}
	da, db := describe(a), describe(b)
	if fa, fb := fitsTitle(a, da), fitsTitle(b, db); fa != fb {
		return fa
	}
	if la, lb := utf8.RuneCountInString(da), utf8.RuneCountInString(db); la != lb {
		return la > lb
	}
	return a.ruleID < b.ruleID
}

// fitsTitle reports whether a finding's description fits a line action's title without being cut.
func fitsTitle(f finding, description string) bool {
	return utf8.RuneCountInString(actionVerb(f)+" “"+description+"”") <= actionTitleWidth
}

// toolRules is one scanner's rules among an action's findings.
type toolRules struct {
	// tool is the scanner as the scanner names itself, without its edition unless the edition is
	// what tells two scanners on the line apart.
	tool string
	// rules holds one finding per distinct rule, for its id and the link to its documentation.
	rules []finding
}

// rulesByTool lists the distinct rules an action's findings carry, grouped by the scanner that
// reported them. The rule the title quotes comes first, so the line under a title opens with its
// source, and the rest follow in the order the findings rank.
func (a action) rulesByTool() []toolRules {
	if len(a.findings) == 0 {
		return nil
	}
	var out []toolRules
	index := map[string]int{}
	seen := map[string]bool{}
	for _, f := range append([]finding{titleFinding(a.findings)}, a.findings...) {
		if f.ruleID == "" || seen[f.tool+"\x00"+f.ruleID] {
			continue
		}
		seen[f.tool+"\x00"+f.ruleID] = true
		i, ok := index[f.tool]
		if !ok {
			i = len(out)
			index[f.tool] = i
			out = append(out, toolRules{tool: f.tool})
		}
		out[i].rules = append(out[i].rules, f)
	}
	named := map[string]int{}
	for _, g := range out {
		named[withoutEdition(g.tool)]++
	}
	for i, g := range out {
		if named[withoutEdition(g.tool)] == 1 {
			out[i].tool = withoutEdition(g.tool)
		}
	}
	return out
}

// ruleIDs are the first most distinct rules the action clears. For a line of code they are in the
// order the line under its title lists them, so the first is the rule the title quotes; for any
// other action, in the order its findings rank.
func (a action) ruleIDs(most int) []string {
	fs := a.findings
	if a.atOneLine() {
		fs = nil
		for _, g := range a.rulesByTool() {
			fs = append(fs, g.rules...)
		}
	}
	out := make([]string, 0, most)
	seen := map[string]bool{}
	for _, f := range fs {
		if seen[f.ruleID] || f.ruleID == "" {
			continue
		}
		seen[f.ruleID] = true
		if len(out) == most {
			break
		}
		out = append(out, f.ruleID)
	}
	return out
}

// withoutEdition is a scanner's name without the edition it reports beside it: Semgrep for
// "Semgrep OSS". The edition is the same word on every row a scanner flags, and --evidence records
// which build ran.
func withoutEdition(tool string) string {
	return strings.TrimSuffix(tool, " OSS")
}

// titleFor writes the imperative for a finding that is its own action: a verb, then the rule.
//
// The verb is Draugr's and the rule's name is the scanner's. A scanner's message describes what is
// wrong, "Privileged", "By not specifying a USER, a program in the container may run as 'root'",
// and a list of those under a heading promising things to do reads as a list of complaints. The
// verb is the part a scanner never writes, and the rule's name is the part it always does.
func titleFor(f finding) string {
	name, said := ruleName(f.ruleID, f.message)
	switch {
	case name == "":
		return truncate(firstSentence(f.message), actionTitleWidth)
	case said != "":
		return quoted(actionVerb(f)+" "+name+" ", said, actionTitleWidth)
	}
	return truncate(actionVerb(f)+" "+name, actionTitleWidth)
}

// actionVerb is what a reader does about a rule's findings.
//
// A committed credential is not fixed by editing the file: it is already in the history and
// in every clone of it, so the action is to take it out and to replace it wherever it is used.
// A host on a threat feed is somebody else's, and what the reader can do is find out why the
// application talks to it. A finding scored below low is information a scanner reports about a
// target, a certificate's issuer or a detected technology, and there is nothing in it to fix.
func actionVerb(f finding) string {
	switch {
	case f.control == "secrets":
		return "Remove and rotate"
	case f.control == "threats":
		return "Investigate"
	case f.hasScore && f.score < informationalBelow:
		return "Review"
	default:
		return "Fix"
	}
}

// informationalBelow is the score under which a finding reports a fact rather than a flaw. Nuclei's
// info templates score 1.0, and its low ones 2.0.
const informationalBelow = 2

// summaryFor is the one line saying what an action's rule found, or "" when the title already says
// it or the findings do not agree on one.
//
// The rule's published description where it has one, because it describes the rule rather than one
// occurrence. The first finding's message otherwise, and only when every finding's says the same:
// "Certificate expires in 27 day(s)" is true of one host and false of the next.
func summaryFor(a action) string {
	if len(a.findings) == 0 || strings.Contains(a.title, "“") {
		return ""
	}
	sum := describe(a.findings[0])
	for _, f := range a.findings[1:] {
		if describe(f) != sum {
			return ""
		}
	}
	if sum == "" || truncate(sum, actionTitleWidth) == a.title {
		return ""
	}
	return sum
}

// describe is what a finding's rule is about, in one sentence.
//
// A rule description that names the rule's own id is a scanner filling the field rather than
// describing anything. Semgrep's reads "Semgrep Finding: <id>", and the message says more.
func describe(f finding) string {
	if d := f.ruleSummary; d != "" && !strings.Contains(d, f.ruleID) {
		return firstSentence(d)
	}
	return firstSentence(f.message)
}

// licenseUnit names the image or repository whose licenses are one review.
func licenseUnit(f finding) string {
	if f.image != "" {
		return displayImage(f.image)
	}
	return upstreamUnit(f)
}

// licenseTitle is the decision a license finding in the reader's own code asks for.
//
// The rule id carries the package, `license/<spdx>/<package>`, and the package name may itself
// hold slashes, so the license is the segment after the prefix and the package everything after
// that. A license Trivy read from a file rather than a package has no package segment.
func licenseTitle(f finding) string {
	rest, ok := strings.CutPrefix(f.ruleID, "license/")
	if !ok || rest == "" {
		return truncate(firstSentence(f.message), actionTitleWidth)
	}
	spdx, pkg, ok := strings.Cut(rest, "/")
	if !ok || pkg == "" {
		return truncate("Review the files licensed "+spdx, actionTitleWidth)
	}
	return truncate("Replace or accept "+pkg+", licensed "+spdx, actionTitleWidth)
}

// ruleName is what a rule is called, in the words a reader can recognize it by.
//
// Rule identifiers come in three shapes, and each says its name in a different place:
//
//   - A namespaced path, "headers/csp-unsafe-inline" or Semgrep's
//     "dockerfile.security.missing-user.missing-user". The last segment is the name and the rest
//     is where the scanner files it.
//   - A slug, "private-key" or "tls-cert-expired", which is already a name.
//   - A catalog number, "KSV-0017", "DS-0002", a CIS section. It names nothing to somebody who has
//     not looked it up, so said is the scanner's one-line summary, which the title quotes beside
//     it, because it is the scanner's wording and often not a sentence of its own.
//
// Empty when the finding has no rule, which leaves the title to the message.
func ruleName(id, message string) (name, said string) {
	name = shortRuleName(id)
	if name == "" || hasLower(name) {
		return name, ""
	}
	if summary := firstSentence(message); summary != "" && summary != id {
		return name, summary
	}
	return name, ""
}

// shortRuleName is the part of a rule id that names the rule: the last segment of a namespaced
// path, and the id itself for a slug or a catalog number.
func shortRuleName(id string) string {
	name := id
	if i := strings.LastIndexByte(name, '/'); i >= 0 && i < len(name)-1 {
		name = name[i+1:]
	}
	// Only a dotted path whose last segment is a word. A CIS section, "1.2.3", is dotted too, and
	// its last segment is a number, not a name.
	if i := strings.LastIndexByte(name, '.'); i >= 0 && hasLower(name[i+1:]) {
		name = name[i+1:]
	}
	return name
}

// hasLower reports whether s holds a lowercase letter, the tell of a name rather than a number
// somebody assigned.
func hasLower(s string) bool {
	return strings.IndexFunc(s, unicode.IsLower) >= 0
}

// firstSentence is the opening sentence of a scanner's message, the part written to be read on
// its own.
func firstSentence(msg string) string {
	s := strings.TrimSpace(msg)
	// First line only. A scanner's message often carries a paragraph after it.
	if i := strings.IndexByte(s, '\n'); i > 0 {
		s = strings.TrimSpace(s[:i])
	}
	// A doubled space inside a line reads as a typo on a terminal.
	s = strings.Join(strings.Fields(s), " ")
	// A sentence boundary is a full stop followed by a space. Splitting on the full stop alone cuts
	// "str.format_map" to "str" and a version to its major, the punctuation inside an identifier
	// looks exactly like the punctuation at the end of a sentence.
	for from := 0; ; {
		i := strings.Index(s[from:], ". ")
		if i < 0 {
			// The last sentence ends at the end of the message, and its full stop goes the same way
			// the others do.
			if t := strings.TrimSuffix(s, "."); t != s && !abbreviation(t) {
				return t
			}
			return s
		}
		i += from
		if i > 0 && !abbreviation(s[:i]) {
			return s[:i]
		}
		from = i + 2
	}
}

// abbreviation reports whether the word ending s is an abbreviation, whose full stop ends the word
// rather than the sentence: single letters, each followed by a full stop, "e.g" or "i.e" or an
// initial. "str.format_map" is not one, and ends a sentence as often as anything else does.
func abbreviation(s string) bool {
	word := s[strings.LastIndexAny(s, " (")+1:]
	for part := range strings.SplitSeq(word, ".") {
		if r := []rune(part); len(r) != 1 || !unicode.IsLetter(r[0]) {
			return false
		}
	}
	return true
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

// fixedVersions lists the releases the findings say resolve them, in the order first seen: each
// advisory's own answer, which target combines into one where the ecosystem's order allows.
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

// target is the version to move to, or "" when there is no one answer.
//
// For an upgrade, the lowest release that clears every finding, by the package's own ecosystem's
// order. For any other action, the release only when every advisory in it names the same one: an
// image's findings are in many packages, and no one package's release is the image's fix.
func (a action) target() string {
	if a.step != nil && a.step.target != "" {
		return a.step.target
	}
	if strings.HasPrefix(a.key, "upgrade\x00") {
		return upgradeTarget(a.findings)
	}
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

// Action is one thing to do and what doing it clears, for a consumer outside this package. The
// shape is skald's, so report.json can carry it; ActionsFor is what fills it.
type Action = skald.Action

// ActionFinding is one finding an action clears.
type ActionFinding = skald.ActionFinding

// ActionLocation is one place an action applies to.
type ActionLocation = skald.ActionLocation

// ActionsFor groups a run's findings into the fix list, most urgent first.
//
// The one implementation of the fix list. The console's "What to do", the HTML report,
// report.json's actions and the MCP server's fix_list all come from groupActions over findings
// built by findingOf, so a scan describes the same actions, grouped the same way and clearing the
// same counts, wherever it is read.
//
// Suppressed findings are left out for the same reason the console leaves them out: an excluded
// finding is a decision somebody recorded, and proposing it as work is proposing to undo that
// decision without the reason they gave.
//
// Keyed by control, as a run holds them, because the grouping keys on it: two controls reporting
// the same rule id are two things to do, and an image's packages and its licenses are two actions.
// A caller holding a merged results.sarif passes it as one entry under any name, and each result's
// own control, which the file carries, is used instead.
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
			// A flaw another scanner's finding is already counted for, skipped as the console skips
			// it. Counted twice, one library's advisories would clear more findings here than the
			// console says exist.
			if res.Suppressed() || res.Correlated() {
				continue
			}
			findings = append(findings, findingOf(name, rep, res))
		}
	}
	sortFindings(findings)

	grouped, external := groupActions(findings, nil)
	out := make([]Action, 0, len(grouped)+len(external))
	for _, a := range grouped {
		rules := a.ruleIDs(most)
		act := Action{
			ID:            a.id(),
			Title:         a.title,
			Kind:          a.kind,
			Summary:       a.summary,
			Component:     a.component,
			Control:       a.control,
			Priority:      a.priority,
			Clears:        a.count(),
			Upstream:      a.upstream,
			Where:         a.where(most),
			RuleIDs:       rules,
			Key:           a.key,
			FixedVersions: a.fixedVersions(),
			Target:        a.target(),
			Locations:     a.locations(),
			Fingerprints:  fingerprintsOf(a.findings),
			Findings:      actionFindings(a.findings),
			OneChange:     !a.byRule,
		}
		if p := a.dependency(); p != nil {
			act.Ecosystem, act.Package, act.From = p.Ecosystem, p.Name, p.Version
			act.Versioning = ecosystemName(a)
		}
		if s := a.step; s != nil {
			act.Policy = string(s.policy)
			if s.applies {
				within := s.beyond == ""
				act.WithinPolicy = &within
				act.After = s.after
				act.Beyond = string(s.beyond)
			} else {
				applies := false
				act.PolicyApplies = &applies
			}
		}
		out = append(out, act)
	}
	return out
}

// Cleared is how many findings a set of actions resolves between them, each counted once: the
// figure the console's "What to do" heading gives for the rows it lists.
//
// Counted by identity rather than summed, so the figure cannot exceed the findings it describes
// whatever the grouping does. Each finding is in exactly one action, which makes the two equal; a
// grouping that put one finding in two actions would otherwise count it twice. Read from each
// action's Fingerprints, which ActionsFor fills.
func Cleared(actions []Action) int {
	groups := make([][]string, len(actions))
	for i, a := range actions {
		groups[i] = a.Fingerprints
	}
	return distinctFindings(groups)
}

// distinctFindings counts the distinct fingerprints across groups.
func distinctFindings(groups [][]string) int {
	seen := map[string]bool{}
	for _, g := range groups {
		for _, fp := range g {
			seen[fp] = true
		}
	}
	return len(seen)
}

// fingerprintsOf is each finding's fingerprint, in the order the action holds them.
func fingerprintsOf(fs []finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.fingerprint)
	}
	return out
}

// actionFindings is the exported view of an action's findings, in the order the action holds them.
func actionFindings(fs []finding) []ActionFinding {
	out := make([]ActionFinding, 0, len(fs))
	for _, f := range fs {
		out = append(out, ActionFinding{
			Control: f.control, RuleID: f.ruleID, Tool: f.tool, Priority: f.priority,
			Severity: f.severity, Message: f.message, Component: f.component,
			Repository: f.repository, Location: f.location, HelpURI: f.helpURI,
			Fingerprint: f.fingerprint, Upgrade: upgradeLabel(f),
		})
	}
	return out
}

// packageUnit is what makes two dependency findings one action: the same component, ecosystem,
// package and installed version.
func packageUnit(f finding) string {
	return f.component + "\x00" + f.pkg.Ecosystem + "\x00" + f.pkg.Name + "\x00" + f.pkg.Version
}

// upstreamUnit names the thing a reader would have to take a newer version of.
//
// The repository where it identifies one, and the component otherwise, a scan of a local checkout
// records the path it was given, and "." is not something anybody can go and update. Empty when
// neither is known, which leaves the finding to the ordinary package and code cases below rather
// than titling an action after nothing.
func upstreamUnit(f finding) string {
	if r := f.repository; r != "" && r != "." && !strings.HasPrefix(r, "/") && !strings.HasPrefix(r, ".") {
		return shortRepository(r)
	}
	return f.component
}
