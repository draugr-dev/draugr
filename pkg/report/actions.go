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

	"github.com/draugr-dev/draugr/internal/manifests"
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
	spans := len(a.repositories()) > 1
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

	for _, f := range findings {
		if f.remediation == sarif.RemediationExternal {
			external = append(external, f)
			continue
		}
		key, title, byRule := actionFor(f)
		a, seen := byKey[key]
		if !seen {
			a = &action{key: key, title: title, control: f.control, priority: f.priority, byRule: byRule}
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
		if a.byRule {
			a.summary = summaryFor(a)
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

// rankedAction is an action and what it is ranked by: its own band and count, or for one step of
// an upgrade the policy split, the package's.
type rankedAction struct {
	*action
	priority string
	count    int
	group    string
	beyond   bool
}

// packageRanks pairs each action with what it is ranked by. The steps of one package's upgrade
// rank together, by the worst band either clears and the findings both clear, so the major step
// that clears the urgent findings is read beside the minor step it follows.
func packageRanks(actions []action) []rankedAction {
	worst := map[string]string{}
	total := map[string]int{}
	group := func(a action) string { return strings.TrimSuffix(a.key, "\x00beyond") }
	for _, a := range actions {
		g := group(a)
		if w, ok := worst[g]; !ok || moreUrgentBand(a.priority, w) {
			worst[g] = a.priority
		}
		total[g] += a.count()
	}
	out := make([]rankedAction, len(actions))
	for i := range actions {
		g := group(actions[i])
		out[i] = rankedAction{action: &actions[i], priority: worst[g], count: total[g], group: g,
			beyond: actions[i].key != g}
	}
	return out
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

// moreUrgent orders actions by the worst priority they clear, then by how many findings that is.
//
// Priority first, always. An action clearing one P1 outranks one clearing forty P4s, because a P1
// is not something to trade away for volume. Sorting by count first would bury the urgent work
// under the plentiful kind.
func moreUrgent(a, b rankedAction) bool {
	if a.priority != b.priority {
		return moreUrgentBand(a.priority, b.priority)
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

// actionFor returns the key two findings share when one fix clears both, and how to say it.
// byRule reports an action titled by the name of the rule it groups on, which is the one kind of
// title that does not say what is wrong.
func actionFor(f finding) (key, title string, byRule bool) {
	switch {
	// The licenses in an image or a repository somebody else publishes are one review. Nobody running
	// the scan can swap a package inside it, so what is left is to read what it carries and decide
	// whether that is acceptable to ship, once for the whole of it.
	//
	// Before the upstream cases below, which would title this "Update" and send the reader for a
	// newer version carrying the same licenses.
	case f.control == "licenses" && f.builtUpstream && licenseUnit(f) != "":
		return "licenses\x00" + licenseUnit(f), "Review the licenses in " + licenseUnit(f), false

	// A license in the reader's own dependencies is a decision about one package: replace it, or
	// accept the terms it comes with. No version is named, because no version changes a license.
	case f.control == "licenses":
		return f.control + "\x00" + f.ruleID, licenseTitle(f), false

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
		return "image\x00" + f.location, "Update " + displayLocation(f), false

	// The same argument one level up, for a repository somebody else publishes. The unit of work is
	// their software, not a file inside it: keying on the location here would title the action
	// "Update requirements.txt", which is an instruction to edit a file in a repository the reader
	// cannot push to, precisely the advice declaring `builtBy: upstream` exists to stop.
	//
	// Falls back to the component when the repository is a local path, which is what a scan of a
	// checkout reports. "Update ." names nothing.
	case f.builtUpstream && upstreamUnit(f) != "":
		return "upstream\x00" + upstreamUnit(f), "Update " + upstreamUnit(f), false

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
			fmt.Sprintf("Upgrade %s %s", f.pkg.Name, f.pkg.Version), false

	// A dependency nobody has fixed yet. Still one decision per package rather than one per
	// advisory, and still an action: there is no version to move to, so the choice is to replace
	// the library, to accept it, or to wait, and a reader has to make it once for the package.
	//
	// Without this the finding falls through to its own rule and the row is titled with the
	// advisory's description of the flaw, which describes what is wrong and never says what to do.
	case f.pkg != nil && f.pkg.Name != "" && f.remediation != sarif.RemediationUpstream:
		return "nofix\x00" + packageUnit(f),
			fmt.Sprintf("Replace or accept %s %s, no fix available", f.pkg.Name, f.pkg.Version), false

	// Nothing fixes these where they are, and the release underneath is the fix, one move for every
	// finding in that layer, and usually the largest single reduction available.
	case f.remediation == sarif.RemediationUpstream && f.operatingSystem != "":
		return "os\x00" + f.operatingSystem,
			fmt.Sprintf("Move off %s, past end of service life, so no fix is coming",
				f.operatingSystem), false

	// The same rule in several places is one thing to understand and apply, whether that is a
	// missing directive in three Dockerfiles or a credential committed to four files.
	default:
		return f.control + "\x00" + f.ruleID, titleFor(f), true
	}
}

// titleFor writes the imperative for a finding that is its own action: a verb, then the rule.
//
// The verb is Draugr's and the rule's name is the scanner's. A scanner's message describes what is
// wrong, "Privileged", "By not specifying a USER, a program in the container may run as 'root'",
// and a list of those under a heading promising things to do reads as a list of complaints. The
// verb is the part a scanner never writes, and the rule's name is the part it always does.
func titleFor(f finding) string {
	name := ruleName(f.ruleID, f.message)
	if name == "" {
		return truncate(firstSentence(f.message), actionTitleWidth)
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
//     not looked it up, so the scanner's one-line summary goes beside it, quoted, because it is
//     the scanner's wording and often not a sentence of its own.
//
// Empty when the finding has no rule, which leaves the title to the message.
func ruleName(id, message string) string {
	name := id
	if i := strings.LastIndexByte(name, '/'); i >= 0 && i < len(name)-1 {
		name = name[i+1:]
	}
	// Only a dotted path whose last segment is a word. A CIS section, "1.2.3", is dotted too, and
	// its last segment is a number, not a name.
	if i := strings.LastIndexByte(name, '.'); i >= 0 && hasLower(name[i+1:]) {
		name = name[i+1:]
	}
	if name == "" || hasLower(name) {
		return name
	}
	if summary := firstSentence(message); summary != "" && summary != id {
		return name + " “" + summary + "”"
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
// Suppressed findings are left out for the same reason the console leaves them out: an excluded
// finding is a decision somebody recorded, and proposing it as work is proposing to undo that
// decision without the reason they gave.
//
// Keyed by control, as a run holds them, because the grouping keys on it: two controls reporting
// the same rule id are two things to do. A caller holding only a merged results.sarif has no
// control to give and can pass a single entry under "", grouping then falls back to the rule id,
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
			// A flaw another scanner's finding is already counted for, skipped as the console skips
			// it. Counted twice, one library's advisories would clear more findings here than the
			// console says exist.
			if res.Suppressed() || res.Correlated() {
				continue
			}
			findings = append(findings, finding{
				control: name, ruleID: res.RuleID, tool: res.Tool, priority: res.Priority,
				fingerprint: res.Fingerprint(),
				component:   res.Component, repository: res.Repository,
				location: locationOf(res), message: res.Message,
				level: res.Level, severity: res.Severity(""),
				helpURI: rep.HelpURI(res.RuleID),
				score:   res.Score, hasScore: res.HasScore,
				remediation:     res.Remediation(),
				builtUpstream:   res.BuiltUpstream,
				pkg:             res.Package,
				operatingSystem: res.OperatingSystem,
				upgradePolicy:   res.UpgradePolicy,
				image:           res.Image,
				ruleSummary:     rep.Rules[res.RuleID].ShortDescription,
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
		act := Action{
			ID:            a.id(),
			Title:         a.title,
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
		}
		if s := a.step; s != nil {
			act.Policy = string(s.policy)
			if s.applies {
				within := s.beyond == ""
				act.WithinPolicy = &within
				act.After = s.after
			} else {
				applies := false
				act.PolicyApplies = &applies
			}
		}
		out = append(out, act)
	}
	return out
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
