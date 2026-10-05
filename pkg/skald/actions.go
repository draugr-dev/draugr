package skald

import "github.com/draugr-dev/draugr/pkg/sarif"

// Action is one thing to do and what doing it clears, as report.json and the MCP server carry it.
//
// Declared here so the document can hold it; the grouping that produces one is report.ActionsFor.
// The keying is the subtle part. Which findings are one fix and which only look alike, and a second
// implementation of it would drift from that one silently, leaving an assistant and a terminal
// describing the same report differently.
type Action struct {
	// ID identifies the action across runs: the same findings grouped the same way, toward the same
	// target, get the same ID. A dependency action's is derived from its component, package,
	// installed version and target, so it changes when any of them does.
	ID string `json:"id"`
	// Title is what to do, in the imperative.
	Title string `json:"title"`
	// Summary is the scanner's one-line description of what is wrong, for an action whose title
	// names a rule rather than saying what it found. Empty where the title says it already.
	Summary string `json:"summary,omitempty"`
	// Component every finding belongs to. A dependency action is always one component's; an action
	// grouped on a rule or an image can span several, and then this is empty.
	Component string `json:"component,omitempty"`
	// Control the findings came from, and the worst priority among them.
	Control  string `json:"control,omitempty"`
	Priority string `json:"priority,omitempty"`
	// Clears is how many findings this one action resolves.
	Clears int `json:"clears"`
	// Upstream marks an action whose unit of work is something somebody else publishes: the fix
	// is to take a newer one, not to change anything inside it.
	Upstream bool `json:"upstream,omitempty"`
	// Ecosystem, Package and From name the dependency and the version installed, for an action
	// that upgrades or replaces one. Empty for every other action.
	Ecosystem string `json:"ecosystem,omitempty"`
	Package   string `json:"package,omitempty"`
	From      string `json:"from,omitempty"`
	// Target is the one version to move to. For an upgrade it is the lowest release that clears
	// every finding, by the package's own ecosystem's order. Empty when no one release can be named,
	// for an ecosystem Draugr cannot order or for an image whose findings are in many packages.
	Target string `json:"target,omitempty"`
	// FixedVersions are the releases the advisories name as fixing these findings, in the order
	// first seen, each advisory's own answer.
	FixedVersions []string `json:"fixedVersions,omitempty"`
	// Locations are every distinct place the findings are, in the order first seen.
	Locations []ActionLocation `json:"locations,omitempty"`
	// Where lists the same places as text, capped, the way the console names them.
	Where []string `json:"where,omitempty"`
	// RuleIDs are the rules this action resolves, capped, so a caller can look any of them up.
	RuleIDs []string `json:"ruleIds,omitempty"`
	// Findings are every finding this action clears, most urgent first, uncapped where Where and
	// RuleIDs are capped.
	Findings []ActionFinding `json:"findings,omitempty"`
	// Key is what these findings grouped under: the identity that makes two of them one action.
	//
	// Opaque, and deliberately. Its shape is report's business and changes when the grouping
	// does. What it is for is membership: a caller holding the findings can ask which action each
	// one belongs to and match on this, instead of inferring it from a title. Title is written for a
	// reader and is not an identity, an action fed by two controls takes one of their names, and
	// matching on that silently drops the other's findings.
	//
	// Not serialized. It is an identity for a caller holding report's own output in memory, and it
	// contains a separator that has no business in a JSON document. ID is the serialized identity.
	Key string `json:"-"`
	// OneChange marks an action that one change resolves: an upgrade, a newer image, a license
	// review. Its findings are what the change clears. An action for a rule has each finding at a
	// place that needs its own edit.
	OneChange bool `json:"-"`
}

// The kinds of place an action applies to.
const (
	// LocationManifest is a file somebody edits to declare a dependency: package.json, go.mod,
	// requirements.txt.
	LocationManifest = "manifest"
	// LocationLockfile is a file a package manager writes from a manifest: package-lock.json,
	// poetry.lock.
	LocationLockfile = "lockfile"
	// LocationVendored is a copy of a dependency committed to the tree, such as a minified script.
	// Bumping the manifest leaves it as it was.
	LocationVendored = "vendored"
	// LocationImage is a container image, for a finding read from one.
	LocationImage = "image"
	// LocationFile is any other file a finding is in.
	LocationFile = "file"
)

// ActionLocation is one place an action applies to.
type ActionLocation struct {
	// Repository the path is in, for a component holding more than one. Paths are relative to it.
	Repository string `json:"repository,omitempty"`
	// Path is the file, or the image reference for a location of kind image.
	Path string `json:"path"`
	Line int    `json:"line,omitempty"`
	// Kind is one of the Location constants.
	Kind string `json:"kind"`
}

// ActionFinding is one finding an action clears.
//
// The document carries what identifies the finding and ranks it. The fingerprint is the one
// results.sarif records for the same finding, which is where the rest of it is.
type ActionFinding struct {
	Control    string         `json:"control,omitempty"`
	RuleID     string         `json:"ruleId,omitempty"`
	Tool       string         `json:"tool,omitempty"`
	Priority   string         `json:"priority,omitempty"`
	Severity   sarif.Severity `json:"-"`
	Message    string         `json:"-"`
	Component  string         `json:"-"`
	Repository string         `json:"repository,omitempty"`
	// Location is the file and line, or the image for a finding inside one.
	Location    string `json:"location,omitempty"`
	HelpURI     string `json:"-"`
	Fingerprint string `json:"fingerprint,omitempty"`
	// Upgrade is the dependency and the version that clears it, `jinja2 2.10 → 2.10.1`, or its
	// "no fix available". Empty for a finding that is not about a dependency.
	Upgrade string `json:"-"`
}
