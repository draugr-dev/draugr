package sarif

import (
	"cmp"
	"encoding/json"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/draugr-dev/draugr/internal/manifests"
)

// What follows reads the dependency an imported finding is about, the version that fixes it, and
// the advisory's other identifiers, from wherever the file states them.
//
// SARIF has no member for a package, so each tool puts it somewhere of its own: a package URL in a
// property bag, a logical location written as name@version, a fix that inserts name@version, or
// labeled lines in a message written for a person. Each source is read only in the shape its tool
// writes, and only where it names the package the finding is about. A finding whose file states no
// package keeps none, and nothing is worked out from a rule id, whose text belongs to whoever chose
// it: a dependency finding with an invented package would group into an upgrade that clears nothing.

// foreignLogicalLocation is a SARIF logical location: a named thing a result is about, which a
// dependency scanner may use for the package, written as name@version.
type foreignLogicalLocation struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
}

// looseLogicalLocations is a location's logicalLocations. A member that is not an array of objects
// is none, rather than a reason to refuse a file read before this member was.
type looseLogicalLocations []foreignLogicalLocation

func (l *looseLogicalLocations) UnmarshalJSON(b []byte) error {
	var v []foreignLogicalLocation
	if json.Unmarshal(b, &v) == nil {
		*l = v
	}
	return nil
}

// foreignFix is a SARIF fix: the replacements that would resolve the result.
type foreignFix struct {
	ArtifactChanges []struct {
		Replacements []struct {
			InsertedContent *struct {
				Text string `json:"text"`
			} `json:"insertedContent"`
		} `json:"replacements"`
	} `json:"artifactChanges"`
}

// looseFixes is a result's fixes, read as looseLogicalLocations is.
type looseFixes []foreignFix

func (l *looseFixes) UnmarshalJSON(b []byte) error {
	var v []foreignFix
	if json.Unmarshal(b, &v) == nil {
		*l = v
	}
	return nil
}

// packageOf is the dependency a result is about, or nil where the file states none.
//
// The name and installed version come from the first of these the file holds:
//
//   - Draugr's own `package` property, an object;
//   - the result's message, where it holds `Package:` and `Installed Version:` lines, as Trivy's does;
//   - the result's message, where it opens `Package 'name@version' is vulnerable to`, as
//     OSV-Scanner's does;
//   - one logical location written as name@version;
//   - one package URL in the result's `purls` property, its artifact's, or its rule's, as Grype
//     writes on the rule.
//
// A package URL beside a name from the text is kept only where it names the same package at the
// same version, so the finding never carries an identifier for a package it is not about.
func (fr foreignRunReader) packageOf(sr foreignResult, rule *foreignRule, uri string) *Package {
	if sr.Properties != nil && sr.Properties.Package.pkg != nil {
		return sr.Properties.Package.pkg
	}
	var p Package
	fixStated := false
	msg := sr.Message.Text
	if name, version, ok := labeledPackage(msg); ok {
		p.Name, p.Version = name, version
		p.FixedVersion, fixStated = labeled(msg, "Fixed Version")
	} else if m := osvMessage.FindStringSubmatch(msg); m != nil {
		p.Name, p.Version = m[1], m[2]
	} else if name, version, ok := logicalPackage(sr); ok {
		p.Name, p.Version = name, version
	}
	if purl, ok := fr.purlOf(sr, rule); ok {
		if name, version, typ, ok := parsePURL(purl); ok {
			switch {
			case p.Name == "":
				p.Name, p.Version, p.PURL, p.Ecosystem = name, version, purl, typ
			case name == p.Name && (version == "" || version == p.Version):
				p.PURL, p.Ecosystem = purl, typ
			}
		}
	}
	if p.Name == "" {
		return nil
	}
	if p.Ecosystem == "" {
		p.Ecosystem = ecosystemOfFile(uri)
	}
	if !fixStated {
		p.FixedVersion = statedFix(sr, rule, p)
	}
	return &p
}

// labeled reads one "Key: value" line from a message, and whether the line is there at all: a line
// with nothing after the colon states that there is no value, which a missing line does not.
func labeled(text, key string) (string, bool) {
	for _, line := range strings.Split(text, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), key+":"); ok {
			return strings.TrimSpace(rest), true
		}
	}
	return "", false
}

// labeledPackage reads the package and installed version from a message that states both on lines
// of their own, as Trivy's does:
//
//	Package: golang.org/x/text
//	Installed Version: v0.3.5
//	Vulnerability CVE-2021-38561
//	Severity: HIGH
//	Fixed Version: 0.3.7
func labeledPackage(msg string) (name, version string, ok bool) {
	name, _ = labeled(msg, "Package")
	version, _ = labeled(msg, "Installed Version")
	return name, version, name != "" && version != ""
}

// osvMessage is OSV-Scanner's message for a vulnerable package: `Package 'lodash@4.17.15' is
// vulnerable to 'CVE-2020-28500' (also known as 'GHSA-29mw-wpgm-hmr9').` The name may itself hold
// an @, as an npm scope does, so the version is what follows the last one.
var osvMessage = regexp.MustCompile(`^Package '([^'\s]+)@([^'\s@]+)' is vulnerable to '`)

// logicalPackage reads the package from the result's logical locations, where exactly one names a
// package as name@version. A logical location of another kind, a function or a type, is not a
// package, and two naming different packages leave the finding's package unstated.
func logicalPackage(sr foreignResult) (name, version string, ok bool) {
	type pair struct{ name, version string }
	var found []pair
	for _, loc := range sr.Locations {
		for _, ll := range loc.LogicalLocations {
			switch ll.Kind {
			case "", "package", "module":
			default:
				continue
			}
			n, v, ok := nameAtVersion(cmp.Or(ll.FullyQualifiedName, ll.Name))
			if ok && !slices.Contains(found, pair{n, v}) {
				found = append(found, pair{n, v})
			}
		}
	}
	if len(found) != 1 {
		return "", "", false
	}
	return found[0].name, found[0].version, true
}

// nameAtVersion splits name@version at its last @, so an npm scope stays in the name. Anything with
// whitespace or a quote in it is prose, not a package.
func nameAtVersion(s string) (name, version string, ok bool) {
	if s == "" || strings.ContainsAny(s, " \t\r\n'\"") {
		return "", "", false
	}
	i := strings.LastIndex(s, "@")
	if i <= 0 || i == len(s)-1 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// purlOf is the one package URL the file gives for a result: from the result's `purls` property,
// else its artifact's, else its rule's. A list naming more than one package says which packages the
// rule covers rather than which one this result is about, and gives none.
func (fr foreignRunReader) purlOf(sr foreignResult, rule *foreignRule) (string, bool) {
	var sources []*foreignProperties
	sources = append(sources, sr.Properties)
	if len(sr.Locations) > 0 {
		if i := sr.Locations[0].PhysicalLocation.ArtifactLocation.Index; i != nil && *i >= 0 && *i < len(fr.run.Artifacts) {
			sources = append(sources, fr.run.Artifacts[*i].Properties)
		}
	}
	if rule != nil {
		sources = append(sources, rule.Properties)
	}
	for _, props := range sources {
		if props == nil || len(props.PURLs) == 0 {
			continue
		}
		var distinct []string
		for _, p := range props.PURLs {
			if p = strings.TrimSpace(p); p != "" && !slices.Contains(distinct, p) {
				distinct = append(distinct, p)
			}
		}
		if len(distinct) != 1 {
			return "", false
		}
		return distinct[0], true
	}
	return "", false
}

// purlTypeName is a package URL type, as the specification spells one.
var purlTypeName = regexp.MustCompile(`^[a-z][a-z0-9.+-]*$`)

// purlNamespaced are the package URL types whose namespace is part of the package's name, as its
// ecosystem writes it: golang.org/x/text, @angular/core, symfony/http-kernel.
var purlNamespaced = map[string]bool{"golang": true, "npm": true, "composer": true, "github": true, "bitbucket": true, "swift": true}

// purlDistribution are the types whose namespace names the distribution a package came from rather
// than any part of its name: pkg:deb/debian/openssl is openssl.
var purlDistribution = map[string]bool{"deb": true, "rpm": true, "apk": true, "alpm": true}

// parsePURL reads a package URL of the form pkg:type/namespace/name@version, with any qualifiers and
// subpath set aside, into the package's name as its ecosystem writes it, its version, and its type.
//
// Strict, because a package URL that does not parse names nothing a reader could act on: ok is false
// for anything outside that form, for a percent-escape that does not decode, and for a namespace of a
// type this does not know how to join to the name. Maven's group joins its artifact with a colon, as
// group:artifact. The version may be absent.
func parsePURL(s string) (name, version, typ string, ok bool) {
	rest, ok := strings.CutPrefix(s, "pkg:")
	if !ok {
		return "", "", "", false
	}
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	typ, rest, ok = strings.Cut(strings.TrimLeft(rest, "/"), "/")
	typ = strings.ToLower(typ)
	if !ok || !purlTypeName.MatchString(typ) {
		return "", "", "", false
	}
	if i := strings.LastIndex(rest, "@"); i > 0 && !strings.Contains(rest[i+1:], "/") {
		v, err := url.PathUnescape(rest[i+1:])
		if err != nil || v == "" {
			return "", "", "", false
		}
		rest, version = rest[:i], v
	}
	segments := strings.Split(strings.Trim(rest, "/"), "/")
	for i, seg := range segments {
		dec, err := url.PathUnescape(seg)
		if err != nil || dec == "" {
			return "", "", "", false
		}
		segments[i] = dec
	}
	last := segments[len(segments)-1]
	namespace := segments[:len(segments)-1]
	switch {
	case len(namespace) == 0, purlDistribution[typ]:
		name = last
	case typ == "maven" && len(namespace) == 1:
		name = namespace[0] + ":" + last
	case purlNamespaced[typ]:
		name = strings.Join(namespace, "/") + "/" + last
	default:
		return "", "", "", false
	}
	return name, version, typ, true
}

// statedFix is the version that fixes p, where the file states it somewhere other than a message
// already read for it:
//
//   - the rule's help, where its `Package:` line names p and any `Version:` line p's version, and a
//     `Fix Version:` or `Fixed Version:` line follows, as Grype writes a rule for each package;
//   - a Markdown table in the rule's help with `Package Name` and `Fixed Version` columns, the rows
//     naming p, as OSV-Scanner writes for every package an advisory covers;
//   - a fix of the result's that inserts p's own name at another version. A fix that upgrades a
//     different package, the one that brings p in, says nothing about which version of p is fixed.
//
// Several versions are kept as a list, as a scanner writes one fix per release line. Empty where the
// file states none.
func statedFix(sr foreignResult, rule *foreignRule, p Package) string {
	var fixes []string
	add := func(v string) {
		if v = strings.TrimSpace(v); v != "" && !slices.Contains(fixes, v) {
			fixes = append(fixes, v)
		}
	}
	if rule != nil {
		help := rule.Help.text()
		if name, _ := labeled(help, "Package"); name == p.Name {
			if v, stated := labeled(help, "Version"); !stated || v == p.Version {
				fix, ok := labeled(help, "Fix Version")
				if !ok {
					fix, _ = labeled(help, "Fixed Version")
				}
				add(fix)
			}
		}
		if len(fixes) == 0 {
			for _, v := range tableFixes(rule.Help.markdown(), p.Name) {
				add(v)
			}
		}
	}
	if len(fixes) == 0 {
		for _, fix := range sr.Fixes {
			for _, change := range fix.ArtifactChanges {
				for _, r := range change.Replacements {
					if r.InsertedContent == nil {
						continue
					}
					if n, v, ok := nameAtVersion(strings.TrimSpace(r.InsertedContent.Text)); ok && n == p.Name {
						add(v)
					}
				}
			}
		}
	}
	return strings.Join(fixes, ", ")
}

// tableFixes are the fixed versions a Markdown table gives for one package: the rows whose
// `Package Name` cell is the package, read from the `Fixed Version` cell. A cell that holds no digit,
// or holds a space, is not a version.
func tableFixes(md, name string) []string {
	var out []string
	pkgCol, fixCol := -1, -1
	for _, line := range strings.Split(md, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") {
			pkgCol, fixCol = -1, -1
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		if pkgCol < 0 || fixCol < 0 {
			pkgCol, fixCol = slices.Index(cells, "Package Name"), slices.Index(cells, "Fixed Version")
			continue
		}
		if pkgCol >= len(cells) || fixCol >= len(cells) || cells[pkgCol] != name {
			continue
		}
		if v := cells[fixCol]; strings.ContainsAny(v, "0123456789") && !strings.ContainsAny(v, " \t") {
			out = append(out, v)
		}
	}
	return out
}

// manifestEcosystem names, in the words a scanner reports an ecosystem in, the package manager whose
// dependency file a finding lies in, keyed by the ecosystem Draugr's list of dependency files gives
// the file.
var manifestEcosystem = map[string]string{
	"go": "gomod", "npm": "npm", "python": "pip", "maven": "pom", "gradle": "gradle",
	"nuget": "nuget", "ruby": "gem", "rust": "cargo", "php": "composer",
}

// ecosystemOfFile is the package manager a dependency file belongs to, for a package the file states
// without a package URL: go.mod is Go's, package-lock.json npm's. It orders the versions an upgrade
// chooses between. Empty for a path that is not a dependency file Draugr recognizes.
func ecosystemOfFile(uri string) string {
	format := manifests.FormatOf(path.Base(uri))
	if format == "" {
		return ""
	}
	for _, f := range manifests.Formats() {
		if f.Name == format {
			return manifestEcosystem[f.Ecosystem]
		}
	}
	return ""
}

// statedAliases are the advisory identifiers the file states for a result beside the one its rule
// id carries: in the result's `tags`, its rule's `tags`, and its rule's `deprecatedIds`, which SARIF
// defines as the ids the same rule was known by. A tag is an identifier only where the whole tag is
// one, so `CVE-2021-44228` is read and a sentence mentioning one is not.
//
// They are what lets KEV and EPSS, which are keyed on CVEs, reach a finding named by a GitHub or Go
// advisory, and what lets correlation count the finding once with another scanner's copy of it.
// Nothing is looked up: an identifier the file does not state stays unknown.
func statedAliases(sr foreignResult, rule *foreignRule, ruleID string) []string {
	var lists []looseStrings
	if sr.Properties != nil {
		lists = append(lists, sr.Properties.Tags)
	}
	if rule != nil {
		if rule.Properties != nil {
			lists = append(lists, rule.Properties.Tags)
		}
		lists = append(lists, rule.DeprecatedIDs)
	}
	own := vulnerabilityID.FindString(ruleID)
	var ids []string
	for _, list := range lists {
		for _, s := range list {
			s = strings.TrimSpace(s)
			if s == "" || vulnerabilityID.FindString(s) != s || s == own || slices.Contains(ids, s) {
				continue
			}
			ids = append(ids, s)
		}
	}
	return ids
}
