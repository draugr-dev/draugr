package engine

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/draugr-dev/draugr/pkg/dephealth"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// MaliciousPackageRule is the rule a finding about a package flagged as malicious is reported
// under. Draugr's own, because the statement carries no advisory identifier to report it under.
const MaliciousPackageRule = "malicious-package"

// MaliciousPackageTool is the source named on such a finding: the service that answered the
// lookup, which relays the OSSF Malicious Packages Project's list.
const MaliciousPackageTool = "deps.dev"

// maliciousPackageRule explains the rule, for a reader who meets it in a report or an editor.
var maliciousPackageRule = sarif.Rule{
	Name:             "MaliciousPackage",
	ShortDescription: "A dependency flagged as malicious",
	FullDescription:  "The OSSF Malicious Packages Project lists this package as malicious in every version.",
	Help: "Remove the package and anything that pulls it in. Its install scripts may already have " +
		"run: treat the machines that installed it, and the credentials they held, as compromised.",
	HelpURI: "https://github.com/ossf/malicious-packages",
}

// addMaliciousPackages reports each listed package the lookup flagged as malicious that no scanner
// made a finding about.
//
// A package with a finding already is raised where it stands, by the ranking. One with none would
// otherwise be looked up, flagged and then never mentioned, which is the case the lookup covers
// every package for: a package on the list rarely has an advisory a vulnerability scanner would
// match. One finding per component, repository, file and package, under the control whose scan
// listed it, at high, which the ranking then raises to critical and explains.
func (e *Engine) addMaliciousPackages(controls map[string]plugin.ControlResult) {
	type place struct{ component, repository, path, purl string }
	flagged := map[string]bool{}
	malicious := func(purl string) bool {
		if seen, ok := flagged[purl]; ok {
			return seen
		}
		pkg, _ := e.health.Lookup(purl)
		is := false
		for _, f := range pkg.Findings {
			if f.Kind == dephealth.KindMalicious {
				is = true
			}
		}
		flagged[purl] = is
		return is
	}
	// What a finding already covers, by component and package across every control: a package
	// another control reported is raised there, and a second finding would count it twice.
	covered := map[[2]string]bool{}
	for _, cr := range controls {
		for _, res := range cr.Report.Results {
			if res.Package != nil && res.Package.PURL != "" {
				covered[[2]string{res.Component, purlIdentity(res.Package.PURL)}] = true
			}
		}
	}
	for name, cr := range controls {
		added := map[place]bool{}
		for _, p := range cr.Report.Inventory {
			at := place{p.Component, p.Repository, p.Path, purlIdentity(p.PURL)}
			if added[at] || covered[[2]string{p.Component, at.purl}] || !malicious(p.PURL) {
				continue
			}
			added[at] = true
			cr.Report.Results = append(cr.Report.Results, maliciousFinding(name, p))
		}
		if len(added) == 0 {
			continue
		}
		if cr.Report.Rules == nil {
			cr.Report.Rules = map[string]sarif.Rule{}
		}
		cr.Report.Rules[MaliciousPackageRule] = maliciousPackageRule
		controls[name] = cr
	}
}

// maliciousFinding is the finding for one listed package flagged as malicious.
func maliciousFinding(control string, p sarif.InventoryPackage) sarif.Result {
	name, version := purlNameVersion(p.PURL)
	return sarif.Result{
		Tool:    MaliciousPackageTool,
		RuleID:  MaliciousPackageRule,
		Level:   sarif.LevelError,
		Message: fmt.Sprintf("%s %s is flagged as malicious", name, version),
		Location: sarif.Location{
			URI: p.Path, StartLine: p.Line,
		},
		Control:    control,
		Component:  p.Component,
		Repository: p.Repository,
		Package: &sarif.Package{
			Name: name, Version: version, PURL: p.PURL, Ecosystem: purlType(p.PURL),
		},
	}
}

// purlIdentity is a package URL without its qualifiers and subpath, which describe where a package
// came from rather than which package it is. The form dependency health is keyed on.
func purlIdentity(purl string) string {
	if i := strings.IndexAny(purl, "?#"); i >= 0 {
		purl = purl[:i]
	}
	return strings.TrimSpace(purl)
}

// purlNameVersion reads the package's name, with its namespace, and its version out of a package
// URL: `pkg:npm/%40scope/name@1.2.0` is `@scope/name` and `1.2.0`. A part that does not decode is
// returned as written.
func purlNameVersion(purl string) (name, version string) {
	rest := purlIdentity(purl)
	rest = strings.TrimPrefix(rest, "pkg:")
	if _, after, ok := strings.Cut(rest, "/"); ok {
		rest = after
	}
	if i := strings.LastIndex(rest, "@"); i > 0 {
		rest, version = rest[:i], rest[i+1:]
	}
	if dec, err := url.PathUnescape(rest); err == nil {
		rest = dec
	}
	if dec, err := url.PathUnescape(version); err == nil {
		version = dec
	}
	return rest, version
}
