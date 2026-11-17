package sarif

import (
	"slices"
	"testing"
)

// The real files each tool writes are read in internal/scanners' tests. These cover the SARIF members
// and the rules about them that no file there exercises: a package named by a logical location, a fix
// inserting a version, a package URL on the result or its artifact, identifiers in tags, and what is
// left unset.

func TestForeignSARIFReadsAPackageFromALogicalLocationAndItsFix(t *testing.T) {
	rep, _ := readForeign(t, `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[
		{"ruleId":"a","locations":[{"physicalLocation":{"artifactLocation":{"uri":"package.json"}},
			"logicalLocations":[{"fullyQualifiedName":"@scope/body-parser@1.19.0"}]}],
		 "fixes":[{"artifactChanges":[{"replacements":[{"insertedContent":{"text":"@scope/body-parser@1.20.3"}}]}]}]},
		{"ruleId":"b","locations":[{"physicalLocation":{"artifactLocation":{"uri":"package.json"}},
			"logicalLocations":[{"fullyQualifiedName":"multer@2.0.1"}]}],
		 "fixes":[{"artifactChanges":[{"replacements":[{"insertedContent":{"text":"@nestjs/platform-express@10.4.20"}}]}]}]},
		{"ruleId":"c","locations":[{"logicalLocations":[{"name":"handler@v2","kind":"function"}]}]},
		{"ruleId":"d","locations":[{"logicalLocations":[{"name":"a@1"}]},{"logicalLocations":[{"name":"b@2"}]}]},
		{"ruleId":"e","locations":[{"logicalLocations":[{"name":"not a package@1"},{"name":"@1"},{"name":"x@"}]}]},
		{"ruleId":"f","locations":[{"logicalLocations":{"name":"x@1"}}],"fixes":"none"}]}]}`)
	want := &Package{Name: "@scope/body-parser", Version: "1.19.0", FixedVersion: "1.20.3", Ecosystem: "npm"}
	if p := rep.Results[0].Package; p == nil || *p != *want {
		t.Errorf("package = %+v, want %+v", p, want)
	}
	// The fix upgrades the package that brings multer in, which says nothing about which multer.
	want = &Package{Name: "multer", Version: "2.0.1", Ecosystem: "npm"}
	if p := rep.Results[1].Package; p == nil || *p != *want {
		t.Errorf("package = %+v, want %+v, with no fix", p, want)
	}
	for _, r := range rep.Results[2:] {
		if r.Package != nil {
			t.Errorf("%s: package = %+v, want none", r.RuleID, r.Package)
		}
	}
}

func TestForeignSARIFReadsOnePackageURLFromTheResultItsArtifactOrItsRule(t *testing.T) {
	rep, _ := readForeign(t, `{"version":"2.1.0","runs":[{
		"tool":{"driver":{"name":"x","rules":[
			{"id":"r","properties":{"purls":["pkg:pypi/flask@0.12.2"]}},
			{"id":"two","properties":{"purls":["pkg:npm/a@1","pkg:npm/b@1"]}}]}},
		"artifacts":[{"location":{"uri":"pom.xml"},"properties":{"purls":["pkg:maven/org.apache/commons-text@1.9"]}}],
		"results":[
			{"ruleId":"r","properties":{"purls":["pkg:npm/%40angular/core@1.0.0?arch=x#sub"]}},
			{"ruleId":"other","locations":[{"physicalLocation":{"artifactLocation":{"index":0}}}]},
			{"ruleId":"r"},
			{"ruleId":"two"},
			{"ruleId":"r","message":{"text":"Package: flask\nInstalled Version: 0.12.2\nFixed Version: 2.3.2, 2.2.5"}},
			{"ruleId":"r","message":{"text":"Package: flask\nInstalled Version: 1.0\nFixed Version: "}}]}]}`)
	want := []*Package{
		{Name: "@angular/core", Version: "1.0.0", PURL: "pkg:npm/%40angular/core@1.0.0?arch=x#sub", Ecosystem: "npm"},
		{Name: "org.apache:commons-text", Version: "1.9", PURL: "pkg:maven/org.apache/commons-text@1.9", Ecosystem: "maven"},
		{Name: "flask", Version: "0.12.2", PURL: "pkg:pypi/flask@0.12.2", Ecosystem: "pypi"},
		nil,
		// The message and the package URL agree, so the URL is kept.
		{Name: "flask", Version: "0.12.2", FixedVersion: "2.3.2, 2.2.5", PURL: "pkg:pypi/flask@0.12.2", Ecosystem: "pypi"},
		// They disagree on the version, and the message is about this result: no URL for another
		// version, and the empty fixed version as the message states it.
		{Name: "flask", Version: "1.0"},
	}
	for i, w := range want {
		got := rep.Results[i].Package
		if (got == nil) != (w == nil) || (got != nil && *got != *w) {
			t.Errorf("result %d: package = %+v, want %+v", i, got, w)
		}
	}
}

func TestForeignSARIFReadsAFixFromTheRulesHelpOnlyForItsPackage(t *testing.T) {
	rep, _ := readForeign(t, `{"version":"2.1.0","runs":[{
		"tool":{"driver":{"name":"x","rules":[
			{"id":"same","help":{"text":"Package: lodash\nVersion: 4.17.15\nFix Version: 4.17.21"},"properties":{"purls":["pkg:npm/lodash@4.17.15"]}},
			{"id":"other","help":{"text":"Package: lodash-es\nFix Version: 4.17.21"},"properties":{"purls":["pkg:npm/lodash@4.17.15"]}},
			{"id":"version","help":{"text":"Package: lodash\nVersion: 4.17.20\nFix Version: 4.17.21"},"properties":{"purls":["pkg:npm/lodash@4.17.15"]}},
			{"id":"table","help":{"markdown":"| Source | Package Name | Package Version |\n| --- | --- | --- |\n| lockfile | lodash | 4.17.15 |\n\n| Vulnerability ID | Package Name | Fixed Version |\n| --- | --- | --- |\n| GHSA-1 | lodash | 4.17.19 |\n| GHSA-1 | lodash-es | 4.17.20 |\n| GO-1 | lodash | 4.17.19 |\n| GO-2 | lodash | -- |\n| GO-3 | lodash |"}}]}},
		"results":[
			{"ruleId":"same"},
			{"ruleId":"other"},
			{"ruleId":"version"},
			{"ruleId":"table","message":{"text":"Package 'lodash@4.17.15' is vulnerable to 'GHSA-1'."}}]}]}`)
	for i, want := range []string{"4.17.21", "", "", "4.17.19"} {
		p := rep.Results[i].Package
		if p == nil || p.FixedVersion != want {
			t.Errorf("%s: package = %+v, want fixed version %q", rep.Results[i].RuleID, p, want)
		}
	}
}

func TestForeignSARIFReadsAdvisoryIdentifiersFromTagsAndDeprecatedIDs(t *testing.T) {
	rep, _ := readForeign(t, `{"version":"2.1.0","runs":[{
		"tool":{"driver":{"name":"x","rules":[
			{"id":"GHSA-jfh8-c2jp-5v3q","properties":{"tags":["security","CVE-2021-44228","CWE-502"]},
			 "deprecatedIds":["GHSA-jfh8-c2jp-5v3q","GO-2021-0001"]},
			{"id":"B602","properties":{"tags":["security","see CVE-2021-44228"]},"deprecatedIds":"B601"}]}},
		"results":[
			{"ruleId":"GHSA-jfh8-c2jp-5v3q","properties":{"tags":["CVE-2021-45046","CVE-2021-44228"]}},
			{"ruleId":"B602"}]}]}`)
	if got, want := rep.Results[0].Aliases, []string{"CVE-2021-45046", "CVE-2021-44228", "GO-2021-0001"}; !slices.Equal(got, want) {
		t.Errorf("aliases = %q, want %q", got, want)
	}
	if got := rep.Results[1].Aliases; len(got) != 0 {
		t.Errorf("aliases = %q, want none from a tag that is a sentence", got)
	}
}

func TestParsePURL(t *testing.T) {
	for _, c := range []struct {
		purl, name, version, typ string
		ok                       bool
	}{
		{"pkg:golang/golang.org/x/text@v0.3.5", "golang.org/x/text", "v0.3.5", "golang", true},
		{"pkg:npm/%40scope/name@1.0.0", "@scope/name", "1.0.0", "npm", true},
		{"pkg:npm/@scope/name", "@scope/name", "", "npm", true},
		{"pkg:deb/debian/openssl@3.0.11-1?arch=amd64&distro=debian-12", "openssl", "3.0.11-1", "deb", true},
		{"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "org.apache.logging.log4j:log4j-core", "2.14.1", "maven", true},
		{"pkg:PyPI/flask@0.12.2", "flask", "0.12.2", "pypi", true},
		{"pkg:composer/symfony/http-kernel@5.0.0", "symfony/http-kernel", "5.0.0", "composer", true},
		{"pkg:generic/acme/thing@1", "", "", "", false},
		{"pkg:npm/lodash@", "", "", "", false},
		{"pkg:npm/lo%zzdash@1", "", "", "", false},
		{"pkg:npm/lodash@1%zz", "", "", "", false},
		{"pkg:9bad/x@1", "", "", "", false},
		{"pkg:npm", "", "", "", false},
		{"pkg:npm//x@1", "x", "1", "npm", true},
		{"npm/lodash@4", "", "", "", false},
	} {
		name, version, typ, ok := parsePURL(c.purl)
		if name != c.name || version != c.version || typ != c.typ || ok != c.ok {
			t.Errorf("parsePURL(%q) = %q %q %q %v, want %q %q %q %v", c.purl, name, version, typ, ok, c.name, c.version, c.typ, c.ok)
		}
	}
}

func TestEcosystemOfFile(t *testing.T) {
	for uri, want := range map[string]string{
		"go.mod": "gomod", "file:///src/app/package-lock.json": "npm", "svc/requirements.txt": "pip",
		"Gemfile.lock": "gem", "main.go": "", "": "", "environment.yml": "",
	} {
		if got := ecosystemOfFile(uri); got != want {
			t.Errorf("ecosystemOfFile(%q) = %q, want %q", uri, got, want)
		}
	}
}
