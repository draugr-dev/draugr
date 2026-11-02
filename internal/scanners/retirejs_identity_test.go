package scanners

import (
	"context"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// retireNamedOutput is what retire.js 5.7.0 printed for a tree holding a vendored DOMPurify 3.4.16,
// underscore.js 1.8.3 and Knockout 3.4.2, each file only its release banner, with each advisory's
// info links cut to the first. DOMPurify and underscore.js carry an npm name that differs from the
// component name; Knockout's entry in retire.js's repository records none.
const retireNamedOutput = `{"version":"5.7.0","data":[
{"file":"/tmp/checkout/static/knockout.js","results":[
{"version":"3.4.2","component":"knockout","detection":"filecontent","vulnerabilities":[
{"info":["https://github.com/knockout/knockout/issues/1244"],"below":"3.5.0","severity":"medium",
 "identifiers":{"summary":"XSS injection point in attr name binding for browser IE7 and older","issue":"1244",
 "CVE":["CVE-2019-14862"],"githubID":"GHSA-vcjj-xf2r-mwvc"},"cwe":["CWE-79"]}],
"licenses":["MIT"]}]},
{"file":"/tmp/checkout/static/underscore.js","results":[
{"version":"1.8.3","component":"underscore.js","npmname":"underscore","detection":"filecontent","vulnerabilities":[
{"info":["https://nvd.nist.gov/vuln/detail/CVE-2021-23358"],"below":"1.12.1","atOrAbove":"1.3.2","severity":"high",
 "identifiers":{"summary":" vulnerable to Arbitrary Code Injection via the template function","CVE":["CVE-2021-23358"],
 "githubID":"GHSA-cf4h-3jhx-xvhq"},"cwe":["CWE-94"]},
{"info":["https://github.com/jashkenas/underscore/security/advisories/GHSA-qpx9-hpmf-5gmw"],"below":"1.13.8","atOrAbove":"0",
 "severity":"high","identifiers":{"summary":"Underscore.js versions up to 1.13.7 are vulnerable to Denial of Service via stack overflow. The _.flatten and _.isEqual functions use unbounded recursion without a depth limit, so deeply nested structures sourced from untrusted input (e.g. via JSON.parse) can exhaust the call stack and crash the process.",
 "githubID":"GHSA-qpx9-hpmf-5gmw","CVE":["CVE-2026-27601"]},"cwe":["CWE-674","CWE-770"]}],
"licenses":["MIT"]}]},
{"file":"/tmp/checkout/static/purify.js","results":[
{"version":"3.4.16","component":"DOMPurify","npmname":"dompurify","detection":"filecontent","vulnerabilities":[
{"info":["https://github.com/cure53/DOMPurify/security/advisories/GHSA-c6gr-qvv4-5v3f"],"below":"3.4.17","atOrAbove":"0",
 "severity":"low","identifiers":{"summary":"DOMPurify: SMIL attributeName=href guard is skipped when PARSER_MEDIA_TYPE is application/xhtml+xml",
 "githubID":"GHSA-c6gr-qvv4-5v3f","CVE":["CVE-2026-116802"]},"cwe":["CWE-79"]},
{"info":["https://github.com/cure53/DOMPurify/security/advisories/GHSA-mrv2-3pqr-j5jr"],"below":"3.4.17","atOrAbove":"0",
 "severity":"high","identifiers":{"summary":"DOMPurify IN_PLACE: hook that removes a parent or sibling leaves the detached subtree's event handlers armed (incomplete fix for GHSA-p98j-92pf-mc4p)",
 "githubID":"GHSA-mrv2-3pqr-j5jr","CVE":["CVE-2026-116803"]},"cwe":["CWE-693","CWE-79"]},
{"info":["https://github.com/cure53/DOMPurify/security/advisories/GHSA-cg2g-xh64-v4q7"],"below":"3.4.17","atOrAbove":"3.4.4",
 "severity":"critical","identifiers":{"summary":"DOMPurify SAFE_FOR_TEMPLATES bypass: split template expressions survive in attached shadow root content on DOM output modes",
 "githubID":"GHSA-cg2g-xh64-v4q7","CVE":["CVE-2026-116804"]},"cwe":["CWE-79"]}],
"licenses":["MPL-2.0 OR Apache-2.0"]}]}],"messages":[],"errors":[]}`

// trivyNamedOutput is what Trivy 0.74.0 printed with --list-all-pkgs for a package-lock.json pinning
// dompurify 3.4.16 and underscore 1.8.3 in the same tree, cut to the fields Draugr reads. Trivy keys
// DOMPurify's advisories on their GitHub advisory ids and underscore's on their CVEs.
const trivyNamedOutput = `{"SchemaVersion":2,"Results":[{"Target":"package-lock.json","Class":"lang-pkgs","Type":"npm",
"Packages":[
 {"Name":"dompurify","Version":"3.4.16","Identifier":{"PURL":"pkg:npm/dompurify@3.4.16","UID":"8d02fec5ee00505a"},"Locations":[{"StartLine":15,"EndLine":19}]},
 {"Name":"underscore","Version":"1.8.3","Identifier":{"PURL":"pkg:npm/underscore@1.8.3","UID":"28bd90785f79bc6"},"Locations":[{"StartLine":20,"EndLine":24}]}],
"Vulnerabilities":[
 {"VulnerabilityID":"GHSA-cg2g-xh64-v4q7","PkgName":"dompurify","PkgIdentifier":{"PURL":"pkg:npm/dompurify@3.4.16","UID":"8d02fec5ee00505a"},"InstalledVersion":"3.4.16","FixedVersion":"3.4.17","Status":"fixed","Severity":"CRITICAL","Title":"DOMPurify SAFE_FOR_TEMPLATES bypass: split template expressions survive in attached shadow root content on DOM output modes","CVSS":{"ghsa":{"V40Score":9.2}}},
 {"VulnerabilityID":"GHSA-mrv2-3pqr-j5jr","PkgName":"dompurify","PkgIdentifier":{"PURL":"pkg:npm/dompurify@3.4.16","UID":"8d02fec5ee00505a"},"InstalledVersion":"3.4.16","FixedVersion":"3.4.17","Status":"fixed","Severity":"HIGH","Title":"DOMPurify IN_PLACE: hook that removes a parent or sibling leaves the detached subtree's event handlers armed (incomplete fix for GHSA-p98j-92pf-mc4p)","CVSS":{"ghsa":{"V40Score":7.6}}},
 {"VulnerabilityID":"GHSA-c6gr-qvv4-5v3f","PkgName":"dompurify","PkgIdentifier":{"PURL":"pkg:npm/dompurify@3.4.16","UID":"8d02fec5ee00505a"},"InstalledVersion":"3.4.16","FixedVersion":"3.4.17","Status":"fixed","Severity":"LOW","Title":"DOMPurify: SMIL attributeName=href guard is skipped when PARSER_MEDIA_TYPE is application/xhtml+xml"},
 {"VulnerabilityID":"CVE-2021-23358","VendorIDs":["GHSA-cf4h-3jhx-xvhq"],"PkgName":"underscore","PkgIdentifier":{"PURL":"pkg:npm/underscore@1.8.3","UID":"28bd90785f79bc6"},"InstalledVersion":"1.8.3","FixedVersion":"1.12.1","Status":"fixed","Severity":"CRITICAL","Title":"nodejs-underscore: Arbitrary code execution via the template function","CVSS":{"ghsa":{"V3Score":9.8}}},
 {"VulnerabilityID":"CVE-2026-27601","VendorIDs":["GHSA-qpx9-hpmf-5gmw"],"PkgName":"underscore","PkgIdentifier":{"PURL":"pkg:npm/underscore@1.8.3","UID":"28bd90785f79bc6"},"InstalledVersion":"1.8.3","FixedVersion":"1.13.8","Status":"fixed","Severity":"HIGH","Title":"Underscore.js: Underscore.js: Denial of Service via recursive data structures in flatten and isEqual functions","CVSS":{"ghsa":{"V3Score":5.9,"V40Score":8.2}}}]}]}`

// A library whose banner name differs from its npm name is reported under the npm name, the one a
// lockfile scanner uses, and a library retire.js knows no npm name for keeps its component name.
// Each finding names the advisory's other identifiers beside its rule id.
func TestRetireJSNamesThePackageAsNPMDoes(t *testing.T) {
	rep, err := parseRetireJS([]byte(retireNamedOutput), "/tmp/checkout", nil)
	if err != nil {
		t.Fatal(err)
	}
	type want struct {
		purl    string
		aliases []string
	}
	wants := map[string]want{
		"CVE-2019-14862":  {"pkg:npm/knockout@3.4.2", []string{"GHSA-vcjj-xf2r-mwvc"}},
		"CVE-2021-23358":  {"pkg:npm/underscore@1.8.3", []string{"GHSA-cf4h-3jhx-xvhq"}},
		"CVE-2026-27601":  {"pkg:npm/underscore@1.8.3", []string{"GHSA-qpx9-hpmf-5gmw"}},
		"CVE-2026-116802": {"pkg:npm/dompurify@3.4.16", []string{"GHSA-c6gr-qvv4-5v3f"}},
		"CVE-2026-116803": {"pkg:npm/dompurify@3.4.16", []string{"GHSA-mrv2-3pqr-j5jr"}},
		"CVE-2026-116804": {"pkg:npm/dompurify@3.4.16", []string{"GHSA-cg2g-xh64-v4q7"}},
	}
	if len(rep.Results) != len(wants) {
		t.Fatalf("results = %d, want one per advisory", len(rep.Results))
	}
	for _, r := range rep.Results {
		w, ok := wants[r.RuleID]
		if !ok {
			t.Errorf("unexpected rule %q", r.RuleID)
			continue
		}
		if r.Package.PURL != w.purl || !strings.HasSuffix(w.purl, "/"+r.Package.Name+"@"+r.Package.Version) {
			t.Errorf("%s: package %+v, want %s", r.RuleID, *r.Package, w.purl)
		}
		if !slices.Equal(r.Aliases, w.aliases) {
			t.Errorf("%s: aliases = %q, want %q", r.RuleID, r.Aliases, w.aliases)
		}
		// The report trims the package's own "name version → fix: " off the message, so the message
		// has to open with the name the package carries.
		if prefix := r.Package.Name + " " + r.Package.Version + " → " + r.Package.FixedVersion + ": "; !strings.HasPrefix(r.Message, prefix) {
			t.Errorf("%s: message %q does not open with %q", r.RuleID, r.Message, prefix)
		}
	}
}

// The other identifiers are each CVE and the GitHub advisory id, other than the rule id's own, and
// none for an advisory with only retire.js's own identifiers.
func TestRetireAliases(t *testing.T) {
	rep, err := parseRetireJS([]byte(realRetireOutput), "/tmp/checkout", nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range [][]string{{"GHSA-2pqj-h3vj-pqgw"}, nil, nil} {
		if got := rep.Results[i].Aliases; !slices.Equal(got, want) {
			t.Errorf("%s: aliases = %q, want %q", rep.Results[i].RuleID, got, want)
		}
	}
	var v retireVulnerable
	v.Identifiers.CVE = []string{"CVE-2026-10001", "CVE-2026-10002", "CVE-2026-10001"}
	v.Identifiers.GitHubID = "GHSA-cg2g-xh64-v4q7"
	if got := retireAliases("CVE-2026-10001", v); !slices.Equal(got, []string{"CVE-2026-10002", "GHSA-cg2g-xh64-v4q7"}) {
		t.Errorf("aliases = %q", got)
	}
}

// A vendored DOMPurify and a lockfile pinning dompurify at the same version, in each of two
// components' repositories, through the engine. retire.js keys DOMPurify's advisories on their
// CVEs and Trivy on their GitHub ids; both key underscore's on CVEs. Each component counts each flaw
// once, and the fix list has one upgrade per package naming both files.
func TestAVendoredCopyAndItsLockfileAreOneUpgrade(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dirs := map[string]string{"one": t.TempDir(), "two": t.TempDir()}
	checkout := func(_ context.Context, url, _ string, _ git.Scope) (git.Tree, func(), error) {
		return git.Tree{Dir: dirs[url]}, func() {}, nil
	}

	retire := NewRetireJS().(repoScanner)
	retire.checkout, retire.prewarm, retire.cacheVersion, retire.dataState = checkout, nil, nil, nil
	retire.run = func(_ context.Context, _ string, argv []string) ([]byte, error) {
		dir := argv[slices.Index(argv, "--path")+1]
		return []byte(strings.ReplaceAll(retireNamedOutput, "/tmp/checkout", dir)), nil
	}
	trivy := NewTrivyFS().(repoScanner)
	trivy.checkout, trivy.prewarm, trivy.cacheVersion, trivy.dataState = checkout, nil, nil, nil
	trivy.run = func(context.Context, string, []string) ([]byte, error) { return []byte(trivyNamedOutput), nil }

	reg := engine.NewRegistry()
	reg.RegisterController(matchController{control: "sca", scanners: []string{"retirejs", "trivy-fs"}})
	reg.RegisterScanner(retire)
	reg.RegisterScanner(trivy)
	model := saga.Model{
		Config: saga.Config{Controls: map[string]saga.ControllerSettings{"sca": {"enabled": true}}},
		Components: []saga.Component{
			{Name: "api", Repositories: []saga.Repository{{URL: "one"}}},
			{Name: "web", Repositories: []saga.Repository{{URL: "two"}}},
		},
	}
	res, err := engine.New(reg).Run(context.Background(), model)
	if err != nil {
		t.Fatal(err)
	}
	results := res.Controls["sca"].Report.Results
	if len(results) != 22 {
		t.Fatalf("results = %d, want 11 per component: 6 from retire.js and 5 from Trivy", len(results))
	}
	counted := map[string]int{}
	for _, r := range results {
		if !r.Correlated() {
			counted[r.Component]++
		}
	}
	if counted["api"] != 6 || counted["web"] != 6 {
		t.Errorf("counted = %v, want 6 flaws per component: 3 in dompurify, 2 in underscore, 1 in knockout", counted)
	}

	type upgrade struct {
		component, title string
		clears           int
		paths            []string
	}
	var got []upgrade
	for _, a := range report.ActionsFor(map[string]sarif.Report{"sca": res.Controls["sca"].Report}) {
		var paths []string
		for _, l := range a.Locations {
			paths = append(paths, l.Path)
		}
		sort.Strings(paths)
		got = append(got, upgrade{a.Component, a.Title, a.Clears, paths})
	}
	sort.Slice(got, func(i, j int) bool { return got[i].component+got[i].title < got[j].component+got[j].title })
	var want []upgrade
	for _, component := range []string{"api", "web"} {
		want = append(want,
			upgrade{component, "Upgrade dompurify 3.4.16", 3, []string{"package-lock.json", "static/purify.js"}},
			upgrade{component, "Upgrade knockout 3.4.2", 1, []string{"static/knockout.js"}},
			upgrade{component, "Upgrade underscore 1.8.3", 2, []string{"package-lock.json", "static/underscore.js"}},
		)
	}
	if len(got) != len(want) {
		t.Fatalf("actions = %+v\nwant %+v", got, want)
	}
	for i := range want {
		if got[i].component != want[i].component || got[i].title != want[i].title ||
			got[i].clears != want[i].clears || !slices.Equal(got[i].paths, want[i].paths) {
			t.Errorf("action %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}
