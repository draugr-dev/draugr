package scanners

import (
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// realRetireOutput is what retire.js 5.4.3 printed for a vendored jQuery 1.8.3, abridged to three
// of the seven advisories it found — one with a CVE, one with only a GitHub id, and one with
// neither, because those are the three branches the rule id has to handle.
//
// Real output rather than an invention: a fixture somebody wrote by hand tests the parser against
// the shape they imagined, which is the shape the parser already handles.
const realRetireOutput = `{"version":"5.4.3","start":"2026-08-15T18:06:00.030Z","data":[
{"file":"/tmp/checkout/site/static/jquery.min.js","results":[
{"version":"1.8.3","component":"jquery","npmname":"jquery","detection":"filecontent","vulnerabilities":[
{"info":["https://nvd.nist.gov/vuln/detail/CVE-2012-6708"],"below":"1.9.0b1","severity":"medium",
 "identifiers":{"summary":"Selector interpreted as HTML","CVE":["CVE-2012-6708"],"bug":"11290",
 "githubID":"GHSA-2pqj-h3vj-pqgw"},"cwe":["CWE-64","CWE-79"]},
{"info":["https://github.com/advisories/GHSA-q4m3-2j7h-f7xw"],"below":"1.9.0","atOrAbove":"1.2.1",
 "severity":"high","identifiers":{"summary":"Cross-Site Scripting via load","githubID":"GHSA-q4m3-2j7h-f7xw"},
 "cwe":["CWE-79"]},
{"info":["https://github.com/jquery/jquery.com/issues/162"],"below":"2.999.999","severity":"low",
 "identifiers":{"summary":"jQuery 1.x and 2.x are End-of-Life","retid":"73","issue":"162"},
 "cwe":["CWE-1104"]}],
"licenses":["MIT"]}]}],"messages":[],"errors":[],"time":0.366}`

func TestRetireJSInfo(t *testing.T) {
	info := NewRetireJS().Info()
	if info.Name != "retirejs" {
		t.Errorf("name = %q", info.Name)
	}
	if info.Binary != "retire" {
		t.Errorf("binary = %q, want the command npm installs", info.Binary)
	}
	if len(info.Controls) != 1 || info.Controls[0] != "sca" {
		t.Errorf("controls = %v", info.Controls)
	}
}

// TestRetireJSArgsNeverFailOnFindings pins the flag without which the exit code becomes the
// verdict: retire.js exits 13 when it finds anything.
func TestRetireJSArgsNeverFailOnFindings(t *testing.T) {
	argv := retireJSArgs("/tmp/checkout", nil)
	i := slices.Index(argv, "--exitwith")
	if i < 0 || argv[i+1] != "0" {
		t.Errorf("argv must pass --exitwith 0, or a finding fails the scan: %v", argv)
	}
	if !slices.Contains(argv, "json") {
		t.Errorf("argv must ask for JSON: %v", argv)
	}
	if i := slices.Index(argv, "--path"); i < 0 || argv[i+1] != "/tmp/checkout" {
		t.Errorf("argv must scan the checkout: %v", argv)
	}
}

// TestParseRetireJSReadsRealOutput checks the whole conversion against output the tool actually
// produced.
func TestParseRetireJSReadsRealOutput(t *testing.T) {
	report, err := parseRetireJS([]byte(realRetireOutput), "/tmp/checkout", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Results) != 3 {
		t.Fatalf("want one finding per advisory, got %d", len(report.Results))
	}

	first := report.Results[0]
	if first.RuleID != "CVE-2012-6708" {
		t.Errorf("rule id = %q, want the CVE — the identifier a reader can look up and the one an "+
			"exclusion is most likely written against", first.RuleID)
	}
	if first.Level != sarif.LevelWarning {
		t.Errorf("medium should be a warning, got %v", first.Level)
	}
	// Package identity is what lets a vendored file and the npm package be recognised as one
	// library, and what carries these findings into the platform report formats.
	if first.Package == nil {
		t.Fatal("no package identity")
	}
	if first.Package.Name != "jquery" || first.Package.Version != "1.8.3" {
		t.Errorf("package = %+v", first.Package)
	}
	if first.Package.FixedVersion != "1.9.0b1" {
		t.Errorf("fixed version = %q", first.Package.FixedVersion)
	}
	if first.Package.PURL != "pkg:npm/jquery@1.8.3" {
		t.Errorf("purl = %q", first.Package.PURL)
	}
	// The location is the file retire.js matched, absolute — the repository scanner rewrites it
	// to a repo-relative path afterwards, as it does for every scanner.
	if first.Location.URI != "/tmp/checkout/site/static/jquery.min.js" {
		t.Errorf("location = %q", first.Location.URI)
	}
	if !strings.Contains(first.Message, "detected by filecontent") {
		t.Errorf("the message should say how the library was recognised, which is the answer to "+
			"'why is this not in my lockfile': %q", first.Message)
	}
}

// TestRetireRuleIDPrefersThePortableIdentifier covers all three branches, because an unstable rule
// id breaks every suppression written against it.
func TestRetireRuleIDPrefersThePortableIdentifier(t *testing.T) {
	report, err := parseRetireJS([]byte(realRetireOutput), "/tmp/checkout", nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"CVE-2012-6708", "GHSA-q4m3-2j7h-f7xw", "retirejs:jquery:73"}
	for i, w := range want {
		if report.Results[i].RuleID != w {
			t.Errorf("rule id[%d] = %q, want %q", i, report.Results[i].RuleID, w)
		}
	}
	// The fallback is prefixed so it cannot be read as a CVE by anything matching on shape.
	if strings.HasPrefix(report.Results[2].RuleID, "CVE-") {
		t.Error("a retire.js-local identifier must not look like a CVE")
	}
}

func TestRetireJSSeverities(t *testing.T) {
	for _, c := range []struct {
		in    string
		level sarif.Level
		score float64
		has   bool
	}{
		{"critical", sarif.LevelError, 9.5, true},
		{"high", sarif.LevelError, 8.0, true},
		{"medium", sarif.LevelWarning, 5.0, true},
		{"low", sarif.LevelNote, 2.0, true},
		{"", sarif.LevelNote, 0, false},
		{"nonsense", sarif.LevelNote, 0, false},
	} {
		level, score, has := retireSeverity(c.in)
		if level != c.level || score != c.score || has != c.has {
			t.Errorf("retireSeverity(%q) = %v, %v, %v", c.in, level, score, has)
		}
	}
}

func TestParseRetireJSRejectsGarbage(t *testing.T) {
	if _, err := parseRetireJS([]byte("not json"), "/d", nil); err == nil {
		t.Error("unparseable output should error rather than report a clean scan")
	}
	// An empty run is a real answer, not a failure: a repository with no front-end assets.
	report, err := parseRetireJS([]byte(`{"version":"5.4.3","data":[],"errors":[]}`), "/d", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Results) != 0 {
		t.Errorf("want no findings, got %d", len(report.Results))
	}
}

func TestRetirePURL(t *testing.T) {
	for _, c := range []struct{ name, version, want string }{
		{"jquery", "1.8.3", "pkg:npm/jquery@1.8.3"},
		{"jquery", "", "pkg:npm/jquery"},
		{"", "1.0", ""},
	} {
		if got := retirePURL(c.name, c.version); got != c.want {
			t.Errorf("retirePURL(%q, %q) = %q, want %q", c.name, c.version, got, c.want)
		}
	}
}

// TestRetireJSIsSelectableOnSCA is the check a unit test of the scanner alone cannot make: a
// scanner a control will not select is one the descriptor accepts and nothing runs.
func TestRetireJSIsSelectableOnSCA(t *testing.T) {
	info := NewRetireJS().Info()
	if !slices.Contains(info.Controls, "sca") {
		t.Fatalf("retirejs does not serve sca: %v", info.Controls)
	}
	if len(info.TargetKinds) != 1 || info.TargetKinds[0] != plugin.TargetRepository {
		t.Errorf("target kinds = %v, want a repository", info.TargetKinds)
	}
}
