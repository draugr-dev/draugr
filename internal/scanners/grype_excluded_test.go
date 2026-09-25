package scanners

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// grypeIgnoredJinja2 is a match Grype's JSON report lists as ignored, trimmed from Grype 0.118.0's
// output for Jinja2 2.10 with `.grype.yaml` ignoring CVE-2020-28493.
const grypeIgnoredJinja2 = `{
  "vulnerability": {"id": "CVE-2020-28493", "dataSource": "https://github.com/advisories/GHSA-g3rq-g295-4j3m",
    "namespace": "github:language:python", "severity": "Medium",
    "description": "Regular Expression Denial of Service (ReDoS) in Jinja2",
    "cvss": [{"metrics": {"baseScore": 5.3}}, {"metrics": {"baseScore": 6.9}}],
    "fix": {"versions": ["2.11.3"]}},
  "relatedVulnerabilities": [{"id": "GHSA-g3rq-g295-4j3m"}],
  "matchDetails": [{"type": "exact-direct-match", "matcher": "python-matcher"}],
  "artifact": {"name": "jinja2", "version": "2.10", "type": "python", "purl": "pkg:pypi/jinja2@2.10",
    "locations": [{"path": "/requirements.txt"}]},
  "appliedIgnoreRules": [{"vulnerability": "CVE-2020-28493", "reason": "not reachable from the entry point", "namespace": ""}]
}`

// grypeActiveSARIF is Grype's SARIF for the same scan: the match it reported, and nothing of the
// one it ignored.
const grypeActiveSARIF = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"grype","rules":[{
  "id":"CVE-2019-10906-jinja2",
  "help":{"text":"Vulnerability CVE-2019-10906\nSeverity: high\nPackage: jinja2\nVersion: 2.10\nFix Version: 2.10.1\nType: python\n"},
  "properties":{"purls":["pkg:pypi/jinja2@2.10"],"security-severity":"8.6"}}]}},
 "results":[{"ruleId":"CVE-2019-10906-jinja2","level":"error","message":{"text":"vuln"},
  "locations":[{"physicalLocation":{"artifactLocation":{"uri":"/requirements.txt"}}}]}]}]}`

func grypeJSON(matches ...string) string {
	return `{"matches": [], "ignoredMatches": [` + strings.Join(matches, ",") + `],
	  "source": {"type": "directory", "target": "/src"}}`
}

// fakeGrypeOutputs writes what Grype would write for each `-o <format>=<path>` in argv: the JSON
// report given, and an empty inventory for CycloneDX.
func fakeGrypeOutputs(t *testing.T, argv []string, report string) {
	t.Helper()
	for i, a := range argv {
		if a != "-o" || i+1 == len(argv) {
			continue
		}
		format, path, ok := strings.Cut(argv[i+1], "=")
		if !ok {
			continue
		}
		body := report
		if format == "cyclonedx-json" {
			body = `{"components": []}`
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// A match a repository's `.grype.yaml` ignored reaches the report as a suppression by the scanner,
// naming the file and the reason, with the package and severity Grype gives a match it reports.
// Two repositories, each with its own file, so the file named is the one in the repository scanned.
func TestAGrypeExclusionArrivesSuppressed(t *testing.T) {
	prior := grypeRunInDir
	t.Cleanup(func() { grypeRunInDir = prior })
	var ranIn string
	grypeRunInDir = func(_ context.Context, dir string, argv []string) ([]byte, error) {
		ranIn = dir
		fakeGrypeOutputs(t, argv, grypeJSON(grypeIgnoredJinja2))
		return []byte(grypeActiveSARIF), nil
	}

	for _, repo := range []struct{ name, config string }{
		{"api", ".grype.yaml"},
		{"worker", ".grype/config.yaml"},
	} {
		dir := t.TempDir()
		path := filepath.Join(dir, filepath.FromSlash(repo.config))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		rule := "ignore:\n  - vulnerability: CVE-2020-28493\n    reason: not reachable from the entry point\n"
		if err := os.WriteFile(path, []byte(rule), 0o600); err != nil {
			t.Fatal(err)
		}
		s := NewGrypeFS().(repoScanner)
		s.checkout = func(context.Context, string, string, git.Scope) (git.Tree, func(), error) {
			return git.Tree{Dir: dir}, func() {}, nil
		}
		rep, err := s.Scan(context.Background(), plugin.RepositoryTarget{URL: repo.name}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if ranIn != dir {
			t.Errorf("%s: Grype ran in %q, away from the repository's configuration", repo.name, ranIn)
		}
		if len(rep.Results) != 2 {
			t.Fatalf("%s: results = %d, want the reported match and the ignored one", repo.name, len(rep.Results))
		}
		var got *sarif.Result
		for i := range rep.Results {
			if rep.Results[i].RuleID == "CVE-2020-28493-jinja2" {
				got = &rep.Results[i]
			} else if rep.Results[i].Suppression != nil {
				t.Errorf("%s: %s was reported by Grype and arrived suppressed", repo.name, rep.Results[i].RuleID)
			}
		}
		if got == nil {
			t.Fatalf("%s: the ignored match is missing, so the exclusion leaves no record", repo.name)
		}
		sup := got.Suppression
		switch {
		case sup == nil:
			t.Fatalf("%s: no suppression, so the exclusion reads as an active finding", repo.name)
		case sup.Origin != sarif.OriginScanner || sup.Kind != "external":
			t.Errorf("%s: origin %q kind %q, want the scanner's own configuration", repo.name, sup.Origin, sup.Kind)
		case sup.Source != repo.config || sup.Justification != "not reachable from the entry point":
			t.Errorf("%s: source %q justification %q", repo.name, sup.Source, sup.Justification)
		}
		if got.Location.URI != "requirements.txt" {
			t.Errorf("%s: location %q, want the repository-relative path active findings get", repo.name, got.Location.URI)
		}
		if got.Level != sarif.LevelWarning || got.Score != 6.9 {
			t.Errorf("%s: level %q score %v, want Grype's own mapping of a medium at 6.9", repo.name, got.Level, got.Score)
		}
		if p := got.Package; p == nil || p.PURL != "pkg:pypi/jinja2@2.10" || p.FixedVersion != "2.11.3" {
			t.Errorf("%s: package %+v, want what Grype states for a match it reports", repo.name, got.Package)
		}
		if r, ok := rep.Rules[got.RuleID]; !ok || r.FullDescription == "" || r.Name != "PythonMatcherExactDirectMatch" {
			t.Errorf("%s: rule %+v", repo.name, r)
		}
	}
}

// The image scanner carries an exclusion across the same way, over two images, with the location
// replaced by the image reference as every image finding's is.
func TestAGrypeImageExclusionArrivesSuppressed(t *testing.T) {
	prior := grypeRun
	t.Cleanup(func() { grypeRun = prior })
	grypeRun = func(_ context.Context, argv []string) ([]byte, error) {
		ref := strings.TrimPrefix(argv[1], "registry:")
		fakeGrypeOutputs(t, argv, `{"ignoredMatches": [`+grypeIgnoredJinja2+`],
		  "source": {"type": "image", "target": {"userInput": "`+ref+`"}}}`)
		return []byte(grypeImageSARIF), nil
	}
	s := NewGrype()
	for _, ref := range []string{"registry.example/api:1.0", "registry.example/worker:1.0"} {
		rep, err := s.Scan(context.Background(), plugin.ImageTarget{Ref: ref}, nil)
		if err != nil {
			t.Fatal(err)
		}
		var got *sarif.Result
		for i := range rep.Results {
			if rep.Results[i].Suppression != nil {
				got = &rep.Results[i]
			}
		}
		if len(rep.Results) != 2 || got == nil {
			t.Fatalf("%s: results %+v, want the reported match and the ignored one", ref, rep.Results)
		}
		if got.Suppression.Origin != sarif.OriginScanner || got.Image != ref || got.Location.URI != ref {
			t.Errorf("%s: origin %q image %q location %q", ref, got.Suppression.Origin, got.Image, got.Location.URI)
		}
		if !strings.Contains(got.Message, "found in image "+ref) {
			t.Errorf("%s: message %q, want Grype's wording for an image", ref, got.Message)
		}
	}
}

// Grype applies its own rules for kernel headers with no configuration at all. A match only those
// ignored is Grype's matching policy rather than a decision anybody made, and stays out.
func TestGrypeDefaultRulesAreNotExclusions(t *testing.T) {
	kernel := strings.Replace(grypeIgnoredJinja2,
		`[{"vulnerability": "CVE-2020-28493", "reason": "not reachable from the entry point", "namespace": ""}]`,
		`[{"package": {"name": "linux-libc-dev", "type": "deb", "upstream-name": "linux"}, "match-type": "exact-indirect-match", "namespace": ""}]`, 1)
	if kernel == grypeIgnoredJinja2 {
		t.Fatal("fixture did not change")
	}
	out, err := withGrypeExclusions([]byte(grypeActiveSARIF), []byte(grypeJSON(kernel)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != grypeActiveSARIF {
		t.Errorf("SARIF changed for a match only a built-in rule ignored:\n%s", out)
	}
}

// A rule the configuration files here do not hold came from somewhere else Grype reads, such as
// the home directory. The suppression names no file rather than one that does not hold the rule;
// a rule with no reason gives none.
func TestAGrypeExclusionNamesOnlyTheFileHoldingIt(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".grype"), 0o750); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		".grype.yaml":                          "ignore:\n  - vulnerability: CVE-0000-0001\n",
		filepath.Join(".grype", "config.yaml"): "ignore:\n  - vulnerability: CVE-2020-28493\n    reason: not reachable from the entry point\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	unreasoned := strings.Replace(grypeIgnoredJinja2, `"reason": "not reachable from the entry point", `, "", 1)
	unreasoned = strings.ReplaceAll(unreasoned, "CVE-2020-28493", "CVE-2099-0001")
	out, err := withGrypeExclusions([]byte(grypeActiveSARIF), []byte(grypeJSON(grypeIgnoredJinja2, unreasoned)), grypeConfigRules(dir))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := parseGrypeSARIF(out)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]*sarif.Suppression{}
	for _, r := range rep.Results {
		got[r.RuleID] = r.Suppression
	}
	if s := got["CVE-2020-28493-jinja2"]; s == nil || s.Source != ".grype/config.yaml" {
		t.Errorf("suppression %+v, want the file holding the rule", s)
	}
	if s := got["CVE-2099-0001-jinja2"]; s == nil || s.Source != "" || s.Justification != "" {
		t.Errorf("suppression %+v, want no file and no reason", s)
	}
}

// A run that wrote no JSON report fails rather than reporting that its configuration excluded
// nothing, which Draugr cannot know. A failed run is Grype's own error, unchanged.
func TestAGrypeRunWithNoRecordOfExclusionsFails(t *testing.T) {
	if _, err := runGrypeRecordingExclusions(func([]string) ([]byte, error) {
		return []byte(grypeActiveSARIF), nil
	}, "", []string{"grype"}); err == nil {
		t.Error("an empty JSON report was read as nothing excluded")
	}
	boom := errors.New("boom")
	if _, err := runGrypeRecordingExclusions(func([]string) ([]byte, error) { return nil, boom }, "", nil); !errors.Is(err, boom) {
		t.Errorf("err = %v, want Grype's own", err)
	}
	if _, err := runGrypeRecordingExclusions(func(argv []string) ([]byte, error) {
		fakeGrypeOutputs(t, argv, "not json")
		return []byte(grypeActiveSARIF), nil
	}, "", []string{"grype"}); err == nil {
		t.Error("an unreadable JSON report was read as nothing excluded")
	}
}

// With nothing excluded the SARIF is returned byte for byte; with something, it must still be a
// document the reader accepts, and unreadable SARIF is an error rather than an empty report.
func TestWithGrypeExclusionsKeepsTheDocument(t *testing.T) {
	if out, err := withGrypeExclusions([]byte(grypeActiveSARIF), []byte(grypeJSON()), nil); err != nil || string(out) != grypeActiveSARIF {
		t.Errorf("out %s err %v, want the SARIF untouched", out, err)
	}
	if _, err := withGrypeExclusions([]byte("not sarif"), []byte(grypeJSON(grypeIgnoredJinja2)), nil); err == nil {
		t.Error("unreadable SARIF was accepted")
	}
	out, err := withGrypeExclusions([]byte(`{"version":"2.1.0","runs":[]}`), []byte(grypeJSON(grypeIgnoredJinja2, grypeIgnoredJinja2)), nil)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []json.RawMessage `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []json.RawMessage `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 2 || len(doc.Runs[0].Tool.Driver.Rules) != 1 {
		t.Errorf("SARIF %s, want one run, both results and the rule once", out)
	}
}

func TestGrypeScoreAndLevel(t *testing.T) {
	for _, c := range []struct {
		m        grypeMatch
		severity string
		want     string
	}{
		{grypeMatch{}, "critical", "9.0"},
		{grypeMatch{}, "negligible", ""},
		{grypeMatch{RelatedVulnerabilities: []grypeVulnerability{{CVSS: []struct {
			Metrics struct {
				BaseScore float64 `json:"baseScore"`
			} `json:"metrics"`
		}{{}}}}}, "high", "7.0"},
	} {
		if got := grypeScore(c.m, c.severity); got != c.want {
			t.Errorf("grypeScore(%s) = %q, want %q", c.severity, got, c.want)
		}
	}
	for severity, want := range map[string]string{"critical": "error", "high": "error", "medium": "warning", "low": "note", "unknown": "note"} {
		if got := grypeLevel(severity); got != want {
			t.Errorf("grypeLevel(%s) = %q, want %q", severity, got, want)
		}
	}
	if grypeMatcherName(grypeMatch{}) != "" || grypeImageRef(grypeDoc{}) != "" {
		t.Error("an empty match named a matcher or an image")
	}
}
