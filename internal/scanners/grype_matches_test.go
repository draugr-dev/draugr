package scanners

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/tooladapter"
)

// grypeTestMatch is one match of one advisory in minimatch.
type grypeTestMatch struct {
	vuln, related, severity string
	score                   float64
	version, fix, path      string
}

func (m grypeTestMatch) purl() string { return "pkg:npm/minimatch@" + m.version }

// minimatchMatches is trimmed from Grype's JSON report for n8n-io/n8n, with the identifiers
// `--by-cve` reports, in the order Grype wrote them. One advisory matches minimatch at six versions
// across two lockfiles, five of them in one file, so the rule and the file alone cannot tell the
// copies apart. A second advisory matches two of the same versions with a different fixed version
// for each, so a fixed version taken from the wrong match shows too.
var minimatchMatches = []grypeTestMatch{
	{"CVE-2026-118764", "GHSA-g3hv-75wg-m249", "Medium", 6.9, "10.2.3", "11.0.1", "/pnpm-lock.yaml"},
	{"CVE-2026-118764", "GHSA-g3hv-75wg-m249", "Medium", 6.9, "10.2.4", "11.0.1", "/.github/scripts/pnpm-lock.yaml"},
	{"CVE-2026-118764", "GHSA-g3hv-75wg-m249", "Medium", 6.9, "5.1.8", "11.0.1", "/pnpm-lock.yaml"},
	{"CVE-2026-118764", "GHSA-g3hv-75wg-m249", "Medium", 6.9, "8.0.4", "11.0.1", "/pnpm-lock.yaml"},
	{"CVE-2026-118764", "GHSA-g3hv-75wg-m249", "Medium", 6.9, "9.0.1", "11.0.1", "/pnpm-lock.yaml"},
	{"CVE-2026-118764", "GHSA-g3hv-75wg-m249", "Medium", 6.9, "9.0.9", "11.0.1", "/pnpm-lock.yaml"},
	{"CVE-2026-26996", "GHSA-3ppc-4f35-3m26", "High", 8.7, "8.0.4", "8.0.5", "/pnpm-lock.yaml"},
	{"CVE-2026-26996", "GHSA-3ppc-4f35-3m26", "High", 8.7, "9.0.1", "9.0.6", "/pnpm-lock.yaml"},
}

// minimatchImageMatches are the same advisories over the copies of minimatch an image holds, one
// per node_modules directory.
var minimatchImageMatches = []grypeTestMatch{
	{"CVE-2026-118764", "GHSA-g3hv-75wg-m249", "Medium", 6.9, "10.2.3", "11.0.1", "/app/node_modules/minimatch/package.json"},
	{"CVE-2026-118764", "GHSA-g3hv-75wg-m249", "Medium", 6.9, "5.1.8", "11.0.1", "/app/node_modules/glob/node_modules/minimatch/package.json"},
	{"CVE-2026-118764", "GHSA-g3hv-75wg-m249", "Medium", 6.9, "9.0.1", "11.0.1", "/usr/local/lib/node_modules/npm/node_modules/minimatch/package.json"},
	{"CVE-2026-26996", "GHSA-3ppc-4f35-3m26", "High", 8.7, "9.0.1", "9.0.6", "/usr/local/lib/node_modules/npm/node_modules/minimatch/package.json"},
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// grypeTestJSON is Grype's JSON report for matches: of a directory, or of image where one is named.
func grypeTestJSON(t *testing.T, matches []grypeTestMatch, image string) string {
	t.Helper()
	ms := []any{}
	for _, m := range matches {
		ms = append(ms, map[string]any{
			"vulnerability": map[string]any{
				"id": m.vuln, "dataSource": "https://github.com/advisories/" + m.related,
				"namespace": "github:language:javascript", "severity": m.severity,
				"cvss": []any{map[string]any{"metrics": map[string]any{"baseScore": m.score}}},
				"fix":  map[string]any{"versions": []string{m.fix}, "state": "fixed"},
			},
			"relatedVulnerabilities": []any{map[string]any{"id": m.related, "severity": m.severity}},
			"matchDetails":           []any{map[string]any{"type": "exact-direct-match", "matcher": "javascript-matcher"}},
			"artifact": map[string]any{
				"name": "minimatch", "version": m.version, "type": "npm", "purl": m.purl(),
				"locations": []any{map[string]any{"path": m.path, "accessPath": m.path}},
			},
		})
	}
	source := map[string]any{"type": "directory", "target": "/src"}
	if image != "" {
		source = map[string]any{"type": "image", "target": map[string]any{"userInput": image}}
	}
	return mustJSON(t, map[string]any{"matches": ms, "ignoredMatches": []any{}, "source": source})
}

// grypeTestSARIF is the SARIF Grype writes for the same matches, built as Grype's SARIF presenter
// builds it: one rule per advisory and package name, described by the first match of it, and one
// result per match, whose message states its version. An image finding's location is the image's
// short name joined to the package's path.
func grypeTestSARIF(t *testing.T, matches []grypeTestMatch, image string) string {
	t.Helper()
	var rules, results []any
	seen := map[string]bool{}
	for _, m := range matches {
		id := m.vuln + "-minimatch"
		severity := strings.ToLower(m.severity)
		uri, where := m.path, "at: "+m.path
		if image != "" {
			name := image[strings.LastIndex(image, "/")+1:]
			name, _, _ = strings.Cut(name, ":")
			uri, where = name+"/"+m.path, fmt.Sprintf("in image %s at: %s", image, m.path)
		}
		if !seen[id] {
			seen[id] = true
			rules = append(rules, map[string]any{
				"id": id, "name": "JavascriptMatcherExactDirectMatch",
				"shortDescription": map[string]any{"text": fmt.Sprintf("%s %s vulnerability for minimatch package", m.vuln, severity)},
				"helpUri":          "https://github.com/advisories/" + m.related,
				"help": map[string]any{"text": fmt.Sprintf(
					"Vulnerability %s\nSeverity: %s\nPackage: minimatch\nVersion: %s\nFix Version: %s\nType: npm\nLocation: %s\n"+
						"Data Namespace: github:language:javascript\nLink: [%s](https://github.com/advisories/%s)",
					m.vuln, severity, m.version, m.fix, m.path, m.vuln, m.related)},
				"properties": map[string]any{"security-severity": fmt.Sprintf("%.1f", m.score), "purls": []string{m.purl()}},
			})
		}
		sum := sha256.Sum256([]byte(image + "npm" + "minimatch" + m.version + m.path))
		results = append(results, map[string]any{
			"ruleId":  id,
			"level":   grypeLevel(severity),
			"message": map[string]any{"text": fmt.Sprintf("A %s vulnerability in npm package: minimatch, version %s was found %s", severity, m.version, where)},
			"locations": []any{map[string]any{"physicalLocation": map[string]any{
				"artifactLocation": map[string]any{"uri": uri},
				"region":           map[string]any{"startLine": 1, "startColumn": 1, "endLine": 1, "endColumn": 1},
			}}},
			"partialFingerprints": map[string]any{"primaryLocationLineHash": fmt.Sprintf("%x:1", sum)},
		})
	}
	return mustJSON(t, map[string]any{"version": "2.1.0", "runs": []any{map[string]any{
		"tool":    map[string]any{"driver": map[string]any{"name": "grype", "informationUri": "https://github.com/anchore/grype", "rules": rules}},
		"results": results,
	}}})
}

// trivyTestJSON is Trivy's JSON report of the same packages: by lockfile for a repository, under
// Node.js for an image.
func trivyTestJSON(t *testing.T, matches []grypeTestMatch, image bool) string {
	t.Helper()
	var targets []string
	vulns := map[string][]any{}
	for _, m := range matches {
		target := strings.TrimPrefix(m.path, "/")
		if image {
			target = "Node.js"
		}
		if !slices.Contains(targets, target) {
			targets = append(targets, target)
		}
		vulns[target] = append(vulns[target], map[string]any{
			"VulnerabilityID": m.vuln, "PkgName": "minimatch", "InstalledVersion": m.version, "FixedVersion": m.fix,
			"Status":        "fixed",
			"PkgIdentifier": map[string]any{"PURL": m.purl(), "UID": "aaaaaaaaaaaaaaaa"},
			"Severity":      "HIGH", "Title": "minimatch: Denial of Service via crafted glob pattern expansion",
			"CVSS": map[string]any{"ghsa": map[string]any{"V3Score": 7.5}},
		})
	}
	var results []any
	for _, target := range targets {
		typ := "pnpm"
		if image {
			typ = "node-pkg"
		}
		results = append(results, map[string]any{"Target": target, "Class": "lang-pkgs", "Type": typ, "Vulnerabilities": vulns[target]})
	}
	return mustJSON(t, map[string]any{"SchemaVersion": 2, "Results": results})
}

// matchController plans each of its scanners over every repository, or every image, a component
// declares.
type matchController struct {
	control  string
	scanners []string
}

func (c matchController) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: c.control, Scope: plugin.ScopeComponent, DefaultScanners: c.scanners}
}

func (c matchController) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	var jobs []plugin.ScanJob
	for _, scanner := range c.scanners {
		if c.control == "images" {
			for _, img := range comp.Images {
				jobs = append(jobs, plugin.ScanJob{Scanner: scanner, Target: plugin.ImageTarget{Ref: img.Image}})
			}
			continue
		}
		for _, r := range comp.Repositories {
			jobs = append(jobs, plugin.ScanJob{Scanner: scanner, Target: plugin.RepositoryTarget{URL: r.URL}})
		}
	}
	return jobs, nil
}

func (c matchController) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	return plugin.ControlResult{Control: c.control, Report: sarif.Merge(reports...)}, nil
}

// scanOnly is a scanner with its database warm-up, version probe and data reader hidden, each of
// which would run the real tool.
type scanOnly struct{ plugin.Scanner }

// checkMatchedFindings checks every finding of the control: each Grype finding carries the package
// of the match its message names, and each is counted together with Trivy's copy of the same
// version and no other, per component and per repository or image.
func checkMatchedFindings(t *testing.T, res engine.Result, control string, matches []grypeTestMatch, subjects []string) {
	t.Helper()
	fixes := map[string]string{}
	for _, m := range matches {
		fixes[m.vuln+"@"+m.version] = m.fix
	}
	tools := map[string]int{}
	for _, r := range res.Controls[control].Report.Results {
		subject := r.Component + " " + r.Repository + r.Image
		if !slices.Contains(subjects, subject) {
			t.Errorf("%s: finding under %q, want one of %q", r.RuleID, subject, subjects)
		}
		tools[r.Tool]++
		p := r.Package
		if p == nil {
			t.Errorf("%s %s: %s carries no package", subject, r.Tool, r.RuleID)
			continue
		}
		key := r.VulnerabilityID() + "@" + p.Version
		if want, ok := fixes[key]; !ok || p.FixedVersion != want || p.PURL != "pkg:npm/minimatch@"+p.Version {
			t.Errorf("%s %s: %s package %+v, want the match at that version, fixed in %q", subject, r.Tool, r.RuleID, *p, want)
		}
		if strings.HasPrefix(r.Tool, "grype") && !strings.Contains(r.Message, "version "+p.Version+" was found") {
			t.Errorf("%s: %s message %q, package version %s: the finding carries another match's version", subject, r.RuleID, r.Message, p.Version)
		}
		switch c := r.Correlation; {
		case c == nil:
			t.Errorf("%s %s: %s %s is not correlated with the other scanner's copy", subject, r.Tool, r.RuleID, p.Version)
		case c.CountedUnder == "" && len(c.AlsoFoundBy) != 1:
			t.Errorf("%s %s: %s %s counts %d other copies, want the other scanner's at this version alone",
				subject, r.Tool, r.RuleID, p.Version, len(c.AlsoFoundBy))
		}
	}
	for tool, n := range tools {
		if n != len(matches)*len(subjects) {
			t.Errorf("%s: %d findings, want %d per subject over %d subjects", tool, n, len(matches), len(subjects))
		}
	}
	if len(tools) != 2 {
		t.Errorf("tools %v, want Grype and Trivy", tools)
	}
}

// One advisory matching one package at several versions, in several lockfiles, over two
// repositories and two components that share one of them, through the engine. Each Grype finding
// keeps its own version, fixed version and package URL, and is counted with Trivy's copy at that
// version alone.
func TestGrypeRepoFindingsEachCarryTheirOwnMatch(t *testing.T) {
	dirs := map[string]string{"one": t.TempDir(), "two": t.TempDir()}
	checkout := func(_ context.Context, url, _ string, _ git.Scope) (git.Tree, func(), error) {
		return git.Tree{Dir: dirs[url]}, func() {}, nil
	}

	prior := grypeRunInDir
	t.Cleanup(func() { grypeRunInDir = prior })
	grypeRunInDir = func(_ context.Context, _ string, argv []string) ([]byte, error) {
		fakeGrypeOutputs(t, argv, grypeTestJSON(t, minimatchMatches, ""))
		return []byte(grypeTestSARIF(t, minimatchMatches, "")), nil
	}
	grype := NewGrypeFS().(repoScanner)
	grype.checkout, grype.prewarm, grype.cacheVersion, grype.dataState = checkout, nil, nil, nil

	trivyOut := trivyTestJSON(t, minimatchMatches, false)
	trivy := NewTrivyFS().(repoScanner)
	trivy.checkout, trivy.prewarm, trivy.cacheVersion, trivy.dataState = checkout, nil, nil, nil
	trivy.run = func(context.Context, string, []string) ([]byte, error) { return []byte(trivyOut), nil }

	reg := engine.NewRegistry()
	reg.RegisterController(matchController{control: "sca", scanners: []string{"grype-fs", "trivy-fs"}})
	reg.RegisterScanner(grype)
	reg.RegisterScanner(trivy)
	model := saga.Model{
		Config: saga.Config{Controls: map[string]saga.ControllerSettings{"sca": {"enabled": true}}},
		Components: []saga.Component{
			{Name: "api", Repositories: []saga.Repository{{URL: "one"}, {URL: "two"}}},
			{Name: "worker", Repositories: []saga.Repository{{URL: "two"}}},
		},
	}
	res, err := engine.New(reg).Run(context.Background(), model)
	if err != nil {
		t.Fatal(err)
	}
	checkMatchedFindings(t, res, "sca", minimatchMatches, []string{"api one", "api two", "worker two"})
}

// The image scanner reads the same report the same way, over two images and two components that
// share one of them.
func TestGrypeImageFindingsEachCarryTheirOwnMatch(t *testing.T) {
	prior := grypeRun
	t.Cleanup(func() { grypeRun = prior })
	grypeRun = func(_ context.Context, argv []string) ([]byte, error) {
		ref := strings.TrimPrefix(argv[1], "registry:")
		fakeGrypeOutputs(t, argv, grypeTestJSON(t, minimatchImageMatches, ref))
		return []byte(grypeTestSARIF(t, minimatchImageMatches, ref)), nil
	}
	trivyOut := trivyTestJSON(t, minimatchImageMatches, true)
	trivy := tooladapter.New(tooladapter.Config{
		Name: "trivy", Binary: "trivy", Controls: []string{"images"},
		TargetKinds: []plugin.TargetKind{plugin.TargetImage},
		Argv: func(target plugin.Target, _ plugin.Config) ([]string, error) {
			return []string{"trivy", "image", target.(plugin.ImageTarget).Ref}, nil
		},
		Run:    func(context.Context, []string) ([]byte, error) { return []byte(trivyOut), nil },
		Parse:  parseTrivyImage,
		Refine: imageRefLocations,
	})

	reg := engine.NewRegistry()
	reg.RegisterController(matchController{control: "images", scanners: []string{"grype", "trivy"}})
	reg.RegisterScanner(scanOnly{NewGrype()})
	reg.RegisterScanner(trivy)
	model := saga.Model{
		Config: saga.Config{Controls: map[string]saga.ControllerSettings{"images": {"enabled": true}}},
		Components: []saga.Component{
			{Name: "api", Images: []saga.Image{{Image: "registry.example/api:1.0"}, {Image: "registry.example/worker:1.0"}}},
			{Name: "worker", Images: []saga.Image{{Image: "registry.example/worker:1.0"}}},
		},
	}
	res, err := engine.New(reg).Run(context.Background(), model)
	if err != nil {
		t.Fatal(err)
	}
	checkMatchedFindings(t, res, "images", minimatchImageMatches,
		[]string{"api registry.example/api:1.0", "api registry.example/worker:1.0", "worker registry.example/worker:1.0"})
}

// An ignored match carries its own package too, though it shares its rule with a reported match at
// another version.
func TestAnIgnoredGrypeMatchCarriesItsOwnPackage(t *testing.T) {
	var reported, ignored map[string]any
	if err := json.Unmarshal([]byte(grypeTestJSON(t, minimatchMatches[:2], "")), &reported); err != nil {
		t.Fatal(err)
	}
	ms := reported["matches"].([]any)
	ignored = ms[1].(map[string]any)
	ignored["appliedIgnoreRules"] = []any{map[string]any{"vulnerability": "CVE-2026-118764", "reason": "not reachable"}}
	reported["matches"], reported["ignoredMatches"] = ms[:1], []any{ignored}

	out, err := withGrypeJSON([]byte(grypeTestSARIF(t, minimatchMatches[:1], "")), []byte(mustJSON(t, reported)), nil)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := parseGrypeRepoSARIF(out, "/src", nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range rep.Results {
		if r.Package == nil {
			t.Fatalf("%s at %s carries no package", r.RuleID, r.Location.URI)
		}
		got[r.Location.URI] = r.Package.Version
	}
	want := map[string]string{"pnpm-lock.yaml": "10.2.3", ".github/scripts/pnpm-lock.yaml": "10.2.4"}
	if !maps.Equal(got, want) {
		t.Errorf("versions by location %v, want %v", got, want)
	}
}

// A result whose match is not in the JSON report never takes another match's package. The rule's
// help text describes one match, so a result takes it only where the rule has no other result or
// the result states the same version; any other carries no package.
func TestAGrypeResultWithNoMatchNeverTakesAnotherVersion(t *testing.T) {
	out := grypeTestSARIF(t, minimatchMatches, "")
	rep, err := parseGrypeSARIF([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rep.Results {
		_, version, _ := grypeMessagePackage(r.Message)
		switch {
		case r.Package == nil:
			if version == "10.2.3" && r.RuleID == "CVE-2026-118764-minimatch" || version == "8.0.4" && r.RuleID == "CVE-2026-26996-minimatch" {
				t.Errorf("%s %s: no package, though the rule describes this version", r.RuleID, version)
			}
		case r.Package.Version != version:
			t.Errorf("%s: package %s on a result at version %s", r.RuleID, r.Package.Version, version)
		}
	}

	// One result per rule: the rule describes it, whatever its message says.
	single := grypeTestSARIF(t, minimatchMatches[6:7], "")
	single = strings.Replace(single, "version 8.0.4 was found at", "was found at", 1)
	rep, err = parseGrypeSARIF([]byte(single))
	if err != nil {
		t.Fatal(err)
	}
	if p := rep.Results[0].Package; p == nil || p.Version != "8.0.4" || p.FixedVersion != "8.0.5" {
		t.Errorf("package %+v, want the rule's own", p)
	}
}

// Pairing narrows by the package type the message names and by location, and refuses to choose
// between matches that fit equally and disagree.
func TestGrypeMatchIndexFind(t *testing.T) {
	var doc grypeDoc
	if err := json.Unmarshal([]byte(grypeTestJSON(t, minimatchMatches, "")), &doc); err != nil {
		t.Fatal(err)
	}
	// A second copy of 9.0.9 in another file, whose package URL differs, and a package of another
	// type at the same version.
	other := doc.Matches[5]
	other.Artifact.PURL = "pkg:npm/minimatch@9.0.9?repository_url=https://npm.example"
	other.Artifact.Locations = slices.Clone(other.Artifact.Locations)
	other.Artifact.Locations[0].Path, other.Artifact.Locations[0].AccessPath = "/docs/pnpm-lock.yaml", ""
	gem := doc.Matches[5]
	gem.Artifact.Type, gem.Artifact.PURL = "gem", "pkg:gem/minimatch@9.0.9"
	unplaced := doc.Matches[0]
	unplaced.Artifact.Locations = nil
	index := newGrypeMatchIndex(append(doc.Matches, other, gem, unplaced))

	msg := func(kind, version, path string) string {
		return fmt.Sprintf("A medium vulnerability in %s package: minimatch, version %s was found at: %s", kind, version, path)
	}
	for _, c := range []struct {
		name, message, uri, purl string
	}{
		{"by location", msg("npm", "9.0.9", "/pnpm-lock.yaml"), "/pnpm-lock.yaml", "pkg:npm/minimatch@9.0.9"},
		{"the deeper file", msg("npm", "9.0.9", "/docs/pnpm-lock.yaml"), "/docs/pnpm-lock.yaml", other.Artifact.PURL},
		{"by type", msg("gem", "9.0.9", "/pnpm-lock.yaml"), "/pnpm-lock.yaml", "pkg:gem/minimatch@9.0.9"},
		{"a location no match has, where the matches disagree", msg("npm", "9.0.9", "/elsewhere.yaml"), "/elsewhere.yaml", ""},
		{"no stated version", "vuln", "/pnpm-lock.yaml", ""},
		{"a version with no match", msg("npm", "1.0.0", "/pnpm-lock.yaml"), "/pnpm-lock.yaml", ""},
		{"a location no match has, where the matches agree", msg("npm", "10.2.3", "/elsewhere.yaml"), "/elsewhere.yaml", "pkg:npm/minimatch@10.2.3"},
	} {
		t.Run(c.name, func(t *testing.T) {
			pkg, _, ok := index.find("CVE-2026-118764-minimatch", c.message, c.uri)
			if ok != (c.purl != "") || pkg.PURL != c.purl {
				t.Errorf("find = %+v, %v, want %q", pkg, ok, c.purl)
			}
		})
	}
}

// Stamping leaves a document it has nothing to add to as it was, and refuses SARIF it cannot read.
func TestWithGrypeMatchPackagesKeepsTheDocument(t *testing.T) {
	var doc grypeDoc
	if err := json.Unmarshal([]byte(grypeTestJSON(t, minimatchMatches, "")), &doc); err != nil {
		t.Fatal(err)
	}
	if out, err := withGrypeMatchPackages([]byte(grypeActiveSARIF), doc.Matches); err != nil || string(out) != grypeActiveSARIF {
		t.Errorf("out %s err %v, want the SARIF untouched", out, err)
	}
	if _, err := withGrypeJSON([]byte("not sarif"), []byte(grypeTestJSON(t, minimatchMatches, "")), nil); err == nil {
		t.Error("unreadable SARIF was accepted")
	}
	odd := `{"version":"2.1.0","runs":[{"results":["not a result",{"ruleId":"CVE-2026-118764-minimatch",` +
		`"message":{"text":"A medium vulnerability in npm package: minimatch, version 5.1.8 was found at: /pnpm-lock.yaml"},` +
		`"properties":{"tool":"grype"}}]}]}`
	out, err := withGrypeMatchPackages([]byte(odd), doc.Matches)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Runs []struct {
			Results []json.RawMessage `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Properties struct {
			Tool    string         `json:"tool"`
			Package *sarif.Package `json:"package"`
		} `json:"properties"`
	}
	if len(got.Runs) != 1 || len(got.Runs[0].Results) != 2 || json.Unmarshal(got.Runs[0].Results[1], &result) != nil {
		t.Fatalf("SARIF %s, want both entries kept", out)
	}
	if p := result.Properties.Package; p == nil || p.Version != "5.1.8" || result.Properties.Tool != "grype" {
		t.Errorf("properties %+v, want the match's package beside the properties the result had", result.Properties)
	}
}
