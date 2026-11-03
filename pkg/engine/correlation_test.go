package engine

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// found is a finding as one scanner reports it.
func found(tool, rule, purl string, level sarif.Level, score float64) sarif.Result {
	return sarif.Result{
		Tool: tool, RuleID: rule, Level: level, Score: score, HasScore: true,
		Repository: "repo-a", Component: "api",
		Package: &sarif.Package{Name: "flask", PURL: purl},
	}
}

func TestCorrelationCountsOneFlawOnce(t *testing.T) {
	// The arithmetic this exists to fix: two scanners, one flaw, one count. Both findings stay in
	// the report, the disagreement between two scanners is the reason to run two.
	ctrls := controlsWith(
		found("trivy", "CVE-2019-1010083", "pkg:pypi/flask@0.12.2", sarif.LevelError, 8.7),
		found("grype", "CVE-2019-1010083-flask", "pkg:pypi/flask@0.12.2", sarif.LevelError, 8.7),
	)
	groups, _ := applyCorrelation(ctrls)
	if groups != 1 {
		t.Fatalf("groups = %d, want 1", groups)
	}
	if len(ctrls["sca"].Report.Results) != 2 {
		t.Fatalf("results = %d, want both kept", len(ctrls["sca"].Report.Results))
	}
	if n := ctrls["sca"].Report.Counts().Total(); n != 1 {
		t.Errorf("counted %d, want 1, the flaw is one thing to fix", n)
	}
}

func TestCorrelationCountsTheStrongerReading(t *testing.T) {
	// The scanners disagree: medium against low for the same CVE. Reporting the lower would be
	// the report arguing itself down.
	ctrls := controlsWith(
		found("trivy", "CVE-2026-27205", "pkg:pypi/flask@0.12.2", sarif.LevelWarning, 4.3),
		found("grype", "CVE-2026-27205-flask", "pkg:pypi/flask@0.12.2", sarif.LevelNote, 2.3),
	)
	applyCorrelation(ctrls)
	for _, r := range ctrls["sca"].Report.Results {
		if r.Correlated() {
			continue
		}
		if r.Tool != "trivy" || r.Score != 4.3 {
			t.Errorf("counted %s at %v, want the stronger reading", r.Tool, r.Score)
		}
		if len(r.Correlation.AlsoFoundBy) != 1 {
			t.Fatalf("alsoFoundBy = %v, want grype named", r.Correlation.AlsoFoundBy)
		}
		// The other scanner's own rating is kept, not just its name. Two tools rating one CVE
		// medium and low have said something neither says alone, and a reader who only learns
		// that a second tool "also found it" cannot see that.
		other := r.Correlation.AlsoFoundBy[0]
		if other.Tool != "grype" || other.Severity != sarif.SeverityLow || other.Score != 2.3 {
			t.Errorf("observation = %+v, want grype's own low/2.3 reading", other)
		}
		if other.RuleID != "CVE-2026-27205-flask" {
			t.Errorf("ruleId = %q, want what that scanner called it", other.RuleID)
		}
	}
}

func TestCorrelationBreaksTiesTowardTheCanonicalIdentifier(t *testing.T) {
	// Equal severity. The undecorated id is what a reader can look up and what an exclusion is
	// most likely already written against.
	ctrls := controlsWith(
		found("grype", "CVE-2018-1000656-flask", "pkg:pypi/flask@0.12.2", sarif.LevelError, 8.7),
		found("trivy", "CVE-2018-1000656", "pkg:pypi/flask@0.12.2", sarif.LevelError, 8.7),
	)
	applyCorrelation(ctrls)
	for _, r := range ctrls["sca"].Report.Results {
		if !r.Correlated() && r.RuleID != "CVE-2018-1000656" {
			t.Errorf("counted %q, want the canonical identifier", r.RuleID)
		}
	}
}

func TestCorrelationDoesNotCollapseDifferentRepositories(t *testing.T) {
	// A component can hold several, and the same dependency in two of them is two things to fix.
	a := found("trivy", "CVE-2024-11111", "pkg:pypi/flask@0.12.2", sarif.LevelError, 8.7)
	b := found("grype", "CVE-2024-11111-flask", "pkg:pypi/flask@0.12.2", sarif.LevelError, 8.7)
	b.Repository = "repo-b"
	ctrls := controlsWith(a, b)
	if groups, _ := applyCorrelation(ctrls); groups != 0 {
		t.Errorf("groups = %d, want none across repositories", groups)
	}
	if n := ctrls["sca"].Report.Counts().Total(); n != 2 {
		t.Errorf("counted %d, want both", n)
	}
}

func TestCorrelationDoesNotCollapseDifferentPackages(t *testing.T) {
	// One advisory can affect several packages, which is exactly why Grype decorates its ids.
	ctrls := controlsWith(
		found("grype", "CVE-2024-11111-flask", "pkg:pypi/flask@0.12.2", sarif.LevelError, 8.7),
		found("grype", "CVE-2024-11111-django", "pkg:pypi/django@2.0", sarif.LevelError, 8.7),
	)
	if groups, _ := applyCorrelation(ctrls); groups != 0 {
		t.Errorf("groups = %d, want none across packages", groups)
	}
}

func TestCorrelationLeavesFindingsThatAreNotVulnerabilities(t *testing.T) {
	// A leaked credential and a misconfigured resource have no advisory and no package. Inventing
	// a key for them would collapse findings that are not the same flaw.
	ctrls := controlsWith(
		sarif.Result{Tool: "gitleaks", RuleID: "private-key", Level: sarif.LevelError, Repository: "r"},
		sarif.Result{Tool: "semgrep", RuleID: "private-key", Level: sarif.LevelError, Repository: "r"},
	)
	if groups, _ := applyCorrelation(ctrls); groups != 0 {
		t.Errorf("groups = %d, want none without a package and an advisory", groups)
	}
}

func TestCorrelationCarriesADecisionAcrossEveryCopy(t *testing.T) {
	// A reader who excluded a vulnerability excused the vulnerability, not one tool's report of
	// it. Leaving the other copy counted is an exclusion that silently stops working the day a
	// second scanner is added.
	a := found("trivy", "CVE-2024-11111", "pkg:pypi/flask@0.12.2", sarif.LevelError, 8.7)
	a.Suppression = &sarif.Suppression{Kind: "external", Justification: "accepted for now"}
	b := found("grype", "CVE-2024-11111-flask", "pkg:pypi/flask@0.12.2", sarif.LevelError, 8.7)
	ctrls := controlsWith(a, b)

	_, extra := applyCorrelation(ctrls)
	if extra != 1 {
		t.Errorf("extra suppressed = %d, want the second copy excused too", extra)
	}
	for _, r := range ctrls["sca"].Report.Results {
		if !r.Suppressed() {
			t.Errorf("%s copy still counted after the flaw was excused", r.Tool)
			continue
		}
		if r.Suppression.Justification != "accepted for now" {
			t.Errorf("justification = %q, want the reason that was given", r.Suppression.Justification)
		}
	}
	if n := ctrls["sca"].Report.Counts().Total(); n != 0 {
		t.Errorf("counted %d, want none", n)
	}
}

func TestCorrelationIsANoopForOneScanner(t *testing.T) {
	ctrls := controlsWith(found("trivy", "CVE-2024-11111", "pkg:pypi/flask@0.12.2", sarif.LevelError, 8.7))
	groups, extra := applyCorrelation(ctrls)
	if groups != 0 || extra != 0 {
		t.Errorf("groups=%d extra=%d, want zero for a single scanner", groups, extra)
	}
	if ctrls["sca"].Report.Results[0].Correlation != nil {
		t.Error("a finding only one scanner reported should carry no correlation")
	}
}

func TestCorrelationIsNotPartOfFingerprint(t *testing.T) {
	// Which finding of a group happens to be counted is a fact about this run's scanner
	// selection, not about the finding. Folding it in would churn a diff the day somebody adds
	// a second scanner.
	base := found("trivy", "CVE-2024-11111", "pkg:pypi/flask@0.12.2", sarif.LevelError, 8.7)
	marked := base
	marked.Correlation = &sarif.Correlation{AlsoFoundBy: []sarif.Observation{{Tool: "grype"}}}
	if base.Fingerprint() != marked.Fingerprint() {
		t.Error("correlation changed the fingerprint")
	}
}

// Two components shipping the same package at the same version have two flaws, not one.
//
// The monorepo shape makes this the common case rather than an edge one: several components over a
// single repository URL scoped by `paths:`, so the repository is identical across them and only the
// component tells them apart. Collapsed, one team's finding is counted under a component that
// cannot fix it, and the team that can is told it has one fewer than it does.
// Trivy lowercases a Go module's path in the package URL and Grype keeps its case. Their copies of
// one flaw in a module with a capital letter in its path are one flaw, counted once, in the
// component and repository that have it; the other component's copy stays its own.
func TestCorrelationMatchesAGoModuleWhateverItsCase(t *testing.T) {
	const version = "@v0.0.0-20221128193559-754e69321358"
	in := func(tool, rule, purl, component, repo string) sarif.Result {
		r := found(tool, rule, purl, sarif.LevelError, 7.5)
		r.Component, r.Repository = component, repo
		r.Location = sarif.Location{URI: "go.mod"}
		return r
	}
	ctrls := controlsWith(
		in("trivy", "CVE-2026-32952", "pkg:golang/github.com/azure/go-ntlmssp"+version, "api", "repo-api"),
		in("grype", "CVE-2026-32952-github.com/Azure/go-ntlmssp", "pkg:golang/github.com/Azure/go-ntlmssp"+version, "api", "repo-api"),
		in("grype", "CVE-2026-32952-github.com/Azure/go-ntlmssp", "pkg:golang/github.com/Azure/go-ntlmssp"+version, "web", "repo-web"),
	)
	groups, _ := applyCorrelation(ctrls)
	if groups != 1 {
		t.Fatalf("groups = %d, want the api pair alone", groups)
	}
	counted := map[string]int{}
	for _, r := range ctrls["sca"].Report.Results {
		if !r.Correlated() {
			counted[r.Component]++
		}
	}
	if counted["api"] != 1 || counted["web"] != 1 {
		t.Errorf("counted = %v, want one flaw in each component", counted)
	}
	for _, r := range ctrls["sca"].Report.Results {
		if r.Tool == "trivy" && r.Package.PURL != "pkg:golang/github.com/azure/go-ntlmssp"+version {
			t.Errorf("trivy's package URL was rewritten to %q; only the key ignores case", r.Package.PURL)
		}
	}
}

// Only Go's package URLs are compared without case. Another ecosystem's are compared as written.
func TestCorrelationComparesOtherPackageURLsAsWritten(t *testing.T) {
	if got := correlationPURL("pkg:maven/org.Example/Lib@1.0"); got != "pkg:maven/org.Example/Lib@1.0" {
		t.Errorf("a maven package URL became %q", got)
	}
}

func TestCorrelationDoesNotCrossAComponent(t *testing.T) {
	inComponent := func(name, tool, path string) sarif.Result {
		r := found(tool, "CVE-2020-11023", "pkg:npm/jquery@1.8.3", sarif.LevelWarning, 6.9)
		r.Component = name
		r.Location = sarif.Location{URI: path}
		return r
	}
	ctrls := controlsWith(
		inComponent("api", "retirejs", "app/static/js/jquery.min.js"),
		inComponent("storefront", "trivy", "web/package-lock.json"),
		inComponent("storefront", "retirejs", "web/static/js/jquery.min.js"),
	)
	groups, _ := applyCorrelation(ctrls)
	if groups != 1 {
		t.Fatalf("groups = %d, want only the two inside one component", groups)
	}
	for _, r := range ctrls["sca"].Report.Results {
		if r.Component == "api" && r.Correlated() {
			t.Errorf("api's finding is counted under another component: %+v", r.Correlation)
		}
	}
	var counted int
	for _, r := range ctrls["sca"].Report.Results {
		if !r.Correlated() {
			counted++
		}
	}
	if counted != 2 {
		t.Errorf("counted = %d, want one per component", counted)
	}
}

// One advisory in one package version is one flaw per repository, however many lockfiles hold it,
// whether Trivy reports it under a CVE or under the Node Security Working Group's own identifier.
// Two components in two repositories, each with the package pinned in two lockfiles: each
// repository counts each advisory once, with its other lockfile's copy listed behind it.
func TestCorrelationCountsAnNSWGAdvisoryOncePerRepository(t *testing.T) {
	in := func(rule, component, repo, lockfile string) sarif.Result {
		return sarif.Result{
			Tool: "trivy", RuleID: rule, Level: sarif.LevelWarning,
			Component: component, Repository: repo,
			Location: sarif.Location{URI: lockfile},
			Package:  &sarif.Package{Name: "deep-extend", Version: "0.4.2", PURL: "pkg:npm/deep-extend@0.4.2"},
		}
	}
	var results []sarif.Result
	for _, subject := range []struct{ component, repo string }{{"shop", "repo-shop"}, {"blog", "repo-blog"}} {
		for _, lockfile := range []string{"web/yarn.lock", "admin/yarn.lock"} {
			for _, rule := range []string{"CVE-2018-3750", "NSWG-ECO-408"} {
				results = append(results, in(rule, subject.component, subject.repo, lockfile))
			}
		}
	}
	ctrls := controlsWith(results...)

	if groups, _ := applyCorrelation(ctrls); groups != 4 {
		t.Fatalf("groups = %d, want one per advisory per repository", groups)
	}
	counted := map[string]int{}
	behind := map[string]int{}
	for _, r := range ctrls["sca"].Report.Results {
		key := r.Repository + " " + r.RuleID
		if r.Correlated() {
			behind[key]++
			continue
		}
		counted[key]++
		if len(r.Correlation.AlsoFoundBy) != 1 || r.Correlation.AlsoFoundBy[0].RuleID != r.RuleID {
			t.Errorf("%s: alsoFoundBy = %+v, want the other lockfile's copy", key, r.Correlation.AlsoFoundBy)
		}
	}
	for _, repo := range []string{"repo-shop", "repo-blog"} {
		for _, rule := range []string{"CVE-2018-3750", "NSWG-ECO-408"} {
			key := repo + " " + rule
			if counted[key] != 1 || behind[key] != 1 {
				t.Errorf("%s: counted %d, behind %d; want 1 and 1", key, counted[key], behind[key])
			}
		}
	}
	if n := ctrls["sca"].Report.Counts().Total(); n != 4 {
		t.Errorf("counted %d, want 4: two advisories in each of two repositories", n)
	}
}

// A retire.js advisory with neither a CVE nor a GitHub advisory id is one flaw per repository however
// many vendored copies of the library hold it, as its CVE advisories are. Two components in two
// repositories, each vendoring one jQuery bundle twice: each repository counts each advisory once,
// with the other copy behind it, and the two retire.js advisories stay two.
func TestCorrelationCountsARetireJSAdvisoryOncePerRepository(t *testing.T) {
	in := func(rule, component, repo, file string) sarif.Result {
		return sarif.Result{
			Tool: "retirejs", RuleID: rule, Level: sarif.LevelWarning,
			Component: component, Repository: repo,
			Location: sarif.Location{URI: file},
			Package:  &sarif.Package{Name: "jquery", Version: "1.11.2", PURL: "pkg:npm/jquery@1.11.2"},
		}
	}
	rules := []string{"CVE-2015-9251", "retirejs:jquery:11974", "retirejs:jquery:73"}
	var results []sarif.Result
	for _, subject := range []struct{ component, repo string }{{"shop", "repo-shop"}, {"blog", "repo-blog"}} {
		for _, file := range []string{"site/apache-maven-fluido-1.5.min.js", "docs/apache-maven-fluido-1.5.min.js"} {
			for _, rule := range rules {
				results = append(results, in(rule, subject.component, subject.repo, file))
			}
		}
	}
	ctrls := controlsWith(results...)

	if groups, _ := applyCorrelation(ctrls); groups != 6 {
		t.Fatalf("groups = %d, want one per advisory per repository", groups)
	}
	counted := map[string]int{}
	behind := map[string]int{}
	for _, r := range ctrls["sca"].Report.Results {
		key := r.Repository + " " + r.RuleID
		if r.Correlated() {
			behind[key]++
			continue
		}
		counted[key]++
		if len(r.Correlation.AlsoFoundBy) != 1 || r.Correlation.AlsoFoundBy[0].RuleID != r.RuleID {
			t.Errorf("%s: alsoFoundBy = %+v, want the other copy", key, r.Correlation.AlsoFoundBy)
		}
	}
	for _, repo := range []string{"repo-shop", "repo-blog"} {
		for _, rule := range rules {
			key := repo + " " + rule
			if counted[key] != 1 || behind[key] != 1 {
				t.Errorf("%s: counted %d, behind %d; want 1 and 1", key, counted[key], behind[key])
			}
		}
	}
	if n := ctrls["sca"].Report.Counts().Total(); n != 6 {
		t.Errorf("counted %d, want 6: three advisories in each of two repositories", n)
	}
}

// Trivy and Grype reading one image report one flaw, and the same flaw in a second image of the same
// component is a second one. An image finding carries no repository, so the image is what keeps two
// images of one component apart.
func TestCorrelationCountsOneFlawPerImage(t *testing.T) {
	inImage := func(tool, rule, ref string) sarif.Result {
		r := found(tool, rule, "pkg:pypi/flask@0.12.2", sarif.LevelError, 7.5)
		r.Repository = ""
		r.Image = ref
		r.Location = sarif.Location{URI: ref}
		return r
	}
	ctrls := controlsWith(
		inImage("trivy", "CVE-2018-1000656", "registry.example/api:1.0"),
		inImage("grype", "CVE-2018-1000656-flask", "registry.example/api:1.0"),
		inImage("trivy", "CVE-2018-1000656", "registry.example/worker:1.0"),
		inImage("grype", "CVE-2018-1000656-flask", "registry.example/worker:1.0"),
	)
	groups, _ := applyCorrelation(ctrls)
	if groups != 2 {
		t.Fatalf("groups = %d, want one per image", groups)
	}
	counted := map[string]int{}
	for _, r := range ctrls["sca"].Report.Results {
		if r.Correlated() {
			continue
		}
		counted[r.Image]++
		if len(r.Correlation.AlsoFoundBy) != 1 || r.Correlation.AlsoFoundBy[0].Tool != "grype" {
			t.Errorf("%s: alsoFoundBy = %+v, want grype", r.Image, r.Correlation.AlsoFoundBy)
		}
	}
	if counted["registry.example/api:1.0"] != 1 || counted["registry.example/worker:1.0"] != 1 {
		t.Errorf("counted = %v, want one finding per image", counted)
	}
}
