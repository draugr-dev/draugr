package engine

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// devPolicyController is an sca control whose answer is fixed per component.
type devPolicyController struct {
	report map[string]bool
}

func (devPolicyController) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: "sca", Scope: plugin.ScopeComponent}
}
func (devPolicyController) Plan(saga.Model, *saga.Component) ([]plugin.ScanJob, error) {
	return nil, nil
}
func (devPolicyController) Aggregate([]sarif.Report) (plugin.ControlResult, error) {
	return plugin.ControlResult{}, nil
}
func (c devPolicyController) ReportsDevDependencies(_ saga.Model, component string) (bool, string) {
	return c.report[component], "key-for-" + component
}

// devFinding is one finding about nanoid 3.3.7 in a lockfile.
func devFinding(tool, component, repository, location, vuln string, dev bool) sarif.Result {
	return sarif.Result{
		Tool: tool, RuleID: vuln, Level: sarif.LevelError, Component: component, Repository: repository,
		Location: sarif.Location{URI: location},
		Package:  &sarif.Package{Name: "nanoid", Version: "3.3.7", PURL: "pkg:npm/nanoid@3.3.7", Dev: dev},
	}
}

// A finding takes the mark from another scanner's finding about the same package in the same file of
// the same repository and component, and from nothing else: not another file, another repository or
// another component, and not a finding with no package URL.
func TestMarkDevCopiesStaysWithinOneFile(t *testing.T) {
	results := []sarif.Result{
		devFinding("trivy", "web", "one", "pnpm/pnpm-lock.yaml", "CVE-1", true),
		devFinding("grype", "web", "one", "pnpm/pnpm-lock.yaml", "CVE-2", false), // takes it
		devFinding("grype", "web", "one", "app/pnpm-lock.yaml", "CVE-1", false),  // another file
		devFinding("grype", "web", "two", "pnpm/pnpm-lock.yaml", "CVE-1", false), // another repository
		devFinding("grype", "api", "one", "pnpm/pnpm-lock.yaml", "CVE-1", false), // another component
		{Tool: "grype", RuleID: "CVE-1", Component: "web", Repository: "one", Location: sarif.Location{URI: "pnpm/pnpm-lock.yaml"}},
	}
	shared := results[1].Package
	controls := map[string]plugin.ControlResult{"sca": {Report: sarif.Report{Results: results}}}
	markDevCopies(controls)
	got := controls["sca"].Report.Results
	for i, want := range []bool{true, true, false, false, false, false} {
		if dev := got[i].Package != nil && got[i].Package.Dev; dev != want {
			t.Errorf("result %d (%s %s %s): dev %v, want %v", i, got[i].Component, got[i].Repository, got[i].Location.URI, dev, want)
		}
	}
	if shared.Dev {
		t.Error("the mark was written through a package value the scanner handed out, not onto a copy")
	}
}

// Grype names a finding's other identifiers as aliases, and correlation joins two scanners' copies
// across them. The mark does not follow the alias: a Grype finding under a GHSA id that aliases
// Trivy's dev finding takes the mark in the same file, and not in another file, though correlation
// counts both copies as one flaw.
func TestTheDevMarkDoesNotFollowAnAlias(t *testing.T) {
	trivy := devFinding("trivy", "web", "one", "tools/pnpm-lock.yaml", "CVE-2026-0002", true)
	same := devFinding("grype", "web", "one", "tools/pnpm-lock.yaml", "GHSA-2v37-7h3g-55p8", false)
	same.Aliases = []string{"CVE-2026-0002"}
	other := devFinding("grype", "web", "one", "app/pnpm-lock.yaml", "GHSA-2v37-7h3g-55p8", false)
	other.Aliases = []string{"CVE-2026-0002"}

	reg := NewRegistry()
	reg.RegisterController(devPolicyController{})
	e := New(reg)
	controls := map[string]plugin.ControlResult{"sca": {Report: sarif.Report{Results: []sarif.Result{trivy, same, other}}}}
	markDevCopies(controls)
	e.applyDevDependencies(controls, saga.Model{})
	applyCorrelation(controls)

	got := controls["sca"].Report.Results
	if !got[1].Package.Dev || !got[1].SetAsideBySetting() {
		t.Errorf("the aliased copy in the same file: dev %v, suppression %+v, want both", got[1].Package.Dev, got[1].Suppression)
	}
	if got[2].Package.Dev || got[2].Suppressed() {
		t.Errorf("the aliased copy in another file: dev %v, suppression %+v, want neither", got[2].Package.Dev, got[2].Suppression)
	}
	if got[2].Correlated() || !got[0].Correlated() {
		t.Errorf("correlation %+v / %+v, want the alias to join the copies and the runtime one counted",
			got[0].Correlation, got[2].Correlation)
	}
}

// A control with no development-dependency findings, or one with no policy, is left as it was.
func TestMarkDevCopiesLeavesAControlWithNoMark(t *testing.T) {
	results := []sarif.Result{devFinding("grype", "web", "one", "a", "CVE-1", false)}
	controls := map[string]plugin.ControlResult{"sca": {Report: sarif.Report{Results: results}}}
	markDevCopies(controls)
	if controls["sca"].Report.Results[0].Package.Dev {
		t.Error("a finding was marked with nothing to take the mark from")
	}
}

// Each component's answer decides its own findings; a finding a rule already set aside keeps that
// rule's reason; a runtime finding is never touched; a control without a policy is left alone.
func TestApplyDevDependenciesAsksEachComponent(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(devPolicyController{report: map[string]bool{"api": true}})
	e := New(reg)

	excluded := devFinding("trivy", "web", "one", "a", "CVE-9", true)
	excluded.Suppression = &sarif.Suppression{Kind: "external", Origin: sarif.OriginSaga, Justification: "accepted"}
	runtime := devFinding("trivy", "web", "one", "a", "CVE-3", false)
	controls := map[string]plugin.ControlResult{
		"sca": {Report: sarif.Report{Results: []sarif.Result{
			devFinding("trivy", "web", "one", "a", "CVE-1", true),
			devFinding("trivy", "api", "one", "a", "CVE-1", true),
			excluded,
			runtime,
		}}},
		"images": {Report: sarif.Report{Results: []sarif.Result{devFinding("trivy", "web", "", "img", "CVE-1", true)}}},
	}
	if n := e.applyDevDependencies(controls, saga.Model{}); n != 1 {
		t.Errorf("set aside %d, want 1", n)
	}
	got := controls["sca"].Report.Results
	if s := got[0].Suppression; s == nil || s.Origin != sarif.OriginSetting || s.Source != "key-for-web" ||
		s.Justification != sarif.JustificationDevDependency {
		t.Errorf("web's development finding: suppression %+v, want the setting's", s)
	}
	if got[1].Suppressed() {
		t.Error("api reports development dependencies, and its finding was set aside")
	}
	if got[2].Suppression.Origin != sarif.OriginSaga {
		t.Errorf("an excluded finding's reason was replaced: %+v", got[2].Suppression)
	}
	if got[3].Suppressed() {
		t.Error("a runtime finding was set aside")
	}
	if controls["images"].Report.Results[0].Suppressed() {
		t.Error("a control with no policy had a finding set aside")
	}
	if sum := controls["sca"].Summary; sum.Errors != 2 {
		t.Errorf("summary %+v, want the two findings still counted", sum)
	}
}

// providedPolicyController is an sca control with both policies, each answer fixed per component.
type providedPolicyController struct {
	devPolicyController
	provided map[string]bool
}

func (c providedPolicyController) ReportsProvidedDependencies(_ saga.Model, component string) (bool, string) {
	return c.provided[component], "provided-key-for-" + component
}

// providedFinding is one finding about commons-collections 3.2.1 in a pom.
func providedFinding(tool, component, location, vuln string, provided bool) sarif.Result {
	return sarif.Result{
		Tool: tool, RuleID: vuln, Level: sarif.LevelError, Component: component, Repository: "one",
		Location: sarif.Location{URI: location},
		Package: &sarif.Package{Name: "commons-collections", Version: "3.2.1",
			PURL: "pkg:maven/commons-collections/commons-collections@3.2.1", Provided: provided},
	}
}

// The provided mark travels between copies of a package in one file as the development mark does,
// and a finding carrying one mark keeps it while taking the other.
func TestMarkDevCopiesCarriesTheProvidedMark(t *testing.T) {
	both := providedFinding("trivy", "web", "pom.xml", "CVE-1", false)
	both.Package.Dev = true
	results := []sarif.Result{
		providedFinding("grype", "web", "pom.xml", "CVE-1", true),
		providedFinding("trivy", "web", "pom.xml", "CVE-2", false),     // takes it
		providedFinding("trivy", "web", "app/pom.xml", "CVE-1", false), // another file
		providedFinding("trivy", "api", "pom.xml", "CVE-1", false),     // another component
		both, // dev, takes provided
		providedFinding("mend", "web", "pom.xml", "CVE-3", true), // already marked
	}
	controls := map[string]plugin.ControlResult{"sca": {Report: sarif.Report{Results: results}}}
	markDevCopies(controls)
	got := controls["sca"].Report.Results
	for i, want := range []struct{ dev, provided bool }{
		{true, true}, {true, true}, {}, {}, {true, true}, {true, true},
	} {
		if p := got[i].Package; p.Dev != want.dev || p.Provided != want.provided {
			t.Errorf("result %d (%s %s): dev %v provided %v, want %+v", i, got[i].Component, got[i].Location.URI, p.Dev, p.Provided, want)
		}
	}
}

// Each component's providedDependencies decides its own provided findings, with the reason provided
// by the runtime; a finding the development setting already set aside keeps that reason, and a
// control whose controller has no provided policy is left alone.
func TestApplyProvidedDependenciesAsksEachComponent(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(providedPolicyController{provided: map[string]bool{"api": true}})
	reg.RegisterController(namedDevPolicy{name: "licenses"})
	e := New(reg)

	devAndProvided := providedFinding("grype", "web", "pom.xml", "CVE-4", true)
	devAndProvided.Package.Dev = true
	controls := map[string]plugin.ControlResult{
		"sca": {Report: sarif.Report{Results: []sarif.Result{
			providedFinding("grype", "web", "pom.xml", "CVE-1", true),
			providedFinding("grype", "api", "pom.xml", "CVE-1", true),
			providedFinding("grype", "web", "pom.xml", "CVE-2", false),
			devAndProvided,
		}}},
		"licenses": {Report: sarif.Report{Results: []sarif.Result{providedFinding("grype", "web", "pom.xml", "CVE-1", true)}}},
	}
	if n := e.applyDevDependencies(controls, saga.Model{}); n != 1 {
		t.Errorf("development setting set aside %d, want 1", n)
	}
	if n := e.applyProvidedDependencies(controls, saga.Model{}); n != 1 {
		t.Errorf("provided setting set aside %d, want 1", n)
	}
	got := controls["sca"].Report.Results
	if s := got[0].Suppression; s == nil || s.Origin != sarif.OriginSetting || s.Source != "provided-key-for-web" ||
		s.Justification != sarif.JustificationProvidedByRuntime {
		t.Errorf("web's provided finding: suppression %+v, want the provided setting's", s)
	}
	if got[1].Suppressed() {
		t.Error("api reports provided dependencies, and its finding was set aside")
	}
	if got[2].Suppressed() {
		t.Error("a finding the application ships was set aside")
	}
	if s := got[3].Suppression; s == nil || s.Justification != sarif.JustificationDevDependency {
		t.Errorf("a finding marked both: suppression %+v, want the development reason", s)
	}
	if controls["licenses"].Report.Results[0].Suppressed() {
		t.Error("a control with no provided policy had a finding set aside")
	}
}

// The own mark travels between copies of a package in one file as the development mark does.
func TestMarkDevCopiesCarriesTheOwnMark(t *testing.T) {
	own := providedFinding("trivy", "web", "pom.xml", "CVE-1", false)
	own.Package.Own = true
	results := []sarif.Result{
		own,
		providedFinding("grype", "web", "pom.xml", "CVE-1", false),     // takes it
		providedFinding("grype", "web", "app/pom.xml", "CVE-1", false), // another file
	}
	controls := map[string]plugin.ControlResult{"sca": {Report: sarif.Report{Results: results}}}
	markDevCopies(controls)
	got := controls["sca"].Report.Results
	for i, want := range []bool{true, true, false} {
		if got[i].Package.Own != want {
			t.Errorf("result %d (%s %s): own %v, want %v", i, got[i].Tool, got[i].Location.URI, got[i].Package.Own, want)
		}
	}
}

// ownPolicyController answers ownPackages per component: report where own[component] is true. It
// has the development policy too, so a finding marked both shows which setting is asked first.
type ownPolicyController struct {
	devPolicyController
	own map[string]bool
}

func (c ownPolicyController) ReportsOwnPackages(_ saga.Model, component string) (bool, string) {
	return c.own[component], "own-key-for-" + component
}

// Each component's ownPackages decides its own findings, with the reason the project's own package,
// before the development setting is asked, so a finding marked both keeps that reason.
func TestApplyOwnPackagesAsksEachComponentFirst(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(ownPolicyController{own: map[string]bool{"api": true}})
	e := New(reg)

	mark := func(component, vuln string, own, dev bool) sarif.Result {
		r := providedFinding("grype", component, "pom.xml", vuln, false)
		r.Package.Own, r.Package.Dev = own, dev
		return r
	}
	controls := map[string]plugin.ControlResult{"sca": {Report: sarif.Report{Results: []sarif.Result{
		mark("web", "CVE-1", true, false),
		mark("api", "CVE-1", true, false),
		mark("web", "CVE-2", false, false),
		mark("web", "CVE-3", true, true),
	}}}}
	if n := e.applyOwnPackages(controls, saga.Model{}); n != 2 {
		t.Errorf("own setting set aside %d, want 2", n)
	}
	e.applyDevDependencies(controls, saga.Model{})
	got := controls["sca"].Report.Results
	if s := got[0].Suppression; s == nil || s.Origin != sarif.OriginSetting || s.Source != "own-key-for-web" ||
		s.Justification != sarif.JustificationOwnPackage {
		t.Errorf("web's own package: suppression %+v, want the own setting's", s)
	}
	if got[1].Suppressed() {
		t.Error("api reports its own packages, and its finding was set aside")
	}
	if got[2].Suppressed() {
		t.Error("a dependency was set aside")
	}
	if s := got[3].Suppression; s == nil || s.Justification != sarif.JustificationOwnPackage {
		t.Errorf("a finding marked own and dev: suppression %+v, want the own reason", s)
	}
}

// namedDevPolicy is a control with only the development policy, under the name given.
type namedDevPolicy struct {
	devPolicyController
	name string
}

func (c namedDevPolicy) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: c.name, Scope: plugin.ScopeComponent}
}

// One flaw in one package, a development dependency in one lockfile of a repository and a runtime
// one in another. The setting sets the development copy aside, which does not reach the runtime
// copy, and the two are counted apart: the runtime row names no copy the setting set aside, and the
// development copies, found by two scanners, stay one suppressed finding of their own.
func TestASettingDoesNotReachARuntimeCopyOfTheFlaw(t *testing.T) {
	setting := func(r sarif.Result) sarif.Result {
		r.Suppression = &sarif.Suppression{Kind: "external", Origin: sarif.OriginSetting, Justification: sarif.JustificationDevDependency}
		return r
	}
	devTrivy := setting(devFinding("trivy", "web", "one", "tools/bun.lock", "CVE-2026-0001", true))
	devTrivy.Score = 9.8 // the strongest copy, so only the suppression decides which one counts
	devGrype := setting(devFinding("grype", "web", "one", "tools/bun.lock", "CVE-2026-0001", true))
	shipped := devFinding("grype", "web", "one", "app/bun.lock", "CVE-2026-0001", false)
	shipped.Score = 5.0
	controls := map[string]plugin.ControlResult{"sca": {Report: sarif.Report{Results: []sarif.Result{devTrivy, devGrype, shipped}}}}

	groups, extra := applyCorrelation(controls)
	if groups != 1 || extra != 0 {
		t.Errorf("groups %d, extra suppressed %d, want 1 and 0", groups, extra)
	}
	got := controls["sca"].Report.Results
	if got[2].Suppressed() {
		t.Error("the runtime copy took the development copy's suppression")
	}
	if got[2].Correlation != nil {
		t.Errorf("the runtime copy is correlated with %+v, want no copy the setting set aside", got[2].Correlation)
	}
	if got[0].Correlated() || got[0].Correlation == nil || len(got[0].Correlation.AlsoFoundBy) != 1 ||
		got[0].Correlation.AlsoFoundBy[0].Tool != "grype" || got[1].Correlation == nil || got[1].Correlation.CountedUnder != "trivy" {
		t.Errorf("development copies %+v / %+v, want one finding counted under trivy, also found by grype",
			got[0].Correlation, got[1].Correlation)
	}
}

// An exclusion on any copy still excuses the whole flaw, the copies a setting set aside included, and
// they stay one finding.
func TestAnExclusionStillExcusesEveryCopyBesideASetting(t *testing.T) {
	dev := devFinding("trivy", "web", "one", "tools/bun.lock", "CVE-2026-0001", true)
	dev.Suppression = &sarif.Suppression{Kind: "external", Origin: sarif.OriginSetting, Justification: sarif.JustificationDevDependency}
	excluded := devFinding("grype", "web", "one", "app/bun.lock", "CVE-2026-0001", false)
	excluded.Suppression = &sarif.Suppression{Kind: "external", Origin: sarif.OriginSaga, Justification: "accepted"}
	shipped := devFinding("trivy", "web", "one", "app/bun.lock", "CVE-2026-0001", false)
	controls := map[string]plugin.ControlResult{"sca": {Report: sarif.Report{Results: []sarif.Result{dev, excluded, shipped}}}}

	groups, extra := applyCorrelation(controls)
	if groups != 1 || extra != 1 {
		t.Errorf("groups %d, extra suppressed %d, want 1 and 1", groups, extra)
	}
	got := controls["sca"].Report.Results
	if !got[2].Suppressed() || got[2].Suppression.Origin != sarif.OriginSaga {
		t.Errorf("the runtime copy: suppression %+v, want the exclusion's", got[2].Suppression)
	}
	counted := 0
	for _, r := range got {
		if !r.Correlated() {
			counted++
		}
	}
	if counted != 1 {
		t.Errorf("%d copies counted, want the flaw counted once", counted)
	}
}
