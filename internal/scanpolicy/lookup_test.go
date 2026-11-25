package scanpolicy

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/exploit"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// goRecords are Go vulnerability database records as index/vulns.json lists them. The first two
// are real; GO-2099-0001 and GO-2099-0002 both list one GitHub advisory id, so naming it says
// nothing about which of them a finding is.
var goRecords = map[string][]string{
	"GO-2020-0001": {"CVE-2020-36567", "GHSA-6vm3-jj99-7229"},
	"GO-2020-0003": {"CVE-2020-36568", "GHSA-hggr-p7v6-73p5"},
	"GO-2099-0001": {"CVE-2099-0001", "GHSA-2222-3333-4444"},
	"GO-2099-0002": {"CVE-2099-0002", "GHSA-2222-3333-4444"},
}

// kevWithLookup is a source whose KEV lists every CVE in goRecords, able to look findings up there.
func kevWithLookup(advisories *exploit.Advisories) *exploit.Source {
	kev := map[string]bool{}
	for _, aliases := range goRecords {
		for _, a := range aliases {
			if strings.HasPrefix(a, "CVE-") {
				kev[a] = true
			}
		}
	}
	return exploit.NewFrom(exploit.Options{KEV: kev, Advisories: advisories})
}

// A finding named only by its Go advisory id, or only by a GitHub advisory id one record lists, is
// raised by KEV on the CVE that record lists, and records where the CVE came from.
func TestAFindingNamedOnlyByAnAdvisoryIsRaisedThroughItsRecord(t *testing.T) {
	fetched := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	src := kevWithLookup(exploit.NewAdvisories(exploit.DatasetGoVulnDB, fetched, goRecords))
	for _, c := range []struct {
		name, ruleID, id, record, cve string
	}{
		{"by Go id", "GO-2020-0001-golang.org/x/net", "GO-2020-0001", "GO-2020-0001", "CVE-2020-36567"},
		{"by GitHub advisory id", "GHSA-hggr-p7v6-73p5-github.com/gin-gonic/gin", "GHSA-hggr-p7v6-73p5", "GO-2020-0003", "CVE-2020-36568"},
	} {
		t.Run(c.name, func(t *testing.T) {
			res := sarif.Result{RuleID: c.ruleID, Level: sarif.LevelWarning, Score: 5.3, HasScore: true}
			got := DefaultPrioritizer(src)("sca", saga.ExposurePublic, saga.CriticalityCritical, res)
			if got.Escalation == nil || got.Escalation.Signal != exploit.SignalKEV || got.Escalation.CVE != c.cve {
				t.Errorf("escalation = %+v, want raised on KEV naming %s", got.Escalation, c.cve)
			}
			if got.Exploited == nil || got.Exploited.CVE != c.cve {
				t.Errorf("listing = %+v, want one naming %s", got.Exploited, c.cve)
			}
			l := got.CVELookup
			if l == nil || l.ID != c.id || l.Record != c.record || l.Dataset != exploit.DatasetGoVulnDB ||
				l.AsOf != "2026-11-16" || len(l.CVEs) != 1 || l.CVEs[0] != c.cve {
				t.Fatalf("lookup = %+v, want %s found as %s in %s", l, c.id, c.cve, c.record)
			}

			// Ranked again, as reachability does once it arrives, the finding keeps the CVE it was
			// found under, whether or not the source can still look it up.
			res.CVELookup = l
			again := DefaultPrioritizer(exploit.New(map[string]bool{c.cve: true}, nil, 0))("sca",
				saga.ExposurePublic, saga.CriticalityCritical, res)
			if again.CVELookup != l || again.Escalation == nil || again.Escalation.CVE != c.cve {
				t.Errorf("ranked again: lookup = %+v, escalation = %+v, want the same CVE", again.CVELookup, again.Escalation)
			}
		})
	}
}

// Uncertainty resolves nothing: an advisory id no record lists, one two records list, a run with
// no copy of the database, and a finding that names its own CVE are all ranked as they arrived.
func TestALookupThatIsNotCertainResolvesNothing(t *testing.T) {
	adv := exploit.NewAdvisories(exploit.DatasetGoVulnDB, time.Time{}, goRecords)
	for _, c := range []struct {
		name string
		src  *exploit.Source
		res  sarif.Result
	}{
		{"an id in no record", kevWithLookup(adv), sarif.Result{RuleID: "GHSA-7777-8888-9999-left-pad"}},
		{"an id two records list", kevWithLookup(adv), sarif.Result{RuleID: "GHSA-2222-3333-4444-example.com/m"}},
		{"no copy of the database", kevWithLookup(nil), sarif.Result{RuleID: "GO-2020-0001-golang.org/x/net"}},
		{"two ids naming two records", kevWithLookup(adv), sarif.Result{RuleID: "GO-2020-0001-golang.org/x/net",
			Aliases: []string{"GO-2020-0001", "GHSA-hggr-p7v6-73p5"}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			c.res.Level = sarif.LevelWarning
			got := DefaultPrioritizer(c.src)("sca", saga.ExposurePublic, saga.CriticalityCritical, c.res)
			if got.CVELookup != nil || got.Escalation != nil || got.Exploited != nil {
				t.Errorf("lookup = %+v, escalation = %+v, listing = %+v, want nothing resolved and nothing raised",
					got.CVELookup, got.Escalation, got.Exploited)
			}
		})
	}

	// A finding naming its CVE is matched on it, and never looked up.
	named := sarif.Result{RuleID: "CVE-2020-36567", Aliases: []string{"GO-2020-0001"}, Level: sarif.LevelWarning}
	if got := DefaultPrioritizer(kevWithLookup(adv))("sca", saga.ExposurePublic, saga.CriticalityCritical, named); got.CVELookup != nil || got.Escalation == nil {
		t.Errorf("lookup = %+v, escalation = %+v, want raised on its own CVE and not looked up", got.CVELookup, got.Escalation)
	}
}

// repoScanner reports, for each repository, the finding findingFor names for it.
type repoScanner struct{}

func (repoScanner) Info() plugin.ScannerInfo { return plugin.ScannerInfo{Name: "advisories"} }

func (repoScanner) Scan(_ context.Context, target plugin.Target, _ plugin.Config) (sarif.Report, error) {
	repo := target.(plugin.RepositoryTarget).URL
	return sarif.Report{Tool: "advisories", Results: []sarif.Result{{
		RuleID: findingFor[repo], Level: sarif.LevelWarning, Location: sarif.Location{URI: "go.mod"},
		Repository: repo,
	}}}, nil
}

// findingFor is the rule id each repository's finding carries.
var findingFor = map[string]string{
	"api-server":  "GO-2020-0001-golang.org/x/net",
	"api-gateway": "GHSA-hggr-p7v6-73p5-github.com/gin-gonic/gin",
	"worker":      "GHSA-2222-3333-4444-example.com/m",
}

// repoController plans one job per repository of a component, as `sca` does.
type repoController struct{}

func (repoController) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: "sca", Scope: plugin.ScopeComponent}
}

func (repoController) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	var jobs []plugin.ScanJob
	for _, r := range comp.Repositories {
		jobs = append(jobs, plugin.ScanJob{Scanner: "advisories", Target: plugin.RepositoryTarget{URL: r.URL}})
	}
	return jobs, nil
}

func (repoController) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	return plugin.ControlResult{Control: "sca", Report: sarif.Merge(reports...)}, nil
}

// Two components, one of them with two repositories: each finding is looked up by its own id and
// given its own record's CVE, never another repository's.
func TestEachRepositorysFindingIsLookedUpOnItsOwn(t *testing.T) {
	reg := engine.NewRegistry()
	reg.RegisterController(repoController{})
	reg.RegisterScanner(repoScanner{})
	m := saga.Model{
		Release: saga.Release{Version: "1"},
		Config:  saga.Config{Controls: map[string]saga.ControllerSettings{"sca": {"enabled": true}}},
		Components: []saga.Component{
			{Name: "api", Exposure: saga.ExposurePublic, Criticality: saga.CriticalityCritical,
				Repositories: []saga.Repository{{URL: "api-server"}, {URL: "api-gateway"}}},
			{Name: "worker", Exposure: saga.ExposureInternal, Criticality: saga.CriticalityImportant,
				Repositories: []saga.Repository{{URL: "worker"}}},
		},
	}
	src := kevWithLookup(exploit.NewAdvisories(exploit.DatasetGoVulnDB, time.Time{}, goRecords))
	run, err := engine.New(reg, engine.WithPrioritization(DefaultPrioritizer(src))).Run(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"api-server": "CVE-2020-36567", "api-gateway": "CVE-2020-36568", "worker": ""}
	results := run.Controls["sca"].Report.Results
	if len(results) != len(want) {
		t.Fatalf("got %d findings, want one per repository: %+v", len(results), results)
	}
	for _, res := range results {
		cve := ""
		if res.CVELookup != nil {
			cve = res.CVELookup.CVEs[0]
		}
		if cve != want[res.Repository] {
			t.Errorf("%s in %s: looked up as %q, want %q", res.RuleID, res.Repository, cve, want[res.Repository])
		}
		if raised := res.Escalation != nil; raised != (cve != "") {
			t.Errorf("%s in %s: escalation = %+v, want a raise exactly where a CVE was found", res.RuleID, res.Repository, res.Escalation)
		}
	}
}

// The coraza advisory as the two databases held it on 2026-11-25: the Go vulnerability database's
// record lists only the GitHub advisory, and OSV.dev's Go records list the CVE. With osv-go read, the
// finding govulncheck names by its GitHub advisory takes that CVE, the key correlation joins Trivy's
// CVE-named copy on (TestCorrelationJoinsAGHSAOnlyCopyThroughTheLookedUpCVE in pkg/engine). Without
// it, the finding keeps no CVE.
func TestAGoFlawTheGoDatabaseGivesNoCVEIsLookedUpInOSV(t *testing.T) {
	const ghsa, cve = "GHSA-3c6w-j9xm-8h2h", "CVE-2026-107833"
	gov := exploit.NewAdvisories(exploit.DatasetGoVulnDB, time.Time{}, map[string][]string{"GO-2026-6690": {ghsa}})
	osvGo := exploit.NewOSVAdvisories("osv-go", time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC), map[string][]string{
		"GO-2026-6690": {cve, ghsa},
		ghsa:           {cve, "GO-2026-6690"},
	}, nil)
	res := sarif.Result{RuleID: ghsa, Aliases: []string{"GO-2026-6690"}, Level: sarif.LevelWarning,
		Package: &sarif.Package{Name: "github.com/corazawaf/coraza/v3", Version: "v3.3.0", Ecosystem: "gomod"}}

	with := exploit.NewFrom(exploit.Options{KEV: map[string]bool{cve: true}, Advisories: gov,
		OSV: map[string]*exploit.Advisories{"Go": osvGo}})
	got := DefaultPrioritizer(with)("sca", saga.ExposurePublic, saga.CriticalityCritical, res)
	if l := got.CVELookup; l == nil || len(l.CVEs) != 1 || l.CVEs[0] != cve || l.Dataset != "osv-go" ||
		l.Source != "GitHub Advisory Database" || l.URL != "https://osv.dev/vulnerability/"+ghsa {
		t.Fatalf("lookup = %+v, want %s from osv-go", l, cve)
	}
	if got.Escalation == nil || got.Escalation.CVE != cve {
		t.Errorf("escalation = %+v, want raised on KEV naming %s", got.Escalation, cve)
	}

	without := exploit.NewFrom(exploit.Options{KEV: map[string]bool{cve: true}, Advisories: gov})
	if got := DefaultPrioritizer(without)("sca", saga.ExposurePublic, saga.CriticalityCritical, res); got.CVELookup != nil {
		t.Errorf("lookup = %+v without osv-go, want none", got.CVELookup)
	}
}
