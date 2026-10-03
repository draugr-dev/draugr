package controllers

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func TestCloudInfo(t *testing.T) {
	info := NewCloud().Info()
	if info.Name != "cloud" || info.Scope != plugin.ScopeComponent {
		t.Errorf("info = %+v", info)
	}
	if len(info.DefaultScanners) != 1 || info.DefaultScanners[0] != "prowler" {
		t.Errorf("default scanners = %v", info.DefaultScanners)
	}
}

// Each component's entry becomes a job against its account, with the provider's ID from accounts:
// and the regions the component claims. Two accounts, so a fact cannot leak from one to the other.
func TestCloudPlanCarriesEachAccountsFacts(t *testing.T) {
	model := saga.Model{Accounts: map[string]saga.Account{
		"prod": {Provider: saga.ProviderGCP, Project: "shop-prod-4821"},
		"data": {Provider: saga.ProviderGCP, Project: "shop-data-1177"},
	}}
	api := &saga.Component{Name: "api", Cloud: []saga.AccountRef{{Account: "prod", Regions: []string{"us-central1"}}}}
	billing := &saga.Component{Name: "billing", Cloud: []saga.AccountRef{{Account: "data"}},
		Controls: map[string]saga.ControllerSettings{"cloud": {"prowler": map[string]any{"compliance": "cis_4.0_gcp"}}}}

	jobs, err := Cloud{}.Plan(model, api)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("api: %v, %v", jobs, err)
	}
	if got := jobs[0].Target.(plugin.AccountTarget); got.ID != "shop-prod-4821" || got.Provider != "gcp" ||
		len(got.Regions) != 1 || jobs[0].Scanner != "prowler" {
		t.Errorf("api's job = %+v", jobs[0])
	}
	jobs, err = Cloud{}.Plan(model, billing)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("billing: %v, %v", jobs, err)
	}
	if got := jobs[0].Target.Identity(); got != "gcp/shop-data-1177" {
		t.Errorf("billing's target = %q", got)
	}
	if jobs[0].Config["compliance"] != "cis_4.0_gcp" {
		t.Errorf("billing's config = %v", jobs[0].Config)
	}
}

func TestCloudPlansNothingForNoComponent(t *testing.T) {
	if jobs, err := (Cloud{}).Plan(saga.Model{}, nil); jobs != nil || err != nil {
		t.Errorf("nil component planned %v, %v", jobs, err)
	}
}

func TestCloudAggregate(t *testing.T) {
	res, err := Cloud{}.Aggregate([]sarif.Report{{Results: []sarif.Result{
		{RuleID: "prowler/a", Level: sarif.LevelError},
		{RuleID: "prowler/b", Level: sarif.LevelNote},
	}}})
	if err != nil || res.Control != "cloud" || res.Summary.Errors != 1 || res.Summary.Notes != 1 {
		t.Errorf("aggregate = %+v, %v", res, err)
	}
}
