package engine

import (
	"context"
	"slices"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// Two components and two services, one check reported by two reports: each component gets its own
// entry per service, a check is listed once, and the order is the same whatever order the reports
// arrived in.
func TestUnreadChecksGroupByComponentAndService(t *testing.T) {
	u := func(component, check, group, reason string) sarif.Unchecked {
		return sarif.Unchecked{Scanner: "prowler", Component: component, Check: check, Group: group, Reason: reason}
	}
	byCtl := map[string][]sarif.Report{"cloud": {
		{Unchecked: []sarif.Unchecked{
			u("web", "compute_instance_public_ip", "compute", "denied compute.instances.list"),
			u("api", "cloudsql_instance_public_ip", "cloudsql", "denied cloudsql.instances.list"),
			u("api", "compute_instance_public_ip", "compute", "denied compute.zones.list"),
		}},
		{Unchecked: []sarif.Unchecked{
			u("api", "compute_firewall_ssh_access_from_the_internet_allowed", "compute", "denied compute.instances.list"),
			u("api", "compute_instance_public_ip", "compute", "denied compute.zones.list"),
		}},
	}}
	got := unreadChecks(byCtl)
	want := []UnreadChecks{
		{Component: "api", Control: "cloud", Group: "cloudsql", Checks: []string{"cloudsql_instance_public_ip"}, Reason: "denied cloudsql.instances.list"},
		{Component: "api", Control: "cloud", Group: "compute", Reason: "denied compute.instances.list",
			Checks: []string{"compute_firewall_ssh_access_from_the_internet_allowed", "compute_instance_public_ip"}},
		{Component: "web", Control: "cloud", Group: "compute", Checks: []string{"compute_instance_public_ip"}, Reason: "denied compute.instances.list"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		g, w := got[i], want[i]
		if g.Component != w.Component || g.Group != w.Group || g.Reason != w.Reason || !slices.Equal(g.Checks, w.Checks) {
			t.Errorf("entry %d = %+v, want %+v", i, g, w)
		}
	}
}

// accountScanner reports one unchecked check for whatever account it is given.
type accountScanner struct{}

func (accountScanner) Info() plugin.ScannerInfo { return plugin.ScannerInfo{Name: "prowler"} }

func (accountScanner) Scan(context.Context, plugin.Target, plugin.Config) (sarif.Report, error) {
	return sarif.Report{Tool: "prowler", Unchecked: []sarif.Unchecked{
		{Scanner: "prowler", Check: "compute_instance_public_ip", Group: "compute", Reason: "denied compute.instances.list"},
	}}, nil
}

// accountController plans one job per component on one shared account.
type accountController struct{}

func (accountController) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: "cloud", Scope: plugin.ScopeComponent}
}

func (accountController) Plan(_ saga.Model, _ *saga.Component) ([]plugin.ScanJob, error) {
	return []plugin.ScanJob{{Scanner: "prowler", Target: plugin.AccountTarget{Account: "prod", Provider: "gcp", ID: "p-1"}}}, nil
}

func (accountController) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	return plugin.ControlResult{Control: "cloud", Report: sarif.Merge(reports...)}, nil
}

// Two components sharing an account share one scan, and each is told what it could not read under
// its own name rather than the first one's.
func TestAnUnreadCheckIsStampedWithEachComponent(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(accountController{})
	reg.RegisterScanner(accountScanner{})
	on := map[string]saga.ControllerSettings{"cloud": {}}
	res, err := New(reg).Run(context.Background(), saga.Model{
		Release:    saga.Release{Version: "1"},
		Components: []saga.Component{{Name: "api", Controls: on}, {Name: "web", Controls: on}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var components []string
	for _, g := range res.UnreadChecks {
		components = append(components, g.Component)
	}
	if !slices.Equal(components, []string{"api", "web"}) {
		t.Errorf("unread checks for %v, want api and web", components)
	}
}
