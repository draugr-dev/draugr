package saga

import (
	"strings"
	"testing"
)

// A component refers to an account declared under accounts:. Two components may share one, whole
// and by regions, which is how one project serving two teams is described.
func TestComponentsReferToDeclaredAccounts(t *testing.T) {
	ok := clusterHeader + `
accounts:
  shop-prod: {provider: gcp, project: shop-prod-4821}
  shop-data: {provider: gcp, project: shop-data-1177}
components:
  - name: platform
    cloud: [{account: shop-prod}]
  - name: api
    cloud: [{account: shop-prod, regions: [us-central1]}]
  - name: billing
    cloud: [{account: shop-data}]
`
	m, err := Load([]byte(ok))
	if err != nil {
		t.Fatalf("components sharing an account: %v", err)
	}
	if got := m.Accounts["shop-prod"]; got.Provider != ProviderGCP || got.ID() != "shop-prod-4821" {
		t.Errorf("account = %+v", got)
	}
	if got := m.Components[1].Cloud; len(got) != 1 || got[0].Regions[0] != "us-central1" {
		t.Errorf("api's cloud = %+v", got)
	}
}

func TestAccountsAreRefusedWhereTheyCannotBeScanned(t *testing.T) {
	for name, tc := range map[string]struct{ body, want string }{
		"an undeclared name": {`
accounts:
  prod: {provider: gcp, project: p-1}
  data: {provider: gcp, project: d-1}
components:
  - name: c
    cloud: [{account: prdo}]
`, `cloud[0].account "prdo" is not declared in accounts (it has data, prod)`},
		"no accounts at all": {`
components:
  - name: c
    cloud: [{account: prod}]
`, `cloud[0].account "prod" is not declared in accounts`},
		"two accounts in one component": {`
accounts:
  prod: {provider: gcp, project: p-1}
  data: {provider: gcp, project: d-1}
components:
  - name: c
    cloud: [{account: prod}, {account: data}]
`, `cloud names 2 accounts; a component runs in one`},
		"no name": {`
accounts:
  prod: {provider: gcp, project: p-1}
components:
  - name: c
    cloud: [{regions: [us-central1]}]
`, `cloud[0].account is required`},
		"an empty region": {`
accounts:
  prod: {provider: gcp, project: p-1}
components:
  - name: c
    cloud: [{account: prod, regions: [""]}]
`, `cloud[0].regions[0] is empty`},
		"a provider Draugr does not check": {`
accounts:
  prod: {provider: aws, project: p-1}
`, `accounts.prod.provider "aws" is not gcp`},
		"a project with no ID": {`
accounts:
  prod: {provider: gcp}
`, `accounts.prod.project is required for provider gcp`},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Load([]byte(clusterHeader + tc.body))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %v, want %q", err, tc.want)
			}
		})
	}
}

// A fragment may name an account the descriptor declares, with the same facts, or one of its own; two
// documents disagreeing about one name are refused naming both.
func TestFragmentsShareAccountsOnlyWhenTheyAgree(t *testing.T) {
	m := &Model{Release: Release{Version: "1"},
		Accounts: map[string]Account{"prod": {Provider: ProviderGCP, Project: "p-1"}}}
	Merge(m, Fragment{Source: "team.saga-fragment.yaml", Accounts: map[string]Account{
		"prod": {Provider: ProviderGCP, Project: "p-1"},
		"data": {Provider: ProviderGCP, Project: "d-1"},
	}})
	if m.Accounts["data"].Project != "d-1" {
		t.Error("a new account from a fragment was not added")
	}
	if err := m.Validate(); err != nil {
		t.Errorf("an agreeing fragment was refused: %v", err)
	}
	Merge(m, Fragment{Accounts: map[string]Account{"prod": {Provider: ProviderGCP, Project: "p-2"}}})
	if err := m.Validate(); err == nil || !strings.Contains(err.Error(), "accounts.prod: a fragment defines it differently") {
		t.Errorf("error %v, want the conflict named", err)
	}
}

// A component described in two documents keeps one entry per account, and an entry for the whole
// account stays the whole account.
func TestAComponentsAccountsUnionAcrossDocuments(t *testing.T) {
	m := &Model{Components: []Component{{Name: "api", Cloud: []AccountRef{{Account: "prod", Regions: []string{"us-central1"}}}}}}
	Merge(m, Fragment{Components: []Component{
		{Name: "api", Cloud: []AccountRef{{Account: "prod", Regions: []string{"europe-west1"}}}},
	}})
	if got := m.Components[0].Cloud; len(got) != 1 || len(got[0].Regions) != 2 {
		t.Fatalf("cloud = %+v, want one entry with both regions", got)
	}
	Merge(m, Fragment{Components: []Component{{Name: "api", Cloud: []AccountRef{{Account: "prod"}}}}})
	if got := m.Components[0].Cloud; len(got) != 1 || len(got[0].Regions) != 0 {
		t.Errorf("cloud = %+v, want the whole account", got)
	}
}

func TestAnUnusedAccountIsWarnedAbout(t *testing.T) {
	m := &Model{
		Accounts:   map[string]Account{"prod": {}, "spare": {}},
		Components: []Component{{Name: "c", Cloud: []AccountRef{{Account: "prod"}}}},
	}
	got := m.AccountWarnings()
	if len(got) != 1 || !strings.Contains(got[0], "accounts.spare is declared") {
		t.Errorf("warnings = %v, want spare alone", got)
	}
}

func TestAnAccountWithNoProviderHasNoID(t *testing.T) {
	if id := (Account{Project: "p-1"}).ID(); id != "" {
		t.Errorf("ID() = %q, want none without a provider", id)
	}
}
