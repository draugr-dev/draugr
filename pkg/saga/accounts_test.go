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

// An AWS account is named by its 12-digit ID. Unquoted, YAML reads one as a number, and the text as
// written is what Draugr keeps, leading zero included.
func TestAnAWSAccountIsNamedByItsID(t *testing.T) {
	m, err := Load([]byte(clusterHeader + `
accounts:
  web-prod: {provider: aws, account: "111111111111"}
  web-data: {provider: aws, account: 011111111111}
components:
  - name: web
    cloud: [{account: web-prod, regions: [us-east-1]}]
  - name: data
    cloud: [{account: web-data}]
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Accounts["web-prod"]; got.Provider != ProviderAWS || got.ID() != "111111111111" {
		t.Errorf("web-prod = %+v", got)
	}
	if got := m.Accounts["web-data"].ID(); got != "011111111111" {
		t.Errorf("an unquoted ID with a leading zero = %q", got)
	}
}

// An Azure subscription is named by its GUID, and may narrow to regions as any account does.
func TestAnAzureSubscriptionIsNamedByItsID(t *testing.T) {
	m, err := Load([]byte(clusterHeader + `
accounts:
  shop-prod: {provider: azure, subscription: 00000000-0000-0000-0000-000000000000}
  shop-data: {provider: azure, subscription: AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}
components:
  - name: platform
    cloud: [{account: shop-prod}]
  - name: api
    cloud: [{account: shop-prod, regions: [eastus]}]
  - name: data
    cloud: [{account: shop-data}]
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Accounts["shop-prod"]; got.Provider != ProviderAzure || got.ID() != "00000000-0000-0000-0000-000000000000" {
		t.Errorf("shop-prod = %+v", got)
	}
	if got := m.Accounts["shop-data"].ID(); got != "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA" {
		t.Errorf("a GUID in capitals = %q", got)
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
  prod: {provider: oracle, project: p-1}
`, `accounts.prod.provider "oracle" is not gcp, aws or azure`},
		"an Azure subscription with no ID": {`
accounts:
  prod: {provider: azure}
`, `accounts.prod.subscription is required for provider azure: the subscription ID, a GUID`},
		"an Azure subscription that is not a GUID": {`
accounts:
  prod: {provider: azure, subscription: shop-prod}
`, `accounts.prod.subscription "shop-prod" is not an Azure subscription ID`},
		"an AWS field on an Azure subscription": {`
accounts:
  prod: {provider: azure, subscription: 00000000-0000-0000-0000-000000000000, account: "111111111111"}
`, `accounts.prod.account is a field of provider aws, and this account's provider is azure, whose ID goes in subscription`},
		"a Google Cloud field on an Azure subscription": {`
accounts:
  prod: {provider: azure, subscription: 00000000-0000-0000-0000-000000000000, project: p-1}
`, `accounts.prod.project is a field of provider gcp, and this account's provider is azure, whose ID goes in subscription`},
		"an Azure field on an AWS account": {`
accounts:
  prod: {provider: aws, account: "111111111111", subscription: 00000000-0000-0000-0000-000000000000}
`, `accounts.prod.subscription is a field of provider azure, and this account's provider is aws, whose ID goes in account`},
		"an Azure field on a Google Cloud account": {`
accounts:
  prod: {provider: gcp, project: p-1, subscription: 00000000-0000-0000-0000-000000000000}
`, `accounts.prod.subscription is a field of provider azure, and this account's provider is gcp, whose ID goes in project`},
		"a project with no ID": {`
accounts:
  prod: {provider: gcp}
`, `accounts.prod.project is required for provider gcp`},
		"an AWS account with no ID": {`
accounts:
  prod: {provider: aws}
`, `accounts.prod.account is required for provider aws: the 12-digit account ID`},
		"an AWS account ID of eleven digits": {`
accounts:
  prod: {provider: aws, account: "11111111111"}
`, `accounts.prod.account "11111111111" is not an AWS account ID`},
		"a Google Cloud field on an AWS account": {`
accounts:
  prod: {provider: aws, account: "111111111111", project: p-1}
`, `accounts.prod.project is a field of provider gcp, and this account's provider is aws, whose ID goes in account`},
		"an AWS field on a Google Cloud account": {`
accounts:
  prod: {provider: gcp, project: p-1, account: "111111111111"}
`, `accounts.prod.account is a field of provider aws, and this account's provider is gcp, whose ID goes in project`},
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
