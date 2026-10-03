package saga

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// Account is a cloud account's own facts, declared once under `accounts:` and shared by every
// component that runs in it.
//
// "Account" is Draugr's word for the unit a provider bills and grants permissions on, which Google
// Cloud calls a project, AWS an account and Azure a subscription. The field holding its ID keeps
// the provider's own word, so the value is the one its console shows.
type Account struct {
	// Provider is the cloud the account belongs to.
	Provider Provider `yaml:"provider"`
	// Project is a Google Cloud project's ID, as `gcloud projects list` prints it.
	Project string `yaml:"project,omitempty"`
}

// AccountRef is one component's use of an account declared under `accounts:`.
type AccountRef struct {
	// Account names an entry under `accounts:`.
	Account string `yaml:"account"`
	// Regions narrows the checks to resources in these regions. Empty means the whole account, and
	// only a component declaring the whole account receives the findings that belong to no region,
	// such as its IAM policy and its audit logging.
	//
	// The same reasoning as a cluster's namespaces: an account shared by several teams is not the
	// unit any of them owns, and a finding about the account as a whole is filed once.
	Regions []string `yaml:"regions,omitempty"`
}

// Provider names a cloud.
type Provider string

// The clouds an account may belong to.
const (
	// ProviderGCP is Google Cloud.
	ProviderGCP Provider = "gcp"
)

// ProviderValues lists the clouds Draugr checks, in the order the schema and error messages give
// them.
var ProviderValues = []Provider{ProviderGCP}

// Valid reports whether p is a cloud Draugr checks.
func (p Provider) Valid() bool { return slices.Contains(ProviderValues, p) }

// ID is the account's identifier at its provider.
func (a Account) ID() string {
	switch a.Provider {
	case ProviderGCP:
		return a.Project
	}
	return ""
}

// validateAccounts checks the declared accounts and every component's use of them.
//
// As for clusters, a name that matches no declaration is refused rather than skipped: a skipped
// account is a component scanned for everything except where it runs, and reads as covered.
//
// One account per component, for now. A component's findings are attributed to it whole, and two
// accounts behind one component would be two accounts' findings under one exposure and
// criticality with no way to say which account each came from.
func validateAccounts(accounts map[string]Account, components []Component) []error {
	var errs []error
	for _, name := range slices.Sorted(maps.Keys(accounts)) {
		a := accounts[name]
		where := "accounts." + name
		if strings.TrimSpace(name) == "" {
			errs = append(errs, errors.New("accounts: an account needs a name"))
		}
		if !a.Provider.Valid() {
			errs = append(errs, fmt.Errorf("%s.provider %q is not %s", where, a.Provider, orList(ProviderValues)))
			continue
		}
		if strings.TrimSpace(a.ID()) == "" {
			errs = append(errs, fmt.Errorf("%s.project is required for provider %s: the project ID, "+
				"as `gcloud projects list` prints it", where, a.Provider))
		}
	}
	for i, comp := range components {
		where := fmt.Sprintf("components[%d] (%s)", i, comp.Name)
		if len(comp.Cloud) > 1 {
			errs = append(errs, fmt.Errorf("%s: cloud names %d accounts; a component runs in one",
				where, len(comp.Cloud)))
		}
		for j, ref := range comp.Cloud {
			switch {
			case strings.TrimSpace(ref.Account) == "":
				errs = append(errs, fmt.Errorf("%s: cloud[%d].account is required, naming an entry "+
					"in accounts", where, j))
			case !hasAccount(accounts, ref.Account):
				msg := fmt.Sprintf("%s: cloud[%d].account %q is not declared in accounts", where, j, ref.Account)
				if names := slices.Sorted(maps.Keys(accounts)); len(names) > 0 {
					msg += " (it has " + strings.Join(names, ", ") + ")"
				}
				errs = append(errs, errors.New(msg))
			}
			for k, region := range ref.Regions {
				if strings.TrimSpace(region) == "" {
					errs = append(errs, fmt.Errorf("%s: cloud[%d].regions[%d] is empty", where, j, k))
				}
			}
		}
	}
	return errs
}

func hasAccount(accounts map[string]Account, name string) bool {
	_, ok := accounts[name]
	return ok
}

// mergeAccounts adds a fragment's accounts to the model's, on the rule clusters follow: two
// documents may both name one account only with the same facts, and a disagreement is recorded for
// Validate to refuse naming both.
func mergeAccounts(model *Model, frag Fragment) {
	for _, name := range slices.Sorted(maps.Keys(frag.Accounts)) {
		account := frag.Accounts[name]
		existing, ok := model.Accounts[name]
		switch {
		case !ok:
			if model.Accounts == nil {
				model.Accounts = map[string]Account{}
			}
			model.Accounts[name] = account
		case existing != account:
			from := frag.Source
			if from == "" {
				from = "a fragment"
			}
			model.accountConflicts = append(model.accountConflicts, fmt.Sprintf(
				"accounts.%s: %s defines it differently from an earlier document "+
					"(%+v there, %+v here); an account is declared once", name, from, existing, account))
		}
	}
}

// unionAccounts merges two components' use of accounts, where an entry with no regions is the
// whole account and so the widest scope.
func unionAccounts(a, b []AccountRef) []AccountRef {
	at := map[string]int{}
	for i, in := range a {
		at[in.Account] = i
	}
	for _, in := range b {
		i, ok := at[in.Account]
		if !ok {
			at[in.Account] = len(a)
			a = append(a, in)
			continue
		}
		a[i].Regions = mergeNamespaces(a[i].Regions, in.Regions)
	}
	return a
}

// AccountWarnings names declared accounts that no component's `cloud:` entry uses, for the reason
// ClusterWarnings names clusters.
func (m *Model) AccountWarnings() []string {
	used := map[string]bool{}
	for _, c := range m.Components {
		for _, ref := range c.Cloud {
			used[ref.Account] = true
		}
	}
	var out []string
	for _, name := range slices.Sorted(maps.Keys(m.Accounts)) {
		if !used[name] {
			out = append(out, fmt.Sprintf("accounts.%s is declared and no component's cloud: "+
				"entry names it, so nothing scans it", name))
		}
	}
	return out
}
