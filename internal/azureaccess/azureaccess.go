// Package azureaccess asks Azure Resource Manager whether the credentials in the environment can
// read a subscription, and which actions they hold on it.
//
// The first question is asked by two callers: `draugr doctor`, to say whether a declared subscription
// can be reached, and the prowler scanner, before Prowler runs. The second is the scanner's. Prowler's
// Azure service base class discards the exceptions its worker threads raise, so a denial inside a
// service can leave no log line, and the answer has to come from somewhere other than its output.
//
// Prowler has no flag for Azure's whole default credential chain: each of its flags keeps one
// credential and excludes the others. AuthFlag chooses the flag, and New builds the credential that
// flag leaves Prowler with, which is what makes the answer about the scan rather than about this
// process.
package azureaccess

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"
)

// ErrNoCredentials is a machine with no Azure credential that yields a token.
var ErrNoCredentials = errors.New("no usable Azure credentials found: run `az login`, set " +
	"AZURE_CLIENT_ID, AZURE_TENANT_ID and AZURE_CLIENT_SECRET, or run where a managed identity is attached")

// ErrRefused is a permissions question Azure refused to answer for these credentials.
var ErrRefused = errors.New("the credentials may not list their permissions on the subscription")

// Subscription is what Azure says about a subscription the credentials can read.
type Subscription struct {
	// ID is the subscription's GUID.
	ID string
	// Name is its display name.
	Name string
}

// Permission is one role's grant on a subscription, as Microsoft.Authorization/permissions returns
// it. An action is held when one entry's Actions match it and that entry's NotActions do not.
type Permission struct {
	// Actions are the action patterns the role allows.
	Actions []string `json:"actions"`
	// NotActions are the patterns excluded from this entry's Actions. They take nothing away from
	// another entry.
	NotActions []string `json:"notActions"`
	// DataActions are the data-plane patterns the role allows, which the checks' control-plane reads do
	// not use.
	DataActions []string `json:"dataActions"`
}

// Reader asks Azure Resource Manager about a subscription.
type Reader interface {
	// Subscription returns the subscription, or an error naming it when the credentials cannot read it.
	Subscription(ctx context.Context, id string) (Subscription, error)
	// Permissions lists the credentials' grants on the subscription. ErrRefused says they may not ask.
	Permissions(ctx context.Context, id string) ([]Permission, error)
}

// The Prowler flags for each credential.
const (
	flagServicePrincipal = "--sp-env-auth"
	flagManagedIdentity  = "--managed-identity-auth"
	flagCLI              = "--az-cli-auth"
)

// AuthFlag is the Prowler flag for the credential the environment declares.
//
// A service principal's three variables are the only form --sp-env-auth accepts, and Prowler refuses
// to start with one missing. IDENTITY_ENDPOINT is what App Service, Functions, Container Apps and Arc
// set for a managed identity. Everything else is --az-cli-auth, which leaves Prowler the sign-in `az
// login` holds, a federated one and `az login --identity` included, and workload identity where
// AZURE_FEDERATED_TOKEN_FILE is set. A virtual machine's managed identity sets no variable, so it is
// reached with `az login --identity`.
func AuthFlag(getenv func(string) string) string {
	switch {
	case getenv("AZURE_CLIENT_ID") != "" && getenv("AZURE_TENANT_ID") != "" && getenv("AZURE_CLIENT_SECRET") != "":
		return flagServicePrincipal
	case getenv("IDENTITY_ENDPOINT") != "":
		return flagManagedIdentity
	}
	return flagCLI
}

// Denied returns the actions, in the order given, that none of the grants allow. Deny assignments
// are outside the answer Azure gives, and Prowler's log catches those.
func Denied(grants []Permission, actions []string) []string {
	var denied []string
	for _, a := range actions {
		if !allowed(grants, a) {
			denied = append(denied, a)
		}
	}
	return denied
}

// HoldsAnAction reports whether any grant allows anything. Azure answers an empty list for credentials
// with no role on a subscription they can still see.
func HoldsAnAction(grants []Permission) bool {
	return slices.ContainsFunc(grants, func(g Permission) bool { return len(g.Actions) > 0 })
}

func allowed(grants []Permission, action string) bool {
	for _, g := range grants {
		if matchesAny(g.Actions, action) && !matchesAny(g.NotActions, action) {
			return true
		}
	}
	return false
}

func matchesAny(patterns []string, action string) bool {
	for _, p := range patterns {
		// Azure compares actions without regard to case, and a star spans any number of segments.
		quoted := strings.ReplaceAll(regexp.QuoteMeta(p), `\*`, `.*`)
		if regexp.MustCompile(`(?i)^` + quoted + `$`).MatchString(action) {
			return true
		}
	}
	return false
}
