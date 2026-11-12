package preflight

import (
	"context"
	"fmt"
	"slices"

	"github.com/draugr-dev/draugr/internal/awsaccess"
	"github.com/draugr-dev/draugr/internal/azureaccess"
	"github.com/draugr-dev/draugr/internal/gcpaccess"
)

// readProject is the permission that says the credentials can see a project at all. Every role
// that can read anything in a project carries it, so its absence means a scan would read nothing.
const readProject = "resourcemanager.projects.get"

// reachAccount asks the cloud whether the credentials in the environment can read the account.
//
// Whether they can read each service is the scanner's question, asked again at scan time where
// the answer becomes the run's unread checks. Doctor asks the one that decides whether a scan is
// worth starting.
func reachAccount(ctx context.Context, provider, id string) (string, error) {
	switch provider {
	case "gcp":
		tester, err := gcpaccess.New(ctx)
		if err != nil {
			return "", err
		}
		return projectReadable(ctx, tester, id)
	case "aws":
		identifier, err := awsaccess.New(ctx)
		if err != nil {
			return "", err
		}
		return callerInAccount(ctx, identifier, id)
	case "azure":
		reader, err := azureaccess.New(ctx)
		if err != nil {
			return "", err
		}
		return subscriptionReadable(ctx, reader, id)
	}
	return "", fmt.Errorf("doctor cannot check accounts on %s", provider)
}

// subscriptionReadable reports whether the credentials can read the declared Azure subscription,
// and what Azure calls it, which tells somebody whose subscription a scan would read. Credentials that
// see the subscription and hold no role on it would be refused by the scan, so they fail here too. A
// list Azure will not give says nothing either way, and the scan reports that itself.
func subscriptionReadable(ctx context.Context, reader azureaccess.Reader, id string) (string, error) {
	sub, err := reader.Subscription(ctx, id)
	if err != nil {
		return "", err
	}
	if grants, err := reader.Permissions(ctx, id); err == nil && !azureaccess.HoldsAnAction(grants) {
		return "", fmt.Errorf("subscription %s (%s) · the credentials hold no role on it; grant Reader", id, sub.Name)
	}
	return fmt.Sprintf("subscription %s (%s) · the credentials can read it", id, sub.Name), nil
}

// callerInAccount reports whether the credentials are an identity in the declared AWS account. It
// is the question a scan asks before Prowler runs; whether that identity can read each service is
// not asked yet.
func callerInAccount(ctx context.Context, id awsaccess.Identifier, account string) (string, error) {
	caller, err := awsaccess.Confirm(ctx, id, account)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("account %s · the credentials are %s", account, caller.ARN), nil
}

func projectReadable(ctx context.Context, tester *gcpaccess.Tester, project string) (string, error) {
	granted, err := tester.Granted(ctx, project, []string{readProject})
	if err != nil {
		return "", err
	}
	if !slices.Contains(granted, readProject) {
		return "", fmt.Errorf("the credentials hold no role on project %s that can read it (%s)", project, readProject)
	}
	return fmt.Sprintf("project %s · the credentials can read it", project), nil
}
