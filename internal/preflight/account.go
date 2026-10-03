package preflight

import (
	"context"
	"fmt"
	"slices"

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
	}
	return "", fmt.Errorf("doctor cannot check accounts on %s", provider)
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
