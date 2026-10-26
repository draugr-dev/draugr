package publish

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/draugr-dev/draugr/internal/credential"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// ownTokenEnv is the variable each kind reads its token from when the descriptor names none.
//
// A descriptor's `tokenEnv` may name this variable or one $DRAUGR_TOKEN_ENVS lists, and nothing
// else, so a change to the descriptor cannot point a publisher at another of the job's secrets.
// TestEveryPublisherReadingATokenNamesItsOwn holds the map to the kinds that read `tokenEnv`.
var ownTokenEnv = map[string]string{
	"github":            "GITHUB_TOKEN",
	"github-pr-comment": "GITHUB_TOKEN",
	"github-issue":      "GITHUB_TOKEN",
	"azure-pr-comment":  "SYSTEM_ACCESSTOKEN",
	"azure-work-item":   "SYSTEM_ACCESSTOKEN",
	"gitlab-mr-comment": "GITLAB_TOKEN",
	"gitlab-issue":      "GITLAB_TOKEN",
	"draugr-api":        apiTokenEnv,
}

// CheckCredential reports whether the environment refuses a publisher entry its credential: a
// `tokenEnv` it does not list, or, for draugr-api, a url it does not allow or a destination that is
// half configured. Nothing is sent, so a scan can ask before any scanner runs rather than learn it
// at the end.
func CheckCredential(cfg saga.PublisherConfig) error {
	cfg = only(cfg)
	if cfg.Kind == "draugr-api" {
		_, _, err := ResolveAPI(cfg)
		return err
	}
	if _, reads := ownTokenEnv[cfg.Kind]; !reads {
		return nil
	}
	_, token, err := tokenFor(cfg)
	if err != nil {
		return err
	}
	if slices.Contains(reads[cfg.Kind], "org") {
		_, err = azureCollection(cfg.Kind, cfg.Org, token != "")
	}
	return err
}

// azureCollectionEnv is the collection URI Azure Pipelines sets for every job.
const azureCollectionEnv = "SYSTEM_TEAMFOUNDATIONCOLLECTIONURI"

// azureCollection is the collection URI an Azure publisher sends its token to.
//
// $SYSTEM_TEAMFOUNDATIONCOLLECTIONURI, which the pipeline sets, or the descriptor's `org` where the
// token stays with Azure DevOps by following it: on the environment's own origin, or on Azure
// DevOps Services, https://dev.azure.com or https://<organization>.visualstudio.com. `org` changes
// by pull request, so any other origin would send the token to whichever host the most recent
// change named. With no token there is nothing to send, and the constructor reports what is
// missing.
func azureCollection(kind, org string, hasToken bool) (string, error) {
	env := os.Getenv(azureCollectionEnv)
	if org == "" {
		return env, nil
	}
	origin, err := credential.Origin(org)
	if err != nil {
		return "", fmt.Errorf("%s publisher: org: %w", kind, err)
	}
	if env != "" {
		if e, err := credential.Origin(env); err == nil && e == origin {
			return org, nil
		}
	}
	switch {
	case azureServices(origin):
		return org, nil
	case env == "" && !hasToken:
		return org, nil
	case env == "":
		return "", fmt.Errorf("%s publisher: org (%s) is not on Azure DevOps Services and $%s is not set, "+
			"so the token would go to an unlisted host. Set $%s to the collection's URL",
			kind, org, azureCollectionEnv, azureCollectionEnv)
	}
	return "", fmt.Errorf("%s publisher: org (%s) is neither on the origin of $%s (%s) nor on Azure DevOps "+
		"Services, so the token would go to an unlisted host. Remove org, or set $%s to the collection's URL",
		kind, org, azureCollectionEnv, env, azureCollectionEnv)
}

// azureServices reports whether an origin is Azure DevOps Services, which serves every hosted
// organization.
func azureServices(origin string) bool {
	if origin == "https://dev.azure.com" {
		return true
	}
	host, ok := strings.CutPrefix(origin, "https://")
	name, onVS := strings.CutSuffix(host, ".visualstudio.com")
	return ok && onVS && name != "" && !strings.ContainsAny(name, ".:")
}

// tokenFor is the variable a publisher entry reads its token from, and the token.
//
// Every constructor calls it before anything else, so a refused variable is an error before the
// publisher decides whether it has anything to do.
func tokenFor(cfg saga.PublisherConfig) (name, value string, err error) {
	name, value, err = credential.Token(cfg.TokenEnv, ownTokenEnv[cfg.Kind])
	if err != nil {
		return name, "", fmt.Errorf("%s publisher: %w", cfg.Kind, err)
	}
	return name, value, nil
}
