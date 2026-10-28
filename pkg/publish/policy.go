package publish

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/internal/credential"
	"github.com/draugr-dev/draugr/internal/login"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/skald"
)

// ErrNoPolicyCheck is a server that answers the run API and judges no policy. It is not a failure
// of the run: there is nothing to check against.
var ErrNoPolicyCheck = errors.New("the server checks no organization policy")

// PolicyClient asks a draugr-api server what the organization's policy makes of a descriptor.
type PolicyClient struct {
	client *http.Client
}

// NewPolicyClient is a client that retries the way the publisher does.
func NewPolicyClient() PolicyClient {
	return PolicyClient{client: newRetryingClient(http.DefaultClient)}
}

// personalTokenPrefix marks a person's API token, the check-only one `draugr login` keeps included.
// The prefix is a public marker the server puts on every such token, not part of the secret.
const personalTokenPrefix = "drgr_api_" // #nosec G101 -- a public prefix marking a token kind, not a credential

// Check sends the effective descriptor to the server's pre-flight and returns its outcome.
//
// The server judges and words every verdict, so this carries no rule logic. A pipeline's ingest
// token is bound to its own project, so its check goes to the ingest route and names none, and a
// server with no policy check answers it 404, which is ErrNoPolicyCheck rather than an error of the
// run. A person's token, from a login or set in the environment, is accepted only on the route
// naming a project, where a 404 is a project the token cannot reach: an error naming it, never a
// server with nothing to check.
func (c PolicyClient) Check(ctx context.Context, dest APIDestination, effective string) (skald.PolicyOutcome, error) {
	personal := dest.Login != nil || strings.HasPrefix(dest.Token, personalTokenPrefix)
	holder := "the token in the environment"
	if dest.Login != nil {
		holder = "the login for " + dest.Endpoint
	}
	path := "/v1/ingest/policy/check"
	if personal {
		if dest.Project == "" {
			return skald.PolicyOutcome{}, errors.New("policy check: the descriptor names no project, and a check made " +
				"with a person's token is made for one; add `project:` to the descriptor")
		}
		path = "/v1/projects/" + url.PathEscape(dest.Project) + "/policy/check"
	}
	body, err := json.Marshal(map[string]any{"descriptor": map[string]string{"effective": effective}})
	if err != nil {
		return skald.PolicyOutcome{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dest.Endpoint+path, bytes.NewReader(body))
	if err != nil {
		return skald.PolicyOutcome{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+dest.Token)
	resp, err := c.client.Do(req)
	if err != nil {
		return skald.PolicyOutcome{}, fmt.Errorf("policy check: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		if personal {
			return skald.PolicyOutcome{}, fmt.Errorf("policy check: %s has no project %q that %s can reach; "+
				"check `project:` in the descriptor", dest.Endpoint, dest.Project, holder)
		}
		return skald.PolicyOutcome{}, ErrNoPolicyCheck
	}
	if resp.StatusCode >= 300 {
		refused := readRefusal(resp)
		// A login's token ends at its expiry or its revocation, and a token issued without the check
		// scope is never accepted here. Either way the remedy is a new login, which the server's own
		// answer does not say.
		if dest.Login != nil {
			switch {
			case resp.StatusCode == http.StatusUnauthorized:
				return skald.PolicyOutcome{}, fmt.Errorf("policy check: the login for %s has expired or was revoked; "+
					"run `draugr login %s`", dest.Endpoint, dest.Login.Server)
			case resp.StatusCode == http.StatusForbidden && refused.Code == "insufficient_scope":
				return skald.PolicyOutcome{}, fmt.Errorf("policy check: the login for %s does not carry the %s scope; "+
					"run `draugr login %s`", dest.Endpoint, login.Scope, dest.Login.Server)
			}
		}
		if personal && resp.StatusCode == http.StatusForbidden && refused.Code == "forbidden" {
			return skald.PolicyOutcome{}, fmt.Errorf("policy check: %s holds no role in project %q", holder, dest.Project)
		}
		return skald.PolicyOutcome{}, fmt.Errorf("policy check: %s", refused.said(resp.Status))
	}
	var out skald.PolicyOutcome
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&out); err != nil {
		return skald.PolicyOutcome{}, fmt.Errorf("policy check: unreadable response: %w", err)
	}
	return out, nil
}

// APIPublishers are the draugr-api destinations a descriptor publishes to.
func APIPublishers(cfgs []saga.PublisherConfig) []saga.PublisherConfig {
	var out []saga.PublisherConfig
	for _, c := range cfgs {
		if c.Kind == "draugr-api" {
			out = append(out, c)
		}
	}
	return out
}

// ResolvePolicyAPI finds where a policy check is sent and the token it carries, the way ResolveAPI
// does, with one addition: where the environment holds no token, the person's login for the
// server's origin, from logins, takes its place.
//
// A token in the environment is the pipeline's, and wins whenever it is set. A login's token goes
// only to the origin that issued it, so a url the descriptor names is allowed where logins holds a
// login for its origin: the token it would carry is that server's own. A nil logins, which is what
// a pipeline passes, is ResolveAPI.
//
// The draugr-api publisher resolves with ResolveAPI and never reads logins. A login is check-only,
// and a person's sign-in must not be able to publish a run.
func ResolvePolicyAPI(cfg saga.PublisherConfig, logins login.Store, now time.Time) (dest APIDestination, skip string, err error) {
	tokenEnv, token, err := credential.Token(cfg.TokenEnv, apiTokenEnv)
	if err != nil || token != "" || logins == nil {
		return ResolveAPI(cfg)
	}
	type held struct {
		login login.Login
		err   error
	}
	seen := map[string]held{}
	lookup := func(origin string) (login.Login, error) {
		if h, ok := seen[origin]; ok {
			return h.login, h.err
		}
		l, err := logins.Get(origin)
		seen[origin] = held{l, err}
		return l, err
	}
	endpoint, err := apiEndpointAllowing(cfg, false, func(origin string) bool {
		_, err := lookup(origin)
		return err == nil
	})
	if err != nil {
		return APIDestination{}, "", err
	}
	endpoint = strings.TrimRight(endpoint, "/")
	if endpoint == "" {
		return APIDestination{}, noLoginReason(cfg, tokenEnv, lookup), nil
	}
	origin, err := credential.Origin(endpoint)
	if err != nil {
		return APIDestination{}, "", fmt.Errorf("draugr-api publisher: %w", err)
	}
	l, err := lookup(origin)
	switch {
	case errors.Is(err, login.ErrNotLoggedIn):
		// An endpoint with neither a token nor a login is half configured, as it is for ResolveAPI.
		return APIDestination{}, "", fmt.Errorf("draugr-api publisher: $%s is not set, and there is no login for %s; "+
			"run `draugr login %s`", tokenEnv, origin, endpoint)
	case err != nil:
		return APIDestination{}, "", fmt.Errorf("draugr-api publisher: $%s is not set, and the login for %s could "+
			"not be read: %w", tokenEnv, origin, err)
	case l.Expired(now):
		return APIDestination{}, fmt.Sprintf("the login for %s expired at %s; run `draugr login %s`",
			origin, l.Expires.UTC().Format("2006-01-02 15:04 UTC"), endpoint), nil
	}
	if err := credential.RequireTLS(endpoint); err != nil {
		return APIDestination{}, "", fmt.Errorf("draugr-api publisher: the login for %s: %w", origin, err)
	}
	return APIDestination{Endpoint: endpoint, Token: l.Token, Login: &l}, "", nil
}

// noLoginReason is why a check with no token and no endpoint asked nothing. A url the repository
// names is one a login could have allowed, so the reason names its origin and what a login for it
// would need.
func noLoginReason(cfg saga.PublisherConfig, tokenEnv string, lookup func(string) (login.Login, error)) string {
	named := cfg.URL
	if named == "" && os.Getenv(apiURLEnv) == "" {
		named = cfg.ProjectURL
	}
	origin, err := credential.Origin(named)
	if named == "" || err != nil {
		return "no $" + apiURLEnv + " or $" + tokenEnv
	}
	if _, err := lookup(origin); err != nil && !errors.Is(err, login.ErrNotLoggedIn) {
		return fmt.Sprintf("no $%s, and the login for %s could not be read: %v", tokenEnv, origin, err)
	}
	return fmt.Sprintf("no $%s, and no login for %s; run `draugr login %s`", tokenEnv, origin, origin)
}
