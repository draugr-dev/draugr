package azureaccess

// The Azure Identity module for Go (MIT) is linked into Draugr for its credentials, which read what
// Prowler's do. The questions themselves are plain requests to Azure Resource Manager.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

const (
	// endpoint is Azure Resource Manager in Azure's public cloud, the one Prowler reads by default.
	endpoint = "https://management.azure.com"
	// scope is the OAuth scope of a request to it.
	scope = endpoint + "/.default"
	// subscriptionsAPI and permissionsAPI are the versions of the two calls.
	subscriptionsAPI = "2022-12-01"
	permissionsAPI   = "2022-04-01"
	// requestTimeout bounds one request, so a stalled connection ends the question.
	requestTimeout = 30 * time.Second
	// maxBody bounds one answer. A page of grants is far smaller.
	maxBody = 4 << 20
)

// TokenFunc returns a bearer token for Azure Resource Manager.
type TokenFunc func(ctx context.Context) (string, error)

// Client asks Azure Resource Manager with one credential.
type Client struct {
	client   *http.Client
	endpoint string
	token    TokenFunc
}

// New builds the credential AuthFlag selects from the environment and returns a Client that asks
// with it.
func New(_ context.Context) (*Client, error) {
	cred, err := credential(os.Getenv, azidentityMakers)
	if err != nil {
		slog.Debug("no Azure credential", "error", err)
		return nil, ErrNoCredentials
	}
	return NewWith(&http.Client{Timeout: requestTimeout}, endpoint, tokenFrom(cred)), nil
}

// tokenFrom asks cred for a token for Azure Resource Manager.
func tokenFrom(cred azcore.TokenCredential) TokenFunc {
	return func(ctx context.Context) (string, error) {
		t, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{scope}})
		if err != nil {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			// The chain's own error lists every credential it tried, which helps whoever is debugging
			// the lookup and nobody reading a scan's errors.
			slog.DebugContext(ctx, "no Azure token", "error", err)
			return "", ErrNoCredentials
		}
		return t.Token, nil
	}
}

// NewWith returns a Client asking endpointURL through client, with tokens from token.
func NewWith(client *http.Client, endpointURL string, token TokenFunc) *Client {
	return &Client{client: client, endpoint: strings.TrimRight(endpointURL, "/"), token: token}
}

// makers builds each credential the environment can select.
type makers struct {
	environment, managed, workload, cli, developer func() (azcore.TokenCredential, error)
}

// azidentityMakers are the real ones. None of them contacts anything until it is asked for a token.
var azidentityMakers = makers{
	environment: func() (azcore.TokenCredential, error) { return azidentity.NewEnvironmentCredential(nil) },
	managed:     func() (azcore.TokenCredential, error) { return azidentity.NewManagedIdentityCredential(nil) },
	workload:    func() (azcore.TokenCredential, error) { return azidentity.NewWorkloadIdentityCredential(nil) },
	cli:         func() (azcore.TokenCredential, error) { return azidentity.NewAzureCLICredential(nil) },
	developer:   func() (azcore.TokenCredential, error) { return azidentity.NewAzureDeveloperCLICredential(nil) },
}

// credential is the credential AuthFlag's flag leaves Prowler with. The last case holds what
// --az-cli-auth keeps of DefaultAzureCredential, in its order.
func credential(getenv func(string) string, build makers) (azcore.TokenCredential, error) {
	switch AuthFlag(getenv) {
	case flagServicePrincipal:
		return build.environment()
	case flagManagedIdentity:
		return build.managed()
	}
	var chain []azcore.TokenCredential
	sources := []func() (azcore.TokenCredential, error){build.cli, build.developer}
	if getenv("AZURE_FEDERATED_TOKEN_FILE") != "" {
		sources = append([]func() (azcore.TokenCredential, error){build.workload}, sources...)
	}
	for _, source := range sources {
		c, err := source()
		if err != nil {
			return nil, err
		}
		chain = append(chain, c)
	}
	return azidentity.NewChainedTokenCredential(chain, nil)
}

// statusError is an answer other than 200.
type statusError struct {
	status  int
	message string
}

func (e *statusError) Error() string {
	return fmt.Sprintf("%d %s: %s", e.status, http.StatusText(e.status), e.message)
}

// get asks for u and decodes the answer into out.
func (c *Client) get(ctx context.Context, u string, out any) error {
	token, err := c.token(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return &statusError{status: resp.StatusCode, message: apiMessage(raw)}
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("unreadable answer: %w", err)
	}
	return nil
}

// apiMessage is the message in an Azure error body, or the body itself.
func apiMessage(raw []byte) string {
	var e struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &e) == nil && e.Error.Message != "" {
		return e.Error.Message
	}
	return strings.TrimSpace(string(raw))
}

// refused reports whether an error is Azure saying no to these credentials, or that they named
// something it will not admit exists.
func refused(err error, statuses ...int) bool {
	var se *statusError
	if !errors.As(err, &se) {
		return false
	}
	for _, s := range statuses {
		if se.status == s {
			return true
		}
	}
	return false
}

// Subscription asks for the subscription, which needs Microsoft.Resources/subscriptions/read.
//
// A subscription the credentials hold no role on and one that does not exist are one answer here,
// because neither says which: the error says both.
func (c *Client) Subscription(ctx context.Context, id string) (Subscription, error) {
	u := c.endpoint + "/subscriptions/" + url.PathEscape(id) + "?api-version=" + subscriptionsAPI
	var out struct {
		SubscriptionID string `json:"subscriptionId"`
		DisplayName    string `json:"displayName"`
	}
	if err := c.get(ctx, u, &out); err != nil {
		switch {
		case errors.Is(err, ErrNoCredentials):
			return Subscription{}, err
		case refused(err, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound):
			return Subscription{}, fmt.Errorf("subscription %s does not exist, or the credentials cannot read it", id)
		}
		return Subscription{}, fmt.Errorf("ask Azure about subscription %s: %w", id, err)
	}
	return Subscription{ID: out.SubscriptionID, Name: out.DisplayName}, nil
}

// Permissions lists the credentials' grants on the subscription, every page of them.
func (c *Client) Permissions(ctx context.Context, id string) ([]Permission, error) {
	u := c.endpoint + "/subscriptions/" + url.PathEscape(id) +
		"/providers/Microsoft.Authorization/permissions?api-version=" + permissionsAPI
	var grants []Permission
	for u != "" {
		var page struct {
			Value    []Permission `json:"value"`
			NextLink string       `json:"nextLink"`
		}
		if err := c.get(ctx, u, &page); err != nil {
			if refused(err, http.StatusUnauthorized, http.StatusForbidden) {
				return nil, ErrRefused
			}
			return nil, fmt.Errorf("ask Azure about the permissions on subscription %s: %w", id, err)
		}
		grants = append(grants, page.Value...)
		// The token goes with the next request, so a link leaving this endpoint is not followed.
		if page.NextLink != "" && !strings.HasPrefix(page.NextLink, c.endpoint+"/") {
			return nil, fmt.Errorf("ask Azure about the permissions on subscription %s: "+
				"the next page is at another host", id)
		}
		u = page.NextLink
	}
	return grants, nil
}
