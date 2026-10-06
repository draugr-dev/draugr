package publish

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

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

// Check sends the effective descriptor to the server's pre-flight and returns its outcome.
//
// The server judges and words every verdict, so this carries no rule logic. A server with no
// policy check answers 404, and that is ErrNoPolicyCheck rather than an error of the run.
func (c PolicyClient) Check(ctx context.Context, dest APIDestination, effective string) (skald.PolicyOutcome, error) {
	body, err := json.Marshal(map[string]any{"descriptor": map[string]string{"effective": effective}})
	if err != nil {
		return skald.PolicyOutcome{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dest.Endpoint+"/v1/ingest/policy/check",
		bytes.NewReader(body))
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
		return skald.PolicyOutcome{}, ErrNoPolicyCheck
	}
	if resp.StatusCode >= 300 {
		return skald.PolicyOutcome{}, fmt.Errorf("policy check: %s", serverError(resp))
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
